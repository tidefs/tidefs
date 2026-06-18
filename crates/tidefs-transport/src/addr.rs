// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Unified transport endpoint address type supporting TCP, RDMA, and Unix
//! domain sockets.
//!
//! [`TransportAddr`] is the single address representation that the transport
//! send path (#5778), receive path (#5780), and peer admission (#5785) use
//! for carrier-agnostic connection establishment. Each carrier backend
//! extracts its native address from the variant at bind/connect time.
//!
//! ## URI formats
//!
//! | Carrier | Format | Example |
//! |---|---|---|
//! | TCP | `tcp://<host>:<port>` | `tcp://10.0.0.1:9100` |
//! | TCP IPv6 | `tcp://[<ipv6>]:<port>` | `tcp://[::1]:9100` |
//! | RDMA | `rdma://<gid>:<qpn>:<svc>` | `rdma://fe80::1:42:1` |
//! | Unix | `unix://<abs_path>` | `unix:///run/tidefs/transport.sock` |

use std::fmt;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;

// ---------------------------------------------------------------------------
// TransportCarrier
// ---------------------------------------------------------------------------

/// Identifies which transport carrier a [`TransportAddr`] uses.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, PartialOrd, Ord)]
pub enum TransportCarrier {
    /// Plain TCP (IPv4 or IPv6).
    Tcp,
    /// RDMA/RoCE.
    Rdma,
    /// Unix domain socket.
    Unix,
}

impl fmt::Display for TransportCarrier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tcp => write!(f, "tcp"),
            Self::Rdma => write!(f, "rdma"),
            Self::Unix => write!(f, "unix"),
        }
    }
}

// ---------------------------------------------------------------------------
// TransportAddr
// ---------------------------------------------------------------------------

/// A unified endpoint address for TideFS transport carriers.
///
/// Each variant carries precisely the addressing information needed by its
/// carrier backend. Upper layers pass a `TransportAddr` without knowing which
/// carrier sits underneath; the backend extracts the variant it supports.
#[derive(Clone, Debug, Eq, PartialEq, Hash, PartialOrd, Ord)]
pub enum TransportAddr {
    /// TCP socket address (IPv4 or IPv6).
    Tcp(SocketAddr),
    /// RDMA queue-pair endpoint.
    Rdma {
        /// GID (Global Identifier) — 16 bytes.
        gid: [u8; 16],
        /// Queue-pair number.
        qpn: u32,
        /// Service ID.
        service_id: u32,
    },
    /// Unix domain socket path.
    Unix(PathBuf),
}

impl TransportAddr {
    /// Return the transport carrier for this address.
    #[must_use]
    pub fn carrier(&self) -> TransportCarrier {
        match self {
            Self::Tcp(_) => TransportCarrier::Tcp,
            Self::Rdma { .. } => TransportCarrier::Rdma,
            Self::Unix(_) => TransportCarrier::Unix,
        }
    }

    /// Return the inner [`SocketAddr`] if this is a `Tcp` variant.
    #[must_use]
    pub fn as_socket_addr(&self) -> Option<SocketAddr> {
        match self {
            Self::Tcp(addr) => Some(*addr),
            _ => None,
        }
    }

    /// Return the inner path if this is a `Unix` variant.
    #[must_use]
    pub fn as_unix_path(&self) -> Option<&PathBuf> {
        match self {
            Self::Unix(path) => Some(path),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Display — human-readable URI representation
// ---------------------------------------------------------------------------

impl fmt::Display for TransportAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tcp(addr) => write!(f, "tcp://{addr}"),
            Self::Rdma {
                gid,
                qpn,
                service_id,
            } => {
                write!(f, "rdma://{}", format_gid(gid))?;
                write!(f, ":{qpn}:{service_id}")
            }
            Self::Unix(path) => write!(f, "unix://{}", path.display()),
        }
    }
}

/// Format a 16-byte GID as colon-separated lowercase hex groups,
/// two bytes per group (e.g. `fe80:0000:0000:0000:0000:0000:0000:0001`).
fn format_gid(gid: &[u8; 16]) -> String {
    let mut s = String::with_capacity(39);
    for i in 0..8 {
        if i > 0 {
            s.push(':');
        }
        let hi = gid[i * 2];
        let lo = gid[i * 2 + 1];
        s.push_str(&format!("{hi:02x}{lo:02x}"));
    }
    s
}

// ---------------------------------------------------------------------------
// FromStr — parse URI strings
// ---------------------------------------------------------------------------

/// Error returned when parsing a [`TransportAddr`] from a string fails.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AddrParseError {
    /// The string is missing a `://` scheme separator.
    MissingScheme,
    /// The scheme is not one of `tcp`, `rdma`, or `unix`.
    UnknownScheme(String),
    /// The host/port portion for a TCP address is invalid.
    InvalidTcpAddr(String),
    /// The RDMA address portion is malformed.
    InvalidRdmaAddr(String),
    /// The Unix socket path is empty.
    EmptyUnixPath,
}

impl fmt::Display for AddrParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingScheme => {
                write!(f, "missing scheme (expected tcp://, rdma://, or unix://)")
            }
            Self::UnknownScheme(s) => {
                write!(f, "unknown scheme '{s}' (expected tcp, rdma, or unix)")
            }
            Self::InvalidTcpAddr(s) => write!(f, "invalid TCP address: {s}"),
            Self::InvalidRdmaAddr(s) => write!(f, "invalid RDMA address: {s}"),
            Self::EmptyUnixPath => write!(f, "empty Unix socket path"),
        }
    }
}

impl FromStr for TransportAddr {
    type Err = AddrParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (scheme, rest) = s.split_once("://").ok_or(AddrParseError::MissingScheme)?;

        match scheme {
            "tcp" => {
                let addr: SocketAddr = rest
                    .parse()
                    .map_err(|_| AddrParseError::InvalidTcpAddr(rest.to_string()))?;
                Ok(TransportAddr::Tcp(addr))
            }
            "rdma" => parse_rdma_addr(rest),
            "unix" => {
                if rest.is_empty() {
                    return Err(AddrParseError::EmptyUnixPath);
                }
                Ok(TransportAddr::Unix(PathBuf::from(rest)))
            }
            other => Err(AddrParseError::UnknownScheme(other.to_string())),
        }
    }
}

// ---------------------------------------------------------------------------
// RDMA address parsing
// ---------------------------------------------------------------------------

/// Parse an RDMA address body: `<gid_hex>:<qpn>:<service_id>`.
fn parse_rdma_addr(body: &str) -> Result<TransportAddr, AddrParseError> {
    let (gid_str, qpn_str, svc_str) = split_rdma_parts(body)?;

    let gid = parse_gid(gid_str)?;
    let qpn = qpn_str
        .parse::<u32>()
        .or_else(|_| u32::from_str_radix(qpn_str.strip_prefix("0x").unwrap_or(qpn_str), 16))
        .map_err(|_| AddrParseError::InvalidRdmaAddr(format!("invalid qpn: {qpn_str}")))?;
    let service_id = svc_str
        .parse::<u32>()
        .or_else(|_| u32::from_str_radix(svc_str.strip_prefix("0x").unwrap_or(svc_str), 16))
        .map_err(|_| AddrParseError::InvalidRdmaAddr(format!("invalid service_id: {svc_str}")))?;

    Ok(TransportAddr::Rdma {
        gid,
        qpn,
        service_id,
    })
}

/// Split `gid_hex:qpn:service_id` by finding the last two `:` separators.
fn split_rdma_parts(body: &str) -> Result<(&str, &str, &str), AddrParseError> {
    let last_colon = body.rfind(':').ok_or_else(|| {
        AddrParseError::InvalidRdmaAddr(format!("missing qpn:service_id in '{body}'"))
    })?;
    let service_id_str = &body[last_colon + 1..];

    let before_last = &body[..last_colon];
    let qpn_colon = before_last
        .rfind(':')
        .ok_or_else(|| AddrParseError::InvalidRdmaAddr(format!("missing qpn in '{body}'")))?;
    let qpn_str = &before_last[qpn_colon + 1..];
    let gid_str = &before_last[..qpn_colon];

    if gid_str.is_empty() || qpn_str.is_empty() || service_id_str.is_empty() {
        return Err(AddrParseError::InvalidRdmaAddr(format!(
            "empty field in '{body}'"
        )));
    }

    Ok((gid_str, qpn_str, service_id_str))
}

/// Parse a GID hex string (8 colon-separated 4-hex-digit groups) into
/// 16 bytes in network byte order.
fn parse_gid(s: &str) -> Result<[u8; 16], AddrParseError> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 8 {
        return Err(AddrParseError::InvalidRdmaAddr(format!(
            "GID must be 8 colon-separated hex groups, got {} parts in '{s}'",
            parts.len()
        )));
    }

    let mut gid = [0u8; 16];
    for (i, part) in parts.iter().enumerate() {
        if part.len() > 4 {
            return Err(AddrParseError::InvalidRdmaAddr(format!(
                "GID group too long: '{part}'"
            )));
        }
        let val = u16::from_str_radix(part, 16).map_err(|_| {
            AddrParseError::InvalidRdmaAddr(format!("invalid hex group '{part}' in GID"))
        })?;
        gid[i * 2] = (val >> 8) as u8;
        gid[i * 2 + 1] = (val & 0xFF) as u8;
    }
    Ok(gid)
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- TransportCarrier

    #[test]
    fn carrier_display() {
        assert_eq!(TransportCarrier::Tcp.to_string(), "tcp");
        assert_eq!(TransportCarrier::Rdma.to_string(), "rdma");
        assert_eq!(TransportCarrier::Unix.to_string(), "unix");
    }

    // -- TransportAddr::carrier

    #[test]
    fn addr_carrier_classification() {
        assert_eq!(
            TransportAddr::Tcp("127.0.0.1:8080".parse().unwrap()).carrier(),
            TransportCarrier::Tcp
        );
        assert_eq!(
            TransportAddr::Rdma {
                gid: [0u8; 16],
                qpn: 1,
                service_id: 0
            }
            .carrier(),
            TransportCarrier::Rdma
        );
        assert_eq!(
            TransportAddr::Unix(PathBuf::from("/tmp/sock")).carrier(),
            TransportCarrier::Unix
        );
    }

    // -- as_socket_addr / as_unix_path

    #[test]
    fn as_socket_addr_extracts_tcp() {
        let addr: SocketAddr = "10.0.0.1:9100".parse().unwrap();
        let ta = TransportAddr::Tcp(addr);
        assert_eq!(ta.as_socket_addr(), Some(addr));
        assert_eq!(ta.as_unix_path(), None);
    }

    #[test]
    fn as_socket_addr_returns_none_for_non_tcp() {
        let ta = TransportAddr::Rdma {
            gid: [0; 16],
            qpn: 1,
            service_id: 2,
        };
        assert_eq!(ta.as_socket_addr(), None);
        let ta = TransportAddr::Unix(PathBuf::from("/tmp/s"));
        assert_eq!(ta.as_socket_addr(), None);
    }

    #[test]
    fn as_unix_path_returns_none_for_non_unix() {
        let ta = TransportAddr::Tcp("127.0.0.1:1".parse().unwrap());
        assert_eq!(ta.as_unix_path(), None);
    }

    // -- Display / FromStr round-trip: TCP

    #[test]
    fn tcp_ipv4_round_trip() {
        let original: TransportAddr = TransportAddr::Tcp("192.168.1.42:9100".parse().unwrap());
        let s = original.to_string();
        assert_eq!(s, "tcp://192.168.1.42:9100");
        let parsed: TransportAddr = s.parse().unwrap();
        assert_eq!(parsed, original);
    }

    #[test]
    fn tcp_ipv6_round_trip() {
        let original: TransportAddr = TransportAddr::Tcp("[::1]:9100".parse().unwrap());
        let s = original.to_string();
        assert_eq!(s, "tcp://[::1]:9100");
        let parsed: TransportAddr = s.parse().unwrap();
        assert_eq!(parsed, original);
    }

    #[test]
    fn tcp_ipv6_full_round_trip() {
        let original: TransportAddr = TransportAddr::Tcp("[fe80::1]:9100".parse().unwrap());
        let s = original.to_string();
        assert_eq!(s, "tcp://[fe80::1]:9100");
        let parsed: TransportAddr = s.parse().unwrap();
        assert_eq!(parsed, original);
    }

    // -- Display / FromStr round-trip: RDMA

    #[test]
    fn rdma_round_trip() {
        let gid: [u8; 16] = [
            0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01,
        ];
        let original = TransportAddr::Rdma {
            gid,
            qpn: 42,
            service_id: 1,
        };
        let s = original.to_string();
        assert_eq!(s, "rdma://fe80:0000:0000:0000:0000:0000:0000:0001:42:1");
        let parsed: TransportAddr = s.parse().unwrap();
        assert_eq!(parsed, original);
    }

    #[test]
    fn rdma_hex_qpn() {
        let gid: [u8; 16] = [0x00; 16];
        let original = TransportAddr::Rdma {
            gid,
            qpn: 0x42,
            service_id: 0,
        };
        let s = original.to_string();
        assert_eq!(s, "rdma://0000:0000:0000:0000:0000:0000:0000:0000:66:0");
        // Note: 0x42 = 66 decimal in Display
        // Parse back from hex: 0x42
        let parsed: TransportAddr = "rdma://0000:0000:0000:0000:0000:0000:0000:0000:0x42:0"
            .parse()
            .unwrap();
        assert_eq!(parsed, original);
    }

    // -- Display / FromStr round-trip: Unix

    #[test]
    fn unix_round_trip() {
        let original = TransportAddr::Unix(PathBuf::from("/run/tidefs/transport.sock"));
        let s = original.to_string();
        assert_eq!(s, "unix:///run/tidefs/transport.sock");
        let parsed: TransportAddr = s.parse().unwrap();
        assert_eq!(parsed, original);
    }

    #[test]
    fn unix_relative_path() {
        let original = TransportAddr::Unix(PathBuf::from("relative.sock"));
        let s = original.to_string();
        assert_eq!(s, "unix://relative.sock");
        let parsed: TransportAddr = s.parse().unwrap();
        assert_eq!(parsed, original);
    }

    // -- FromStr: error cases

    #[test]
    fn parse_missing_scheme() {
        let err: AddrParseError = "10.0.0.1:9100".parse::<TransportAddr>().unwrap_err();
        assert!(matches!(err, AddrParseError::MissingScheme));
    }

    #[test]
    fn parse_unknown_scheme() {
        let err: AddrParseError = "udp://0.0.0.0:53".parse::<TransportAddr>().unwrap_err();
        match err {
            AddrParseError::UnknownScheme(ref s) => assert_eq!(s, "udp"),
            other => panic!("expected UnknownScheme, got {other:?}"),
        }
    }

    #[test]
    fn parse_invalid_tcp_addr() {
        let err: AddrParseError = "tcp://not-an-address".parse::<TransportAddr>().unwrap_err();
        assert!(matches!(err, AddrParseError::InvalidTcpAddr(_)));
    }

    #[test]
    fn parse_invalid_rdma_addr() {
        let err: AddrParseError = "rdma://fe80::1".parse::<TransportAddr>().unwrap_err();
        assert!(matches!(err, AddrParseError::InvalidRdmaAddr(_)));
    }

    #[test]
    fn parse_empty_unix_path() {
        let err: AddrParseError = "unix://".parse::<TransportAddr>().unwrap_err();
        assert!(matches!(err, AddrParseError::EmptyUnixPath));
    }

    #[test]
    fn parse_rdma_bad_gid_group_count() {
        let err: AddrParseError = "rdma://fe80:0000:0001:42:1"
            .parse::<TransportAddr>()
            .unwrap_err();
        assert!(matches!(err, AddrParseError::InvalidRdmaAddr(_)));
    }

    // -- AddrParseError Display

    #[test]
    fn addr_parse_error_display() {
        assert!(AddrParseError::MissingScheme
            .to_string()
            .contains("missing scheme"));
        assert!(AddrParseError::UnknownScheme("sctp".into())
            .to_string()
            .contains("sctp"));
        assert!(AddrParseError::InvalidTcpAddr("bad".into())
            .to_string()
            .contains("bad"));
        assert!(AddrParseError::InvalidRdmaAddr("bad".into())
            .to_string()
            .contains("bad"));
        assert!(AddrParseError::EmptyUnixPath.to_string().contains("empty"));
    }

    // -- GID formatting edge cases

    #[test]
    fn format_gid_all_zeros() {
        let gid = [0u8; 16];
        assert_eq!(format_gid(&gid), "0000:0000:0000:0000:0000:0000:0000:0000");
    }

    #[test]
    fn format_gid_all_ff() {
        let gid = [0xFFu8; 16];
        assert_eq!(format_gid(&gid), "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff");
    }
}
