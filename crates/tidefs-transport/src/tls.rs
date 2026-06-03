use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{
    ClientConfig, ClientConnection, DigitallySignedStruct, Error as RustlsError, ServerConfig,
    ServerConnection, SignatureScheme, StreamOwned,
};

use crate::addr::TransportAddr;
use crate::backend::{AcceptResult, ConnectionLike, TransportBackend};
use crate::error::TransportError;
use crate::session_cohort::NodeInfo;
use crate::tcp::TcpTransport;

// ---------------------------------------------------------------------------
// Certificate verifier that accepts all server certificates.
// Suitable for self-signed development certificates; production deployments
// should replace this with a proper CA-based verifier.
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct NoServerVerification;

impl ServerCertVerifier for NoServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
        ]
    }
}

// ---------------------------------------------------------------------------
// Self-signed certificate generation
// ---------------------------------------------------------------------------

/// Generate a self-signed TLS certificate and private key for the given hostname.
/// Returns DER-encoded certificate chain and private key suitable for rustls.
pub fn generate_self_signed_cert(
    hostname: &str,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), TransportError> {
    let certified_key = rcgen::generate_simple_self_signed(vec![hostname.to_string()])
        .map_err(|e| TransportError::Generic(format!("TLS cert generation failed: {e}")))?;

    let cert_der: CertificateDer<'static> = certified_key.cert.into();
    let key_der = PrivateKeyDer::Pkcs8(certified_key.key_pair.serialize_der().into());

    Ok((vec![cert_der], key_der))
}

// ---------------------------------------------------------------------------
// TLS connection wrapper
// ---------------------------------------------------------------------------

/// A TLS-wrapped connection that delegates frame I/O to a rustls StreamOwned.
enum TlsStream {
    Client(StreamOwned<ClientConnection, TcpStream>),
    Server(StreamOwned<ServerConnection, TcpStream>),
}

pub(crate) struct TlsConnection {
    stream: Option<TlsStream>,
    #[allow(dead_code)]
    peer_addr: SocketAddr,
}

impl TlsConnection {
    fn read_frame_inner<R: Read>(reader: &mut R) -> Result<Vec<u8>, TransportError> {
        let mut len_buf = [0u8; 4];
        reader.read_exact(&mut len_buf).map_err(|e| {
            if e.kind() == std::io::ErrorKind::WouldBlock {
                TransportError::WouldBlock("TLS read_frame would block".into())
            } else {
                TransportError::Generic(format!("TLS frame read failed: {e}"))
            }
        })?;

        let len = u32::from_be_bytes(len_buf) as usize;
        if len > 64 * 1024 * 1024 {
            return Err(TransportError::Generic(format!(
                "TLS frame too large: {len} bytes"
            )));
        }

        let mut payload = vec![0u8; len];
        reader.read_exact(&mut payload).map_err(|e| {
            if e.kind() == std::io::ErrorKind::WouldBlock {
                TransportError::WouldBlock("TLS read_frame payload would block".into())
            } else {
                TransportError::Generic(format!("TLS frame payload read failed: {e}"))
            }
        })?;

        Ok(payload)
    }

    fn write_frame_inner<W: Write>(writer: &mut W, data: &[u8]) -> Result<(), TransportError> {
        let len = data.len() as u32;
        writer
            .write_all(&len.to_be_bytes())
            .map_err(|e| TransportError::Generic(format!("TLS frame write failed: {e}")))?;
        writer
            .write_all(data)
            .map_err(|e| TransportError::Generic(format!("TLS frame payload write failed: {e}")))?;
        writer
            .flush()
            .map_err(|e| TransportError::Generic(format!("TLS flush failed: {e}")))?;
        Ok(())
    }
}

impl ConnectionLike for TlsConnection {
    fn read_frame(&mut self) -> Result<Vec<u8>, TransportError> {
        let stream = self
            .stream
            .as_mut()
            .ok_or_else(|| TransportError::Generic("TLS connection closed".into()))?;
        match stream {
            TlsStream::Client(s) => Self::read_frame_inner(s),
            TlsStream::Server(s) => Self::read_frame_inner(s),
        }
    }

    fn write_frame(&mut self, data: &[u8]) -> Result<(), TransportError> {
        let stream = self
            .stream
            .as_mut()
            .ok_or_else(|| TransportError::Generic("TLS connection closed".into()))?;
        match stream {
            TlsStream::Client(s) => Self::write_frame_inner(s, data),
            TlsStream::Server(s) => Self::write_frame_inner(s, data),
        }
    }

    fn set_nonblocking(&mut self, nonblocking: bool) -> Result<(), TransportError> {
        let stream = self
            .stream
            .as_mut()
            .ok_or_else(|| TransportError::Generic("TLS connection closed".into()))?;

        let result = match stream {
            TlsStream::Client(s) => s.sock.set_nonblocking(nonblocking),
            TlsStream::Server(s) => s.sock.set_nonblocking(nonblocking),
        };
        result.map_err(|e| {
            TransportError::Generic(format!("failed to set TLS connection nonblocking: {e}"))
        })
    }

    fn close(&mut self) {
        self.stream = None;
    }
}

// ---------------------------------------------------------------------------
// TLS transport backend
// ---------------------------------------------------------------------------

/// TLS transport backend.
///
/// Wraps a [TcpTransport] internally for TCP-level bind/connect and upgrades
/// every connection to TLS using rustls. Self-signed certificates are accepted
/// for development; production deployments should use a proper CA.
pub struct TlsTransport {
    inner: TcpTransport,
    server_config: Arc<ServerConfig>,
    client_config: Arc<ClientConfig>,
    server_name: ServerName<'static>,
}

impl TlsTransport {
    /// Create a new TLS transport backend.
    ///
    /// `certs` and `key` are the server's certificate chain and private key.
    /// Use [generate_self_signed_cert] to create these for development.
    pub fn new(
        connect_timeout: Duration,
        read_timeout: Duration,
        certs: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
        server_name: String,
    ) -> Result<Self, TransportError> {
        let server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| TransportError::Generic(format!("TLS server config: {e}")))?;

        let client_config = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoServerVerification))
            .with_no_client_auth();

        let server_name = ServerName::try_from(server_name)
            .map_err(|e| TransportError::Generic(format!("invalid server name: {e}")))?;

        Ok(Self {
            inner: TcpTransport::new(connect_timeout, read_timeout),
            server_config: Arc::new(server_config),
            client_config: Arc::new(client_config),
            server_name,
        })
    }
}

impl TransportBackend for TlsTransport {
    fn bind(&mut self, addr: TransportAddr) -> Result<(), TransportError> {
        self.inner.bind(addr)
    }

    fn local_addr(&self) -> Option<TransportAddr> {
        self.inner.local_addr()
    }

    fn connect(&mut self, peer: &NodeInfo) -> Result<Box<dyn ConnectionLike>, TransportError> {
        // Connect raw TCP first, then wrap with TLS client.
        // We bypass TcpTransport::connect() since we need the raw TcpStream
        // to construct the TLS wrapper; TcpConnection hides the stream.
        for addr in &peer.addresses {
            let Some(socket_addr) = addr.as_socket_addr() else {
                continue;
            };
            match TcpStream::connect_timeout(&socket_addr, self.inner.connect_timeout) {
                Ok(stream) => {
                    stream
                        .set_read_timeout(Some(self.inner.read_timeout))
                        .map_err(|e| TransportError::ConnectFailed {
                            peer_addr: addr.clone(),
                            source: e,
                        })?;
                    if self.inner.nonblocking {
                        stream.set_nonblocking(true).map_err(|e| {
                            TransportError::ConnectFailed {
                                peer_addr: addr.clone(),
                                source: e,
                            }
                        })?;
                    }

                    let client_conn = ClientConnection::new(
                        Arc::clone(&self.client_config),
                        self.server_name.clone(),
                    )
                    .map_err(|e| TransportError::Generic(format!("TLS client connection: {e}")))?;

                    let tls_stream = StreamOwned::new(client_conn, stream);

                    let tls_conn = TlsConnection {
                        stream: Some(TlsStream::Client(tls_stream)),
                        peer_addr: socket_addr,
                    };

                    return Ok(Box::new(tls_conn));
                }
                Err(_) => continue,
            }
        }

        Err(TransportError::ConnectFailed {
            peer_addr: peer
                .addresses
                .first()
                .cloned()
                .unwrap_or_else(|| TransportAddr::Tcp("0.0.0.0:0".parse().unwrap())),
            source: std::io::Error::new(
                std::io::ErrorKind::ConnectionRefused,
                "all TLS peer addresses unreachable",
            ),
        })
    }

    fn set_nonblocking(&mut self, nonblocking: bool) -> Result<(), TransportError> {
        self.inner.set_nonblocking(nonblocking)
    }

    fn accept(&mut self) -> Result<AcceptResult, TransportError> {
        let listener = self
            .inner
            .listener
            .as_ref()
            .ok_or_else(|| TransportError::Generic("TLS listener not bound".into()))?;

        // TLS requires blocking I/O for the handshake, so we set the
        // listener to blocking mode for accept. The underlying TCP accept
        // will block until a connection arrives.
        listener.set_nonblocking(false).map_err(|e| {
            TransportError::Generic(format!("failed to set listener blocking: {e}"))
        })?;

        let (stream, peer_addr) = listener.accept().map_err(TransportError::AcceptFailed)?;

        // Restore non-blocking for the listener (the connection itself
        // uses StreamOwned which handles its own I/O).
        listener.set_nonblocking(true).ok();

        stream
            .set_read_timeout(Some(self.inner.read_timeout))
            .map_err(TransportError::AcceptFailed)?;
        if self.inner.nonblocking {
            stream
                .set_nonblocking(true)
                .map_err(TransportError::AcceptFailed)?;
        }

        let server_conn = ServerConnection::new(Arc::clone(&self.server_config))
            .map_err(|e| TransportError::Generic(format!("TLS server connection: {e}")))?;

        let tls_stream = StreamOwned::new(server_conn, stream);

        let tls_conn = TlsConnection {
            stream: Some(TlsStream::Server(tls_stream)),
            peer_addr,
        };

        Ok((Box::new(tls_conn), TransportAddr::Tcp(peer_addr)))
    }
}
