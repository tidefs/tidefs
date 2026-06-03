use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use std::net::SocketAddr;
use std::thread;
use std::time::Duration;

use tidefs_transport::backend::{ConnectionLike, TransportBackend};
use tidefs_transport::error::TransportError;
use tidefs_transport::session_cohort::NodeInfo;
use tidefs_transport::tcp::TcpTransport;
use tidefs_transport::TransportAddr;

/// Transport-layer throughput benchmark.
///
/// Benchmarks [`ConnectionLike`] write throughput via [`TcpTransport`]
/// over localhost. The drainer reads frames through the same
/// [`ConnectionLike::read_frame`] path exercised by the envelope layer.
///
/// Each benchmark variant:
/// 1. Binds a localhost TCP listener on an OS-assigned port.
/// 2. Spawns a drainer thread that reads frames in an unbounded loop
///    until the connection drops (or errors).
/// 3. Opens a client connection through [`TcpTransport::connect`].
/// 4. Measures sustained [`ConnectionLike::write_frame`] throughput.
///
/// ## Message sizes tested
///
/// | Size | Label |
/// |---|---|
/// | 64 B | Tiny RPC / keepalive |
/// | 1 KiB | Small metadata / lane control |
/// | 16 KiB | Typical envelope payload |
/// | 64 KiB | Default chunk shipper unit |
/// | 256 KiB | Bulk session batch |
/// | 1 MiB | Large transfer unit |
/// | 4 MiB | Maximum recommended frame (~64 MiB cap) |
const MESSAGE_SIZES: &[usize] = &[64, 1024, 16384, 65536, 262144, 1048576, 4194304];
const ACCEPT_TIMEOUT: Duration = Duration::from_secs(3);

fn bench_throughput(c: &mut Criterion) {
    for &size in MESSAGE_SIZES {
        // ---------- server (drainer) ----------
        let mut server = TcpTransport::default();
        server
            .bind(TransportAddr::Tcp(
                "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
            ))
            .expect("bind localhost for throughput benchmark");
        let addr = server.local_addr().expect("local addr");

        let drainer = thread::spawn(move || {
            let deadline = std::time::Instant::now() + ACCEPT_TIMEOUT;
            let mut conn: Box<dyn ConnectionLike> = loop {
                match server.accept() {
                    Ok((c, _)) => break c,
                    Err(TransportError::Generic(ref msg)) if msg == "no pending connections" => {
                        if std::time::Instant::now() > deadline {
                            panic!("benchmark server: no connection within {ACCEPT_TIMEOUT:?}");
                        }
                        thread::yield_now();
                    }
                    Err(e) => panic!("benchmark server accept error: {e:?}"),
                }
            };
            // Unbounded drain: read until the client closes the connection.
            while conn.read_frame().is_ok() {}
        });

        // ---------- client ----------
        let mut client_backend = TcpTransport::default();
        let peer = NodeInfo::new(0, vec![addr], 0);
        let mut conn = client_backend
            .connect(&peer)
            .expect("connect to benchmark drainer");

        let payload = vec![0x42u8; size];

        let label = human_size_label(size);
        let mut group = c.benchmark_group(format!("transport_throughput/{label}"));
        group.throughput(Throughput::Bytes(size as u64));
        group.sample_size(10);

        group.bench_function("send_one_frame", |b| {
            b.iter(|| {
                conn.write_frame(&payload).expect("write frame");
            })
        });

        group.finish();
        conn.close();
        drainer.join().expect("drainer thread");
    }
}

/// Compact human-readable label: "64B", "1KiB", "16KiB", "1MiB", "4MiB".
fn human_size_label(bytes: usize) -> String {
    if bytes < 1024 {
        format!("{bytes}B")
    } else if bytes < 1024 * 1024 {
        format!("{}KiB", bytes / 1024)
    } else {
        format!("{}MiB", bytes / (1024 * 1024))
    }
}

criterion_group!(benches, bench_throughput);
criterion_main!(benches);
