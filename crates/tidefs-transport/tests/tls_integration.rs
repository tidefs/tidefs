#[cfg(feature = "tls")]
mod tls_tests {
    use std::thread;
    use std::time::Duration;

    use tidefs_transport::backend::TransportBackend;
    use tidefs_transport::session_cohort::NodeInfo;
    use tidefs_transport::tls::{generate_self_signed_cert, TlsTransport};

    /// Two TLS transports communicate over loopback: server accepts,
    /// client connects, frames exchanged end-to-end.
    #[test]
    fn tls_loopback_frame_exchange() {
        let (server_certs, server_key) =
            generate_self_signed_cert("localhost").expect("server cert");
        let (client_certs, client_key) =
            generate_self_signed_cert("localhost").expect("client cert");

        let mut server = TlsTransport::new(
            Duration::from_secs(5),
            Duration::from_secs(10),
            server_certs,
            server_key,
            "localhost".to_string(),
        )
        .expect("server");

        let addr: tidefs_transport::TransportAddr =
            tidefs_transport::TransportAddr::Tcp("127.0.0.1:0".parse().unwrap());
        server.bind(addr).expect("server bind");
        let bound = server.local_addr().expect("server addr");

        // Spawn server accept in background
        let server_handle = thread::spawn(move || {
            let (mut conn, _peer) = server.accept().expect("server accept");
            let frame = conn.read_frame().expect("server read");
            assert_eq!(frame, b"ping");
            conn.write_frame(b"pong").expect("server write");
            conn.close();
        });

        // Give server time to start listening
        thread::sleep(Duration::from_millis(50));

        let mut client = TlsTransport::new(
            Duration::from_secs(5),
            Duration::from_secs(10),
            client_certs,
            client_key,
            "localhost".to_string(),
        )
        .expect("client");

        let node = NodeInfo::new(2, vec![bound], 0);
        let mut conn = client.connect(&node).expect("client connect");
        conn.write_frame(b"ping").expect("client write");
        let reply = conn.read_frame().expect("client read");
        assert_eq!(reply, b"pong");
        conn.close();

        server_handle.join().expect("server thread");
    }

    /// TLS connect succeeds when client trusts all certs (NoServerVerification).
    #[test]
    fn tls_connect_with_self_signed_cert() {
        let (certs, key) = generate_self_signed_cert("localhost").expect("cert");

        let server_certs = certs.clone();
        let server_key = key.clone_key();

        let mut server = TlsTransport::new(
            Duration::from_secs(5),
            Duration::from_secs(10),
            server_certs,
            server_key,
            "localhost".to_string(),
        )
        .expect("server");

        let addr: tidefs_transport::TransportAddr =
            tidefs_transport::TransportAddr::Tcp("127.0.0.1:0".parse().unwrap());
        server.bind(addr).expect("server bind");
        let bound = server.local_addr().expect("server addr");

        let server_handle = thread::spawn(move || {
            let (mut conn, _peer) = server.accept().expect("accept");
            conn.write_frame(b"tls ready").expect("write");
            conn.close();
        });

        thread::sleep(Duration::from_millis(50));

        let mut client = TlsTransport::new(
            Duration::from_secs(5),
            Duration::from_secs(10),
            certs,
            key,
            "localhost".to_string(),
        )
        .expect("client");

        let node = NodeInfo::new(2, vec![bound], 0);
        let mut conn = client.connect(&node).expect("connect");
        let frame = conn.read_frame().expect("read");
        assert_eq!(frame, b"tls ready");
        conn.close();

        server_handle.join().expect("server thread");
    }
}
