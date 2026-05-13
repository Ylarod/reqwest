//! Integration tests for the TLS exporter (RFC 5705 / RFC 8446) support.
//!
//! Only runs when one of the rustls backends is active. The test spins up a
//! local rustls TLS server over plain TCP, completes a tiny HTTP/1.1
//! handshake, has the server derive the same `(label, context, length)`
//! keying material on its end, and asserts the client-side
//! [`TlsInfo::keying_material`] equals the server-side derivation.
#![cfg(feature = "__rustls-aws-lc-rs")]
#![cfg(not(feature = "rustls-no-provider"))]

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::Once;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::rustls::{self, version};
use tokio_rustls::TlsAcceptor;

static INIT_PROVIDER: Once = Once::new();

fn install_provider() {
    INIT_PROVIDER.call_once(|| {
        // The repo currently only exposes the aws-lc-rs rustls feature
        // (`__rustls-aws-lc-rs`), so install that one.
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    });
}

/// Read the on-disk test cert/key (shared with `tests/support/`).
fn load_server_config(only_tls13: bool) -> Arc<rustls::ServerConfig> {
    let cert_der: rustls_pki_types::CertificateDer<'static> =
        std::fs::read("tests/support/server.cert").unwrap().into();
    let key_der: rustls_pki_types::PrivateKeyDer<'static> =
        std::fs::read("tests/support/server.key").unwrap().try_into().unwrap();

    let builder = if only_tls13 {
        rustls::ServerConfig::builder_with_protocol_versions(&[&version::TLS13])
    } else {
        // Restrict the server to TLS 1.2 only, exercising the RFC 5705 KDF.
        rustls::ServerConfig::builder_with_protocol_versions(&[&version::TLS12])
    };
    let mut cfg = builder
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .expect("server config");
    // We're speaking HTTP/1.1 only — keep it simple.
    cfg.alpn_protocols.clear();
    Arc::new(cfg)
}

/// A spawned rustls server. The receiver side captures the per-connection
/// EKM derivations the server saw, keyed by spec, so the test can compare
/// them with the client side after `await`.
struct ServerHandle {
    addr: SocketAddr,
    /// Specs the server is asked to derive on its side. Format matches the
    /// client `(label, context, length)`.
    received: tokio::sync::oneshot::Receiver<Vec<(Vec<u8>, Option<Vec<u8>>, Vec<u8>)>>,
}

fn spawn_server(
    server_specs: Vec<(Vec<u8>, Option<Vec<u8>>, usize)>,
    only_tls13: bool,
) -> ServerHandle {
    install_provider();
    let cfg = load_server_config(only_tls13);
    let acceptor = TlsAcceptor::from(cfg);

    let (ready_tx, ready_rx) = std::sync::mpsc::channel::<SocketAddr>();
    let (done_tx, done_rx) = tokio::sync::oneshot::channel();

    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("rt");
        rt.block_on(async move {
            let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
            let addr = listener.local_addr().unwrap();
            ready_tx.send(addr).unwrap();

            let (stream, _) = listener.accept().await.expect("accept");
            let tls = acceptor.accept(stream).await.expect("accept TLS");

            // Pull out the rustls ServerConnection to do the EKM derivation
            // on the server side, using the *same* spec triples the client
            // registered. Then close gracefully.
            let mut derived: Vec<(Vec<u8>, Option<Vec<u8>>, Vec<u8>)> =
                Vec::with_capacity(server_specs.len());
            {
                let (_io, conn) = tls.get_ref();
                for (label, ctx, length) in &server_specs {
                    let buf = vec![0u8; *length];
                    let material = conn
                        .export_keying_material(buf, label, ctx.as_deref())
                        .expect("server export_keying_material");
                    derived.push((label.clone(), ctx.clone(), material));
                }
            }

            // Read until end of the HTTP request headers (`\r\n\r\n`), then
            // respond. We don't bother parsing — the body content doesn't
            // matter for the assertions.
            let mut tls = tls;
            let mut buf = [0u8; 1024];
            let mut accum: Vec<u8> = Vec::new();
            loop {
                let n = match tls.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => n,
                    Err(_) => break,
                };
                accum.extend_from_slice(&buf[..n]);
                if accum.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            let resp = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";
            let _ = tls.write_all(resp).await;
            let _ = tls.shutdown().await;

            let _ = done_tx.send(derived);
        });
    });

    let addr = ready_rx.recv().expect("server ready");
    ServerHandle { addr, received: done_rx }
}

fn build_client(
    specs: &[(Vec<u8>, Option<Vec<u8>>, usize)],
    min: Option<reqwest::tls::Version>,
) -> reqwest::Client {
    install_provider();
    // The test cert is a `testserver.com` cert and we hit 127.0.0.1 / [::1];
    // skip both certificate-chain and hostname verification, and disable any
    // ambient system proxy so we don't get rerouted through CONNECT (which
    // intentionally suppresses `TlsInfo`).
    let mut builder = reqwest::Client::builder()
        .no_proxy()
        .danger_accept_invalid_certs(true)
        .tls_info(true)
        .use_rustls_tls();
    if let Some(v) = min {
        builder = builder.min_tls_version(v).max_tls_version(v);
    }
    for (label, ctx, len) in specs {
        builder = builder.tls_export_keying_material(label.clone(), ctx.clone(), *len);
    }
    builder.build().expect("client build")
}

async fn run_once(
    specs: Vec<(Vec<u8>, Option<Vec<u8>>, usize)>,
    only_tls13: bool,
    request_min: Option<reqwest::tls::Version>,
) -> (
    Vec<(Vec<u8>, Option<Vec<u8>>, Vec<u8>)>,
    reqwest::tls::TlsInfo,
) {
    let handle = spawn_server(specs.clone(), only_tls13);
    // Hit the actual bound address — using 127.0.0.1 directly avoids
    // tokio's localhost-resolves-to-v6-first surprise where the server
    // bound only v4.
    let url = format!("https://{}/", handle.addr);

    let client = build_client(&specs, request_min);
    let resp = match client.get(&url).send().await {
        Ok(r) => r,
        Err(e) => panic!("client send error to {url}: {e:?}"),
    };
    let info = resp
        .extensions()
        .get::<reqwest::tls::TlsInfo>()
        .cloned()
        .expect("TlsInfo missing on response");

    let server_derived = handle.received.await.expect("server thread");
    (server_derived, info)
}

#[tokio::test]
async fn tls13_client_and_server_agree_on_ekm() {
    let specs = vec![(b"EXPORTER-Channel-Binding".to_vec(), None, 32usize)];
    let (server, info) = run_once(specs.clone(), true, Some(reqwest::tls::Version::TLS_1_3)).await;

    let cbt = info
        .keying_material(b"EXPORTER-Channel-Binding", None)
        .expect("client-side EKM present");
    assert_eq!(cbt.len(), 32);
    assert_eq!(cbt, server[0].2.as_slice(), "EKM bytes must match");
}

#[tokio::test]
async fn tls12_client_and_server_agree_on_ekm() {
    let specs = vec![(b"EXPORTER-Channel-Binding".to_vec(), None, 32usize)];
    let (server, info) = run_once(specs.clone(), false, Some(reqwest::tls::Version::TLS_1_2)).await;

    let cbt = info
        .keying_material(b"EXPORTER-Channel-Binding", None)
        .expect("client-side EKM present");
    assert_eq!(cbt.len(), 32);
    assert_eq!(cbt, server[0].2.as_slice(), "EKM bytes must match");
}

#[tokio::test]
async fn two_contexts_produce_distinct_bytes() {
    let specs = vec![
        (b"my-app".to_vec(), None, 32usize),
        (b"my-app".to_vec(), Some(b"alice".to_vec()), 32usize),
    ];
    let (server, info) = run_once(specs.clone(), true, Some(reqwest::tls::Version::TLS_1_3)).await;

    let a = info.keying_material(b"my-app", None).expect("a");
    let b = info
        .keying_material(b"my-app", Some(b"alice"))
        .expect("b");
    assert_eq!(a.len(), 32);
    assert_eq!(b.len(), 32);
    assert_ne!(a, b, "different context must derive different bytes");
    assert_eq!(a, server[0].2.as_slice());
    assert_eq!(b, server[1].2.as_slice());

    // Unregistered (label, context) returns None.
    assert!(info.keying_material(b"my-app", Some(b"bob")).is_none());
    assert!(info.keying_material(b"not-registered", None).is_none());
}

#[tokio::test]
async fn without_tls_info_no_extension() {
    install_provider();
    let handle = spawn_server(vec![], true);
    let url = format!("https://localhost:{}/", handle.addr.port());

    let client = reqwest::Client::builder()
        .no_proxy()
        .danger_accept_invalid_certs(true)
        // tls_info NOT enabled — TlsInfo must not appear.
        .use_rustls_tls()
        .tls_export_keying_material(b"x".to_vec(), None, 16)
        .build()
        .expect("client");
    let resp = client.get(&url).send().await.expect("send");
    assert!(
        resp.extensions().get::<reqwest::tls::TlsInfo>().is_none(),
        "TlsInfo must be absent when tls_info(false)"
    );

    // Drain the server thread so the OS port can be released.
    let _ = handle.received.await;
}

#[tokio::test]
async fn debug_format_of_real_tls_info_never_prints_material_bytes() {
    // Run a real handshake, then assert the Debug output of TlsInfo does
    // not contain any of the derived EKM bytes.
    let specs = vec![(b"EXPORTER-Channel-Binding".to_vec(), None, 32usize)];
    let (_server, info) = run_once(specs, true, Some(reqwest::tls::Version::TLS_1_3)).await;

    let derived = info
        .keying_material(b"EXPORTER-Channel-Binding", None)
        .expect("client-side EKM present");
    let dbg = format!("{:?}", info);
    // Look for any 4-byte substring of the secret. (Looking for the whole
    // 32-byte secret would be redundant with the strong all-or-nothing
    // formatting elision; 4 bytes is enough to catch any partial leak.)
    for window in derived.windows(4) {
        let hex = format!("{:02x?}", window);
        assert!(
            !dbg.contains(&hex),
            "Debug output leaked secret bytes (window {hex} found in {dbg:?})"
        );
    }
    // Also probe the obvious ascii rendering rust uses for byte arrays.
    let bytes_repr = format!("{:?}", derived);
    assert!(!dbg.contains(&bytes_repr));
}
