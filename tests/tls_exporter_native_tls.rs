//! Integration tests for native-tls + TLS exporter (RFC 5705 / RFC 8446).
//!
//! Mirrors `tests/tls_exporter.rs` but builds the reqwest client with the
//! `native-tls` backend. The server side is still rustls because EKM is a
//! spec-defined primitive (both endpoints derive the same bytes given the
//! same session secrets regardless of TLS implementation).
//!
//! Only enabled on platforms where native-tls' underlying library actually
//! implements `SSL_export_keying_material` — i.e. the OpenSSL backend. On
//! Apple (Secure Transport) and Windows (SChannel) the per-spec call
//! returns an error and reqwest skips the entry, which we don't assert
//! against here.
#![cfg(feature = "__native-tls")]
#![cfg(all(
    feature = "__rustls-aws-lc-rs",
    not(feature = "rustls-no-provider"),
    any(
        target_os = "linux",
        target_os = "android",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly",
        target_os = "illumos",
        target_os = "solaris",
    ),
))]

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
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    });
}

fn load_server_config(only_tls13: bool) -> Arc<rustls::ServerConfig> {
    let cert_der: rustls_pki_types::CertificateDer<'static> =
        std::fs::read("tests/support/server.cert").unwrap().into();
    let key_der: rustls_pki_types::PrivateKeyDer<'static> =
        std::fs::read("tests/support/server.key").unwrap().try_into().unwrap();

    let builder = if only_tls13 {
        rustls::ServerConfig::builder_with_protocol_versions(&[&version::TLS13])
    } else {
        rustls::ServerConfig::builder_with_protocol_versions(&[&version::TLS12])
    };
    let mut cfg = builder
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .expect("server config");
    cfg.alpn_protocols.clear();
    Arc::new(cfg)
}

struct ServerHandle {
    addr: SocketAddr,
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
    let mut builder = reqwest::Client::builder()
        .no_proxy()
        .danger_accept_invalid_certs(true)
        .tls_info(true)
        .use_native_tls();
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
async fn native_tls_tls13_client_and_server_agree_on_ekm() {
    let specs = vec![(b"EXPORTER-Channel-Binding".to_vec(), None, 32usize)];
    let (server, info) = run_once(specs.clone(), true, Some(reqwest::tls::Version::TLS_1_3)).await;

    let cbt = info
        .keying_material(b"EXPORTER-Channel-Binding", None)
        .expect("client-side EKM present");
    assert_eq!(cbt.len(), 32);
    assert_eq!(cbt, server[0].2.as_slice(), "EKM bytes must match");
}

#[tokio::test]
async fn native_tls_tls12_client_and_server_agree_on_ekm() {
    let specs = vec![(b"EXPORTER-Channel-Binding".to_vec(), None, 32usize)];
    let (server, info) = run_once(specs.clone(), false, Some(reqwest::tls::Version::TLS_1_2)).await;

    let cbt = info
        .keying_material(b"EXPORTER-Channel-Binding", None)
        .expect("client-side EKM present");
    assert_eq!(cbt.len(), 32);
    assert_eq!(cbt, server[0].2.as_slice(), "EKM bytes must match");
}

#[tokio::test]
async fn native_tls_two_contexts_produce_distinct_bytes() {
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

    assert!(info.keying_material(b"my-app", Some(b"bob")).is_none());
    assert!(info.keying_material(b"not-registered", None).is_none());
}
