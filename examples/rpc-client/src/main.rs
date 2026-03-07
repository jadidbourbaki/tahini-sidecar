use std::env;
use std::fs::File;
use std::process;

use fizz_rs::{ClientTlsContext, VerificationInfo};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

struct Args {
    sig_path: String,
    cert_path: String,
    server: String,
}

fn parse_args() -> Args {
    let argv: Vec<String> = env::args().collect();
    let mut sig_path = None;
    let mut cert_path = None;
    let mut server = None;

    let mut i = 1;
    while i < argv.len() {
        match argv[i].as_str() {
            "--dc-sig" if i + 1 < argv.len() => {
                sig_path = Some(argv[i + 1].clone());
                i += 2;
            }
            "--dc-cert" if i + 1 < argv.len() => {
                cert_path = Some(argv[i + 1].clone());
                i += 2;
            }
            "--server" if i + 1 < argv.len() => {
                server = Some(argv[i + 1].clone());
                i += 2;
            }
            _ => { i += 1; }
        }
    }

    let sig_path = sig_path.unwrap_or_else(|| {
        eprintln!("error: --dc-sig is required");
        process::exit(1);
    });
    let cert_path = cert_path.unwrap_or_else(|| {
        eprintln!("error: --dc-cert is required");
        process::exit(1);
    });
    let server = server.unwrap_or_else(|| {
        eprintln!("error: --server is required (e.g. server:8443)");
        process::exit(1);
    });

    Args { sig_path, cert_path, server }
}

#[tokio::main]
async fn main() {
    let args = parse_args();

    eprintln!("[rpc-client] loading verification info from {}", args.sig_path);
    eprintln!("[rpc-client] loading parent cert from {}", args.cert_path);
    eprintln!("[rpc-client] connecting to {}", args.server);

    let file = File::open(&args.sig_path).expect("failed to open verification info JSON");
    let info: VerificationInfo = serde_json::from_reader(file)
        .expect("failed to parse verification info JSON");

    let tls = ClientTlsContext::new(info, &args.cert_path)
        .expect("failed to create client TLS context");

    let host = args.server.split(':').next().unwrap_or("localhost");

    let stream = TcpStream::connect(&args.server).await
        .expect("failed to connect to server");
    eprintln!("[rpc-client] TCP connected to {}", args.server);

    let mut conn = tls.connect(stream, host).await
        .expect("TLS handshake failed");
    eprintln!("[rpc-client] TLS handshake succeeded (delegated credential verified)");

    let message = b"Hello from tahini rpc-client over delegated TLS!";
    conn.write_all(message).await.expect("failed to send message");
    conn.flush().await.expect("failed to flush");
    eprintln!("[rpc-client] sent: {}", String::from_utf8_lossy(message));

    let mut buf = vec![0u8; 4096];
    let n = conn.read(&mut buf).await.expect("failed to read response");
    let response = String::from_utf8_lossy(&buf[..n]);
    eprintln!("[rpc-client] received echo: {}", response);

    conn.shutdown().await.expect("failed to close connection");
    eprintln!("[rpc-client] connection closed");
}
