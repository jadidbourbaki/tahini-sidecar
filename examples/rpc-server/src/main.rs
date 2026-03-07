use std::env;
use std::fs::File;
use std::process;

use fizz_rs::{CertificatePublic, DelegatedCredentialData, ServerTlsContext};
use serde::Deserialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[derive(Deserialize)]
#[allow(non_snake_case)]
struct ServerCredentialJson {
    signatureScheme: u16,
    credentialPEM: String,
}

struct Args {
    secret: String,
    dc_path: String,
    cert_path: String,
    port: u16,
}

fn parse_args() -> Args {
    let argv: Vec<String> = env::args().collect();
    let mut secret = None;
    let mut dc_path = None;
    let mut cert_path = None;
    let mut port: u16 = 8443;

    let mut i = 1;
    while i < argv.len() {
        match argv[i].as_str() {
            "--tahini-secret" if i + 1 < argv.len() => {
                secret = Some(argv[i + 1].clone());
                i += 2;
            }
            "--tahini-dc" if i + 1 < argv.len() => {
                dc_path = Some(argv[i + 1].clone());
                i += 2;
            }
            "--tahini-dc-cert" if i + 1 < argv.len() => {
                cert_path = Some(argv[i + 1].clone());
                i += 2;
            }
            "--port" if i + 1 < argv.len() => {
                port = argv[i + 1].parse().unwrap_or(8443);
                i += 2;
            }
            _ => { i += 1; }
        }
    }

    let secret = secret.unwrap_or_else(|| {
        eprintln!("error: --tahini-secret is required");
        process::exit(1);
    });
    let dc_path = dc_path.unwrap_or_else(|| {
        eprintln!("error: --tahini-dc is required");
        process::exit(1);
    });
    let cert_path = cert_path.unwrap_or_else(|| {
        eprintln!("error: --tahini-dc-cert is required");
        process::exit(1);
    });

    Args { secret, dc_path, cert_path, port }
}

#[tokio::main]
async fn main() {
    let args = parse_args();

    if args.secret.len() >= 16 {
        eprintln!("[rpc-server] tahini secret: {}...{}", &args.secret[..8], &args.secret[args.secret.len()-8..]);
    } else {
        eprintln!("[rpc-server] tahini secret: {}", args.secret);
    }
    eprintln!("[rpc-server] loading credential from {}", args.dc_path);
    eprintln!("[rpc-server] loading parent cert from {}", args.cert_path);

    let cert = CertificatePublic::load_from_file(&args.cert_path)
        .expect("failed to load parent certificate");

    let file = File::open(&args.dc_path).expect("failed to open delegated credential server JSON");
    let json: ServerCredentialJson = serde_json::from_reader(file)
        .expect("failed to parse delegated credential server JSON");
    let dc = DelegatedCredentialData::from_pem(&json.credentialPEM)
        .expect("failed to load delegated credential from PEM");

    let tls = ServerTlsContext::new(cert, dc).expect("failed to create server TLS context");

    let bind_addr = format!("0.0.0.0:{}", args.port);
    let listener = TcpListener::bind(&bind_addr).await.expect("failed to bind");
    eprintln!("[rpc-server] listening on {}", bind_addr);

    loop {
        let mut conn = match tls.accept(&listener).await {
            Ok(c) => c,
            Err(e) => {
                eprintln!("[rpc-server] accept error: {}", e);
                continue;
            }
        };
        eprintln!("[rpc-server] client connected");

        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            loop {
                let n = match conn.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => n,
                    Err(e) => {
                        eprintln!("[rpc-server] read error: {}", e);
                        break;
                    }
                };
                let msg = String::from_utf8_lossy(&buf[..n]);
                eprintln!("[rpc-server] received: {}", msg);

                if let Err(e) = conn.write_all(&buf[..n]).await {
                    eprintln!("[rpc-server] write error: {}", e);
                    break;
                }
            }
            eprintln!("[rpc-server] client disconnected");
        });
    }
}
