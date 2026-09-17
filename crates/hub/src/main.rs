//! `wmlhub`: run the relay.
//!
//! There is no authentication yet (docs/ROADMAP.md steps 5 and 6), so the only way it starts is `--dev` on a
//! loopback address, where it trusts the principal a `Hello` claims. It refuses anything else rather than run
//! unauthenticated where another machine could reach it.

use std::net::SocketAddr;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

const USAGE: &str = "usage: wmlhub --dev [--listen 127.0.0.1:8787]";

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt().with_target(false).init();

    let mut dev = false;
    let mut listen: SocketAddr = ([127, 0, 0, 1], 8787).into();
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--dev" => dev = true,
            "--listen" => match args.next().map(|a| a.parse()) {
                Some(Ok(addr)) => listen = addr,
                _ => return usage("--listen needs an address such as 127.0.0.1:8787"),
            },
            "-h" | "--help" => {
                println!("{USAGE}");
                return ExitCode::SUCCESS;
            }
            other => return usage(&format!("unknown argument {other}")),
        }
    }
    if !dev {
        return usage("no authentication yet, so it runs only with --dev");
    }
    if !listen.ip().is_loopback() {
        return usage("--dev trusts every hello, so it listens only on a loopback address");
    }

    let listener = match tokio::net::TcpListener::bind(listen).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("wmlhub: cannot listen on {listen}: {e}");
            return ExitCode::FAILURE;
        }
    };
    tracing::warn!(%listen, "development mode: no authentication, loopback only");
    let seed =
        SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_nanos() as u64) ^ u64::from(std::process::id());

    tokio::select! {
        result = wmlhub::serve(listener, wmlhub::Config::default(), seed) => {
            if let Err(e) = result {
                eprintln!("wmlhub: {e}");
                return ExitCode::FAILURE;
            }
        }
        _ = tokio::signal::ctrl_c() => tracing::info!("shutting down"),
    }
    ExitCode::SUCCESS
}

fn usage(message: &str) -> ExitCode {
    eprintln!("wmlhub: {message}\n{USAGE}");
    ExitCode::from(2)
}
