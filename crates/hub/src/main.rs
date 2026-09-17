//! `wmlhub`: run the relay, and manage who may register on it.
//!
//! Every `serve` option also reads an environment variable (`WMLHUB_*`), which is how the Docker image is
//! configured. See docs/SELF_HOSTING.md.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use clap::{Parser, Subcommand};
use wmlhub::registry::{OpenLimits, Registration, Registry};

#[derive(Parser)]
#[command(name = "wmlhub", version, about = "The window.ml hub: a relay that reads envelopes and forwards ciphertext")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the hub.
    Serve(Serve),
    /// Create or list invites (registration mode `invite`).
    Invite {
        #[command(subcommand)]
        command: InviteCommand,
    },
    /// List registered accounts.
    Accounts {
        #[command(subcommand)]
        command: AccountsCommand,
    },
}

#[derive(clap::Args)]
struct Serve {
    /// Address to listen on. The hub speaks plain websockets: put TLS in front of it (Tailscale, Caddy, a load
    /// balancer) for anything but loopback.
    #[arg(long, env = "WMLHUB_LISTEN", default_value = "127.0.0.1:8787")]
    listen: SocketAddr,
    /// The name clients know this hub by, usually its hostname (hub.example.com, myhub.tailnet-name.ts.net). It is
    /// signed into every login, so it must match what clients are configured with.
    #[arg(long, env = "WMLHUB_HUB_NAME", required_unless_present = "dev")]
    hub_name: Option<String>,
    /// Where registered accounts and outstanding invites are kept.
    #[arg(long, env = "WMLHUB_STATE_DIR", default_value = "wmlhub-state")]
    state_dir: PathBuf,
    /// Who may register a new account: `invite` (needs `wmlhub invite create`) or `open` (anyone, rate limited).
    #[arg(long, env = "WMLHUB_REGISTRATION", default_value = "invite")]
    registration: Registration,
    /// Open registration: new accounts per source address per hour.
    #[arg(long, env = "WMLHUB_OPEN_PER_ADDRESS", default_value_t = OpenLimits::default().per_address)]
    open_per_address: u32,
    /// Open registration: new accounts in total per hour.
    #[arg(long, env = "WMLHUB_OPEN_TOTAL", default_value_t = OpenLimits::default().total)]
    open_total: u32,
    /// Independent relay shards, each with its own lock. 0 picks four per core.
    #[arg(long, env = "WMLHUB_SHARDS", default_value_t = 0)]
    shards: usize,
    /// Development mode: no authentication, trusts whatever a client claims. Loopback addresses only.
    #[arg(long, env = "WMLHUB_DEV")]
    dev: bool,
}

#[derive(Subcommand)]
enum InviteCommand {
    /// Create a single-use invite and print its token. Safe to run while the hub is serving.
    Create {
        #[arg(long, env = "WMLHUB_STATE_DIR", default_value = "wmlhub-state")]
        state_dir: PathBuf,
        /// How long the invite stays valid.
        #[arg(long, default_value_t = 168)]
        ttl_hours: u64,
    },
    /// List outstanding invites (hash prefix and expiry; tokens are not stored).
    List {
        #[arg(long, env = "WMLHUB_STATE_DIR", default_value = "wmlhub-state")]
        state_dir: PathBuf,
    },
}

#[derive(Subcommand)]
enum AccountsCommand {
    /// List registered account ids.
    List {
        #[arg(long, env = "WMLHUB_STATE_DIR", default_value = "wmlhub-state")]
        state_dir: PathBuf,
    },
}

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::Serve(args) => serve(args).await,
        Command::Invite { command: InviteCommand::Create { state_dir, ttl_hours } } => {
            match Registry::create_invite(&state_dir, Duration::from_secs(ttl_hours.saturating_mul(3600)), now_ms()) {
                Ok(token) => {
                    println!("{token}");
                    eprintln!("single use, valid for {ttl_hours} hours; give it to the person registering");
                    ExitCode::SUCCESS
                }
                Err(e) => fail(&format!("cannot create an invite in {}: {e}", state_dir.display())),
            }
        }
        Command::Invite { command: InviteCommand::List { state_dir } } => match Registry::list_invites(&state_dir) {
            Ok(invites) => {
                let now = now_ms();
                if invites.is_empty() {
                    eprintln!("no outstanding invites");
                }
                for (prefix, expires) in invites {
                    if expires < now {
                        println!("{prefix}  expired");
                    } else {
                        println!("{prefix}  valid for {}h", (expires - now) / 3_600_000);
                    }
                }
                ExitCode::SUCCESS
            }
            Err(e) => fail(&format!("cannot read {}: {e}", state_dir.display())),
        },
        Command::Accounts { command: AccountsCommand::List { state_dir } } => match Registry::list_accounts(&state_dir)
        {
            Ok(accounts) => {
                accounts.iter().for_each(|a| println!("{a}"));
                ExitCode::SUCCESS
            }
            Err(e) => fail(&format!("cannot read {}: {e}", state_dir.display())),
        },
    }
}

async fn serve(args: Serve) -> ExitCode {
    // Colour only on a terminal: `docker logs` and log files otherwise fill with escape codes.
    tracing_subscriber::fmt().with_target(false).with_ansi(std::io::IsTerminal::is_terminal(&std::io::stdout())).init();

    let auth = if args.dev {
        if !args.listen.ip().is_loopback() {
            return fail("--dev trusts every hello, so it listens only on a loopback address");
        }
        tracing::warn!(listen = %args.listen, "development mode: no authentication, loopback only");
        wmlhub::Auth::Development
    } else {
        let Some(hub_name) = args.hub_name.filter(|n| !n.trim().is_empty()) else {
            return fail("--hub-name (WMLHUB_HUB_NAME) is required");
        };
        let limits = OpenLimits { per_address: args.open_per_address, total: args.open_total, ..OpenLimits::default() };
        let registry = match Registry::open(&args.state_dir, args.registration, limits) {
            Ok(r) => r,
            Err(e) => return fail(&format!("cannot use state directory {}: {e}", args.state_dir.display())),
        };
        let accounts = Registry::list_accounts(&args.state_dir).map_or(0, |a| a.len());
        tracing::info!(listen = %args.listen, hub = %hub_name, registration = ?args.registration, accounts, "serving");
        if args.registration == Registration::Invite && accounts == 0 {
            tracing::info!("no accounts yet: create an invite with `wmlhub invite create`");
        }
        if !args.listen.ip().is_loopback() {
            tracing::warn!("listening beyond loopback: terminate TLS in front of the hub (Tailscale, Caddy)");
        }
        wmlhub::Auth::Keys { hub_name, registry: Arc::new(registry) }
    };

    let listener = match tokio::net::TcpListener::bind(args.listen).await {
        Ok(l) => l,
        Err(e) => return fail(&format!("cannot listen on {}: {e}", args.listen)),
    };
    let seed = now_ms() ^ u64::from(std::process::id()).rotate_left(32);
    let config = wmlhub::Config { auth, shards: args.shards, ..wmlhub::Config::default() };
    tokio::select! {
        result = wmlhub::serve(listener, config, seed) => {
            if let Err(e) = result {
                return fail(&e.to_string());
            }
        }
        _ = tokio::signal::ctrl_c() => tracing::info!("shutting down"),
    }
    ExitCode::SUCCESS
}

fn fail(message: &str) -> ExitCode {
    eprintln!("wmlhub: {message}");
    ExitCode::from(2)
}
