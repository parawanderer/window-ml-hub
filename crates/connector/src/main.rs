//! `wmlbox`: pair a box connector with an account, and say what it is.
//!
//! Relaying a box's `/api/events` is the library beside this (`wmlhub_connector`); what this binary adds is the part
//! a person does. A connector has no certificate until somebody with a paired device gives it one, and the whole of
//! that exchange's security is a person comparing a fingerprint on two screens — so the terminal has to show it in a
//! way that invites comparison rather than a wall of hex.

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::{Parser, Subcommand};
use tokio::sync::{mpsc, watch};
use wmlhub_client::{Client, Config};
use wmlhub_connector::pair::{Offer, PAIRING_WINDOW};
use wmlhub_connector::relay::Channels;
use wmlhub_connector::run::{Connector, PENDING_FRAMES};
use wmlhub_connector::serve::{Revoking, Serving};
use wmlhub_connector::state::State;
use wmlhub_connector::{Target, state::Keys};
use wmlhub_keys::{hex, principal_id, verify_chain};
use wmlhub_proto::v1::Role;
use wmlhub_seal::{ChannelKey, Sender, StreamKey};

#[derive(Parser)]
#[command(name = "wmlbox", version, about = "The window.ml box connector: relays a box's events through a hub")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Pair this connector with an account, by showing a code and a fingerprint for somebody to confirm.
    Pair(Pair),
    /// Read this box's events and publish them through the hub, for as long as both are there.
    Run(Run),
    /// Say who this connector is and what it was paired with.
    Status {
        #[arg(long, env = "WMLBOX_STATE_DIR", default_value = "wmlbox-state")]
        state_dir: PathBuf,
    },
}

#[derive(clap::Args)]
struct Pair {
    /// The hub to pair through (`ws://` or `wss://`). The same hub the account's other devices are on.
    #[arg(long, env = "WMLBOX_HUB")]
    hub: String,
    /// What to call this box in the paired-devices list.
    #[arg(long, env = "WMLBOX_LABEL", default_value = "box connector")]
    label: String,
    /// Where this connector's keys and certificate are kept. Its contents are secret: it is created `0700` and every
    /// file in it `0600`.
    #[arg(long, env = "WMLBOX_STATE_DIR", default_value = "wmlbox-state")]
    state_dir: PathBuf,
    /// Pair again with a different account, replacing the certificate this connector holds. Its keys are kept, so it
    /// stays the same principal.
    #[arg(long)]
    again: bool,
}

#[derive(clap::Args)]
struct Run {
    /// The hub to publish through (`ws://` or `wss://`). The one this connector was paired on.
    #[arg(long, env = "WMLBOX_HUB")]
    hub: String,
    /// The name the hub is known by, which is signed into every login. A hub calling itself something else is
    /// refused before this connector signs anything.
    #[arg(long, env = "WMLBOX_HUB_NAME")]
    hub_name: String,
    /// The box's events endpoint (`http://127.0.0.1:11434/api/events`).
    #[arg(long, env = "WMLBOX_BOX", default_value = "http://127.0.0.1:11434/api/events")]
    r#box: String,
    #[arg(long, env = "WMLBOX_STATE_DIR", default_value = "wmlbox-state")]
    state_dir: PathBuf,
}

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

#[tokio::main]
async fn main() -> ExitCode {
    match Cli::parse().command {
        Command::Pair(args) => pair(args).await,
        Command::Run(args) => run(args).await,
        Command::Status { state_dir } => status(&State::at(state_dir)),
    }
}

async fn pair(args: Pair) -> ExitCode {
    let state = State::at(&args.state_dir);
    match state.paired() {
        Ok(Some(_)) if !args.again => {
            return fail(&format!(
                "already paired: {} holds a certificate. `wmlbox status` says what it is, and `--again` replaces it",
                state.dir().display()
            ));
        }
        Ok(_) => {}
        Err(e) => return fail(&e.to_string()),
    }

    // The keys outlive any one pairing: pairing again with the same keys keeps the connector the same principal, so
    // whatever was granted to it stays granted to it.
    let keys = match state.keys() {
        Ok(Some(keys)) => keys,
        Ok(None) => match state.generate_keys() {
            Ok(keys) => keys,
            Err(e) => return fail(&format!("cannot write keys to {}: {e}", state.dir().display())),
        },
        Err(e) => return fail(&e.to_string()),
    };

    let offer = match Offer::new(&keys, &args.label, now_ms()) {
        Ok(offer) => offer,
        Err(e) => return fail(&e.to_string()),
    };
    // The hub first: an unreachable one should say so before a person is told to carry a code to another room.
    let mut left = match offer.leave(&args.hub).await {
        Ok(left) => left,
        Err(e) => return fail(&e.to_string()),
    };
    println!("Pairing code   {}", spaced(offer.code()));
    println!("Fingerprint    {}", spaced_fingerprint(&offer.fingerprint()));
    println!();
    println!("Type the code into a device that may pair on this account, and confirm that it shows the same");
    println!("fingerprint. If it shows a different one, refuse it: something between this box and that device");
    println!("is offering its own keys instead.");
    println!();
    println!("Waiting up to {} minutes...", PAIRING_WINDOW.as_secs() / 60);

    let paired = match left.answer(PAIRING_WINDOW, now_ms).await {
        Ok(paired) => paired,
        Err(e) => return fail(&e.to_string()),
    };
    if let Err(e) = state.write_paired(&paired) {
        return fail(&format!("paired, but cannot write {}: {e}", state.dir().display()));
    }
    println!();
    println!("Paired.");
    status(&state)
}

/// Everything a connector needs to publish, checked before it connects so that a failure names itself rather than
/// arriving as a hub refusing a hello.
struct Ready {
    keys: Keys,
    /// a second copy of the same keys: the client takes ownership of one, and the publisher signs grants with the
    /// other. Two values of one key pair, not two key pairs.
    publisher_identity: wmlhub_keys::Identity,
    chain: Vec<wmlhub_proto::v1::Certificate>,
    account_root: [u8; 32],
    label: String,
    channel_key: ChannelKey,
}

fn loaded(state: &State) -> Result<Ready, String> {
    let keys = || match state.keys() {
        Ok(Some(keys)) => Ok(keys),
        Ok(None) => Err(format!("not paired: no keys in {}. Run `wmlbox pair --hub <url>`", state.dir().display())),
        Err(e) => Err(e.to_string()),
    };
    let (keys, again) = (keys()?, keys()?);
    let Some(paired) = state.paired().map_err(|e| e.to_string())? else {
        return Err(format!("not paired: run `wmlbox pair --hub <url>` in {}", state.dir().display()));
    };
    let account_root = <[u8; 32]>::try_from(paired.account_root.as_slice())
        .map_err(|_| "the account root in this connector's state is not a key; pair it again".to_owned())?;
    let verified = verify_chain(&account_root, &paired.chain, now_ms())
        .map_err(|e| format!("this connector's certificate does not verify ({e:?}); pair it again with --again"))?;
    let channel_key = <[u8; 32]>::try_from(paired.channel_key.as_slice())
        .map_err(|_| "the channel key in this connector's state is not a key; pair it again".to_owned())?;
    Ok(Ready {
        keys,
        publisher_identity: again.identity,
        chain: paired.chain,
        account_root,
        label: verified.leaf.label,
        channel_key: ChannelKey::from_bytes(channel_key),
    })
}

async fn run(args: Run) -> ExitCode {
    tracing_subscriber::fmt().with_target(false).with_ansi(std::io::IsTerminal::is_terminal(&std::io::stdout())).init();
    let state = State::at(&args.state_dir);
    let ready = match loaded(&state) {
        Ok(ready) => ready,
        Err(e) => return fail(&e),
    };
    let target = match Target::parse(&args.r#box) {
        Ok(target) => target,
        Err(e) => return fail(&format!("--box {}: {e:?}", args.r#box)),
    };

    // The channels are named for this connector's own principal, not for a label somebody typed: a device reading
    // them knows the principal from the paired-devices list, and two boxes called the same thing would otherwise
    // publish on one channel.
    let me = principal_id(&ready.keys.identity.public());
    let channels = Channels {
        edge: ready.channel_key.channel("box.edges", &me).to_vec(),
        sample: ready.channel_key.channel("box.samples", &me).to_vec(),
    };
    // A fresh key per run, so "everything this key covered" is one run of this connector and a restart is a rotation
    // nobody has to coordinate. A device that held the old one asks again.
    let key = match StreamKey::generate() {
        Ok(key) => key,
        Err(e) => return fail(&format!("no random source: {e}")),
    };
    // Who is revoked, as this connector last knew it. Loaded before connecting: a connector that cannot read it must
    // not start granting as if nobody were.
    let revocations = match state.revocations(&ready.account_root) {
        Ok(revocations) => revocations,
        Err(e) => return fail(&format!("cannot read what this connector knew about revocations: {e}")),
    };
    if let Some(armed_at) = revocations.armed_at() {
        tracing::info!(
            armed_at,
            list = ?revocations.held().map(|held| held.version),
            "following the account's revocation list; new grants stop if it goes a week without one"
        );
    }

    let (frames_tx, mut frames_rx) = mpsc::channel(PENDING_FRAMES);
    let (published_tx, published_rx) = watch::channel(None);
    let mut box_side = Connector::new(target, frames_tx, published_rx);
    tokio::spawn(async move { box_side.run(now_ms).await });

    let mut client = match Client::connect(Config {
        url: args.hub.clone(),
        hub_name: args.hub_name.clone(),
        identity: ready.keys.identity,
        agreement: ready.keys.agreement,
        chain: ready.chain.clone(),
        account_root: ready.account_root,
        role: Role::BoxConnector,
        invite: Vec::new(),
    })
    .await
    {
        Ok(client) => client,
        Err(e) => return fail(&format!("cannot log in to {}: {e:?}", args.hub)),
    };
    tracing::info!(
        hub = %args.hub,
        r#box = %args.r#box,
        label = %ready.label,
        principal = %hex(&me),
        "publishing"
    );

    // The grant carries this connector's own chain, which is how a device checks that the key it was handed came
    // from the publisher it is subscribed to rather than from the hub.
    let publisher = Sender { identity: &ready.publisher_identity, chain: &ready.chain };
    let revoking = Revoking { channel_key: &ready.channel_key, revocations, state: &state };
    let mut serving = Serving::new(publisher, key, channels, revoking, published_tx);
    let stopped = tokio::select! {
        stopped = serving.run(&mut client, &mut frames_rx, &now_ms) => Some(stopped),
        _ = tokio::signal::ctrl_c() => None,
    };
    let counts = serving.counts().clone();
    tracing::info!(?counts, "stopping");
    match stopped {
        Some(e) => fail(&format!("{e:?}")),
        None => ExitCode::SUCCESS,
    }
}

fn status(state: &State) -> ExitCode {
    let keys = match state.keys() {
        Ok(Some(keys)) => keys,
        Ok(None) => {
            eprintln!("not paired: no keys in {}. Run `wmlbox pair --hub <url>`", state.dir().display());
            return ExitCode::SUCCESS;
        }
        Err(e) => return fail(&e.to_string()),
    };
    println!("Principal      {}", hex(&principal_id(&keys.identity.public())));
    let paired = match state.paired() {
        Ok(Some(paired)) => paired,
        Ok(None) => {
            println!("Paired         no. Run `wmlbox pair --hub <url>`");
            return ExitCode::SUCCESS;
        }
        Err(e) => return fail(&e.to_string()),
    };
    let Ok(root) = <[u8; 32]>::try_from(paired.account_root.as_slice()) else {
        return fail("the account root in this connector's state is not a key; pair it again");
    };
    println!("Account        {}", hex(&root));
    // Verified rather than decoded, so an expired or otherwise refused certificate is reported here rather than as a
    // hello a hub will not accept.
    match verify_chain(&root, &paired.chain, now_ms()) {
        Ok(verified) => {
            println!("Label          {}", verified.leaf.label);
            println!("Role           {:?}", verified.leaf.role());
            println!("Certificate    valid for {}", for_how_long(verified.leaf.not_after_ms, now_ms()));
        }
        Err(e) => {
            println!("Certificate    NOT USABLE: {e:?}");
            println!("               pair it again: `wmlbox pair --hub <url> --again`");
        }
    }
    ExitCode::SUCCESS
}

/// Days and hours, because the thing an operator wants from an expiry is whether it is a problem this week.
fn for_how_long(not_after_ms: u64, now_ms: u64) -> String {
    let left = not_after_ms.saturating_sub(now_ms) / 1000;
    match (left / 86_400, (left % 86_400) / 3_600) {
        (0, 0) => format!("{} minutes", (left % 3_600) / 60),
        (0, hours) => format!("{hours} hours"),
        (days, hours) => format!("{days} days, {hours} hours"),
    }
}

/// A pairing code in two groups of four. A person is about to read this aloud or type it into a phone, and eight
/// undifferentiated characters is where that goes wrong.
fn spaced(code: &str) -> String {
    let (left, right) = code.split_at(code.len() / 2);
    format!("{left} {right}")
}

/// A fingerprint in groups of four, for the same reason, and because the comparison is character by character: this
/// is the one thing on the screen a person is expected to check rather than read.
fn spaced_fingerprint(fingerprint: &str) -> String {
    fingerprint.as_bytes().chunks(4).map(|c| String::from_utf8_lossy(c).into_owned()).collect::<Vec<_>>().join(" ")
}

fn fail(message: &str) -> ExitCode {
    eprintln!("wmlbox: {message}");
    ExitCode::from(2)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_code_and_a_fingerprint_are_grouped_for_reading_aloud() {
        assert_eq!(spaced("ABCD2345"), "ABCD 2345");
        assert_eq!(spaced_fingerprint("0123456789ab"), "0123 4567 89ab");
    }

    #[test]
    fn an_expiry_is_said_in_what_an_operator_would_ask() {
        let now = 1_800_000_000_000;
        assert_eq!(for_how_long(now + 90 * 86_400_000, now), "90 days, 0 hours");
        assert_eq!(for_how_long(now + 5 * 3_600_000, now), "5 hours");
        assert_eq!(for_how_long(now + 90_000, now), "1 minutes");
        assert_eq!(for_how_long(now - 1, now), "0 minutes", "an expired certificate does not go negative");
    }
}
