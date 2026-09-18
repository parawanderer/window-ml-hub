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
use wmlhub_connector::pair::{Offer, PAIRING_WINDOW};
use wmlhub_connector::state::State;
use wmlhub_keys::{hex, principal_id, verify_chain};

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

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

#[tokio::main]
async fn main() -> ExitCode {
    match Cli::parse().command {
        Command::Pair(args) => pair(args).await,
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
