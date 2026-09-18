//! The one command a box connector answers: "grant me the key to your streams".
//!
//! A publisher has to wrap its stream key for every device allowed to read it, and a connector has no directory of
//! an account's devices: it knows its own keys and whatever reaches it. So the device asks. What makes that safe is
//! that the asking is a sealed command like any other, and the seal already carries everything the decision needs —
//! the sender's chain up to the account root, the scope its leaf grants, and the agreement key to wrap to. A
//! connector that answered a list it was handed instead would be trusting whoever handed it the list.
//!
//! A refusal is silence. The common one never reaches here at all: a command from a principal whose certificate does
//! not grant `view` fails in `Receiver::open`, so there is nothing to answer it with. The asker learns it worked
//! when the grant arrives, and that the connector is there from presence.

use wmlhub_keys::scope;
use wmlhub_seal::{Opened, Recipient, SealError, Sender, StreamKey, wrap_key};

use crate::relay::Channels;

/// The body of the command, as UTF-8. The session contract (window-ml `SESSION_CONTRACT.md`) is a runtime's
/// vocabulary and a connector implements none of it, so this is the whole of its own: one name, no arguments,
/// because the only thing a connector has to give is the key to the two channels it publishes on.
pub const GRANT_COMMAND: &str = "box.grant";

/// The first counter a grant covers. The stream key is generated when a connector starts, so "everything this key
/// covered" is bounded by one run of it, and what excludes a device is rotating the key rather than where a grant
/// begins.
const FROM_COUNTER: u64 = 1;

/// Why a command was not answered with a grant.
#[derive(Debug, PartialEq, Eq)]
pub enum Refused {
    /// not `box.grant`: a connector answers one command and does not guess at others
    NotTheCommand,
    /// the command did not need `view`, so nothing established that the sender may read the stream
    WrongScope,
    /// the sender's certificate carries no usable agreement key, so a grant to it could not be opened
    NoAgreementKey,
}

/// The wrapped stream key for each channel, for whoever asked, or why not.
///
/// The scope is checked here as well as in the seal, though the seal is what enforces it: `open` refuses a command
/// whose sender does not hold the scope the command names, so this only catches a command that named a different
/// one. Reading it as a permission a second time is what makes the permission visible at the decision.
pub fn wrap_for(
    asked: &Opened,
    publisher: &Sender,
    key: &StreamKey,
    channels: &Channels,
    now_ms: u64,
) -> Result<Result<[Vec<u8>; 2], Refused>, SealError> {
    if asked.body != GRANT_COMMAND.as_bytes() {
        return Ok(Err(Refused::NotTheCommand));
    }
    if asked.scope != scope::VIEW {
        return Ok(Err(Refused::WrongScope));
    }
    let Ok(agreement_key) = <[u8; 32]>::try_from(asked.leaf.agreement_key.as_slice()) else {
        return Ok(Err(Refused::NoAgreementKey));
    };
    let to = Recipient { principal: asked.from, agreement_key };
    let edge = wrap_key(publisher, &to, &channels.edge, key, FROM_COUNTER, now_ms)?;
    let sample = wrap_key(publisher, &to, &channels.sample, key, FROM_COUNTER, now_ms)?;
    Ok(Ok([edge, sample]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use wmlhub_keys::Identity;
    use wmlhub_proto::v1::CertificateBody;

    const NOW: u64 = 1_800_000_000_000;

    fn asked(scope: &str, body: &[u8], agreement_key: Vec<u8>) -> Opened {
        Opened {
            from: [7; 32],
            scope: scope.to_owned(),
            nonce: [0; 16],
            time_ms: NOW,
            body: body.to_vec(),
            answers: None,
            leaf: CertificateBody { agreement_key, ..Default::default() },
        }
    }

    fn channels() -> Channels {
        Channels { edge: b"edge".to_vec(), sample: b"sample".to_vec() }
    }

    #[test]
    fn a_device_that_may_view_is_wrapped_the_key_for_both_channels() {
        let identity = Identity::from_seed([1; 32]);
        let publisher = Sender { identity: &identity, chain: &[] };
        let key = StreamKey::from_bytes([2; 32]);
        let wrapped =
            wrap_for(&asked(scope::VIEW, GRANT_COMMAND.as_bytes(), vec![3; 32]), &publisher, &key, &channels(), NOW)
                .unwrap()
                .expect("granted");
        assert_eq!(wrapped.len(), 2, "one per channel: a device reads edges and samples or neither");
        assert_ne!(wrapped[0], wrapped[1], "each names its own channel");
    }

    #[test]
    fn anything_else_is_refused_rather_than_guessed_at() {
        let identity = Identity::from_seed([1; 32]);
        let publisher = Sender { identity: &identity, chain: &[] };
        let key = StreamKey::from_bytes([2; 32]);
        let refuse = |asked: Opened| wrap_for(&asked, &publisher, &key, &channels(), NOW).unwrap().unwrap_err();

        assert_eq!(refuse(asked(scope::VIEW, b"box.everything", vec![3; 32])), Refused::NotTheCommand);
        assert_eq!(refuse(asked(scope::VIEW, b"", vec![3; 32])), Refused::NotTheCommand, "and an empty body is not it");
        // The seal refuses a command whose sender does not hold the scope it names, so this is the case where a
        // sender holds `drive` and asked under it: nothing has established that it may READ the stream.
        assert_eq!(refuse(asked(scope::DRIVE, GRANT_COMMAND.as_bytes(), vec![3; 32])), Refused::WrongScope);
        assert_eq!(refuse(asked(scope::VIEW, GRANT_COMMAND.as_bytes(), vec![3; 31])), Refused::NoAgreementKey);
    }
}
