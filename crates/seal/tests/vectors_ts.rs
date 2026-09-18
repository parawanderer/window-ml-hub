//! The other direction: what window-ml's TypeScript implementation produced, opened by this one.
//!
//! `tests/vectors.rs` proves that side can open what this one produces. Neither HPKE nor Ed25519 lets randomness be
//! replayed, so the reverse needs vectors generated over there: `vectors/seal-ts-v1.json`, written by window-ml's
//! `scripts/gen-hub-vectors.mjs`. Together the two files are what "these implementations interoperate" means here.
//!
//! The parties are the ones `vectors/seal-v1.json` describes, from the same seeds, so this rebuilds the cast from the
//! same constants and only opens what the file carries.

use std::path::PathBuf;

use serde_json::Value;
use wmlhub_keys::{CertSpec, Identity, hex, issue, principal_id, scope};
use wmlhub_proto::v1::Role;
use wmlhub_seal::{AgreementKey, ChannelKey, Receiver, StreamReader, open_grant};

const TIME_MS: u64 = 1_800_000_000_000;
const ROOT_SEED: u8 = 11;
const RUNTIME_SEED: u8 = 22;
const PHONE_SEED: u8 = 33;
const CHANNEL_KEY: [u8; 32] = [66; 32];

fn path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../vectors/seal-ts-v1.json")
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex")).collect()
}

/// A principal of the shared cast, from the seeds both sides use.
struct Who {
    identity: Identity,
    agreement_seed: [u8; 32],
}

impl Who {
    fn new(root: &Identity, seed: u8, role: Role, scopes: &[&str]) -> Self {
        let identity = Identity::from_seed([seed; 32]);
        let agreement_seed = [seed.wrapping_add(1); 32];
        // issued so the parties match the other side's, though only the keys are needed to open what it sealed
        let _cert = issue(
            root,
            &CertSpec {
                subject: identity.public(),
                agreement_key: AgreementKey::from_seed(&agreement_seed).public(),
                role,
                scopes: scopes.iter().map(|s| (*s).to_owned()).collect(),
                may_pair: false,
                not_before_ms: TIME_MS - 86_400_000,
                not_after_ms: TIME_MS + 86_400_000,
                label: String::new(),
            },
        );
        Self { identity, agreement_seed }
    }

    fn id(&self) -> [u8; 32] {
        principal_id(&self.identity.public())
    }

    fn receiver(&self, root: &Identity) -> Receiver {
        Receiver::new(&self.identity.public(), AgreementKey::from_seed(&self.agreement_seed), root.public())
    }
}

#[test]
fn what_the_typescript_implementation_sealed_opens_here() {
    let raw = std::fs::read_to_string(path()).expect("vectors/seal-ts-v1.json is checked in");
    let v: Value = serde_json::from_str(&raw).expect("valid json");
    assert_eq!(v["version"], 1);

    let root = Identity::from_seed([ROOT_SEED; 32]);
    let runtime = Who::new(&root, RUNTIME_SEED, Role::Runtime, &[]);
    let phone = Who::new(&root, PHONE_SEED, Role::Client, &[scope::VIEW, scope::DRIVE]);

    // a command the browser sealed to the runtime
    let mut runtime_receiver = runtime.receiver(&root);
    let sealed = unhex(v["command"]["sealed"].as_str().unwrap());
    let opened = runtime_receiver.open(&phone.id(), &sealed, TIME_MS).expect("the command opens");
    assert_eq!(hex(&opened.body), v["command"]["body"].as_str().unwrap());
    assert_eq!(opened.scope, v["command"]["scope"].as_str().unwrap());
    assert_eq!(hex(&opened.nonce), v["command"]["nonce"].as_str().unwrap());

    // and its result, sealed back
    let mut phone_receiver = phone.receiver(&root);
    let result = unhex(v["result"]["sealed"].as_str().unwrap());
    let answered = phone_receiver.open(&runtime.id(), &result, TIME_MS).expect("the result opens");
    assert_eq!(hex(&answered.body), v["result"]["body"].as_str().unwrap());
    assert_eq!(hex(&answered.answers.expect("a result answers a command")), v["command"]["nonce"]);

    // a stream key it wrapped, and a frame under that key
    let grant_bytes = unhex(v["grant"]["sealed"].as_str().unwrap());
    let grant = open_grant(&mut phone_receiver, &runtime.id(), &grant_bytes, TIME_MS).expect("the grant opens");
    assert_eq!(hex(&grant.key), v["grant"]["key"].as_str().unwrap());
    assert_eq!(hex(&grant.channel), v["grant"]["channel"].as_str().unwrap());
    let mut reader = StreamReader::new(&grant);
    let published = reader.open(&unhex(v["frame"]["frame"].as_str().unwrap())).expect("the frame opens");
    assert_eq!(hex(&published.batch), v["frame"]["batch"].as_str().unwrap());
    assert_eq!(published.counter, v["frame"]["counter"].as_u64().unwrap());

    // and the channel names it computed
    let channel_key = ChannelKey::from_bytes(CHANNEL_KEY);
    for entry in v["channels"].as_array().expect("channels") {
        let purpose = entry["purpose"].as_str().unwrap();
        let subject = unhex(entry["subject"].as_str().unwrap());
        assert_eq!(hex(&channel_key.channel(purpose, &subject)), entry["channel"].as_str().unwrap(), "{purpose}");
    }
    assert_eq!(hex(&grant.channel), hex(&channel_key.channel("events", b"5f3a9c21")), "the frame's channel");
}
