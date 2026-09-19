//! The vectors a second implementation is checked against (`vectors/seal-v1.json`, docs/VECTORS.md).
//!
//! Everything here goes through the public API only, which is itself the check that a second implementation has
//! everything it needs from what this crate says out loud.
//!
//! The default test OPENS the checked-in vectors: if anything about the format changes, this fails, and regenerating
//! the file is then a deliberate act with a version bump rather than something that slips through.
//!
//! Regenerate: `cargo test -p wmlhub-seal --test vectors write_vectors -- --ignored`

use std::path::PathBuf;

use serde_json::{Value, json};
use wmlhub_keys::revocation::{certificate_hash, sign_revocations, verify_revocations};
use wmlhub_keys::{
    CertSpec, Identity, hello_transcript, hex, issue, principal_id, renew, scope, verify_chain, verify_hello,
};
use wmlhub_proto::prost::Message;
use wmlhub_proto::v1::{Certificate, RevocationList, Role};
use wmlhub_seal::{
    AgreementKey, ChannelKey, Receiver, Recipient, Sender, StreamKey, StreamReader, open_grant, seal_command,
    seal_frame, seal_result, wrap_key,
};

/// 2: every certificate carries a validity window, which the verifier now requires, so a file at version 1 fails
/// against this implementation rather than merely being old.
/// `issue`, which now refuses a spec every verifier would reject.
fn issue_ok(issuer: &Identity, spec: &CertSpec) -> Certificate {
    issue(issuer, spec).expect("a certificate this issuer may make")
}

const VERSION: u32 = 4;
const HUB: &str = "hub.test";
const TIME_MS: u64 = 1_800_000_000_000;
/// Fixed, so the vectors are the same story every time they are regenerated.
const ROOT_SEED: u8 = 11;
const RUNTIME_SEED: u8 = 22;
const PHONE_SEED: u8 = 33;
const CHALLENGE_NONCE: [u8; 32] = [44; 32];
const STREAM_KEY: [u8; 32] = [55; 32];
const CHANNEL_KEY: [u8; 32] = [66; 32];
/// The renewal cast: a laptop that may pair, and a phone the ROOT gave `approve` and the laptop keeps alive.
const LAPTOP_SEED: u8 = 77;
const APPROVER_SEED: u8 = 88;
/// The revocation cast: the one principal the root allowed to sign lists.
const REVOKER_SEED: u8 = 99;

fn path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../vectors/seal-v1.json")
}

fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len() % 2 == 0, "hex of odd length: {s}");
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex")).collect()
}

fn array<const N: usize>(s: &str) -> [u8; N] {
    unhex(s).try_into().unwrap_or_else(|_| panic!("expected {N} bytes"))
}

/// A principal built from a seed, exactly as the vectors describe it.
struct Who {
    identity: Identity,
    agreement_seed: [u8; 32],
    chain: Vec<Certificate>,
}

impl Who {
    fn new(root: &Identity, seed: u8, role: Role, scopes: &[&str]) -> Self {
        let identity = Identity::from_seed([seed; 32]);
        let agreement_seed = [seed.wrapping_add(1); 32];
        let chain = vec![issue_ok(
            root,
            &CertSpec {
                subject: identity.public(),
                agreement_key: AgreementKey::from_seed(&agreement_seed).public(),
                role,
                scopes: scopes.iter().map(|s| (*s).to_owned()).collect(),
                may_pair: false,
                may_revoke: false,
                not_before_ms: TIME_MS - 86_400_000,
                not_after_ms: TIME_MS + 86_400_000,
                label: String::new(),
            },
        )];
        Self { identity, agreement_seed, chain }
    }

    fn id(&self) -> [u8; 32] {
        principal_id(&self.identity.public())
    }

    fn sender(&self) -> Sender<'_> {
        Sender { identity: &self.identity, chain: &self.chain }
    }

    fn recipient(&self) -> Recipient {
        Recipient { principal: self.id(), agreement_key: AgreementKey::from_seed(&self.agreement_seed).public() }
    }

    fn receiver(&self, root: &Identity) -> Receiver {
        Receiver::new(&self.identity.public(), AgreementKey::from_seed(&self.agreement_seed), root.public())
    }

    fn described(&self, seed: u8) -> Value {
        json!({
            "identity_seed": hex(&[seed; 32]),
            "identity_public": hex(&self.identity.public()),
            "principal_id": hex(&self.id()),
            "agreement_seed": hex(&self.agreement_seed),
            "agreement_public": hex(&AgreementKey::from_seed(&self.agreement_seed).public()),
            "certificate": hex(&self.chain[0].encode_to_vec()),
        })
    }
}

fn cast() -> (Identity, Who, Who) {
    let root = Identity::from_seed([ROOT_SEED; 32]);
    let runtime = Who::new(&root, RUNTIME_SEED, Role::Runtime, &[]);
    let phone = Who::new(&root, PHONE_SEED, Role::Client, &[scope::VIEW, scope::DRIVE]);
    (root, runtime, phone)
}

/// A renewal, as the vectors describe it: the laptop's own certificate, the EXPIRED one the root issued the
/// approver, and the laptop's renewal of it. The point is that `approve` is [`NEVER_DELEGABLE`], so the laptop could
/// not have issued the middle one and may re-issue it anyway.
fn renewal(root: &Identity) -> (Certificate, Certificate, Certificate) {
    let laptop = Identity::from_seed([LAPTOP_SEED; 32]);
    let approver = Identity::from_seed([APPROVER_SEED; 32]);
    let laptop_cert = issue_ok(
        root,
        &CertSpec {
            subject: laptop.public(),
            agreement_key: AgreementKey::from_seed(&[LAPTOP_SEED.wrapping_add(1); 32]).public(),
            role: Role::Runtime,
            scopes: vec![scope::VIEW.to_owned(), scope::DRIVE.to_owned()],
            may_pair: true,
            may_revoke: false,
            not_before_ms: TIME_MS - 86_400_000,
            not_after_ms: TIME_MS + 86_400_000,
            label: "laptop".into(),
        },
    );
    // Expired at TIME_MS, deliberately: a renewal exists for a certificate that ran out, and a verifier must not
    // check the predecessor's own window.
    let before = issue_ok(
        root,
        &CertSpec {
            subject: approver.public(),
            agreement_key: AgreementKey::from_seed(&[APPROVER_SEED.wrapping_add(1); 32]).public(),
            role: Role::Client,
            scopes: vec![scope::APPROVE.to_owned()],
            may_pair: false,
            may_revoke: false,
            not_before_ms: TIME_MS - 86_400_000,
            not_after_ms: TIME_MS - 3_600_000,
            label: "phone".into(),
        },
    );
    let renewed = renew(&laptop, &before, TIME_MS - 1_000, TIME_MS + 3_600_000).expect("a renewal of the root's own");
    (laptop_cert, before, renewed)
}

/// A revocation list, as the vectors describe it: the revoker's certificate, and a list it signed revoking the phone
/// entirely and one certificate of the approver. Ed25519 is deterministic, so a second implementation signing the
/// same body with the same key must produce these exact bytes.
fn revocation(root: &Identity, phone: &Who, before: &Certificate) -> RevocationList {
    let revoker = Identity::from_seed([REVOKER_SEED; 32]);
    let chain = vec![issue_ok(
        root,
        &CertSpec {
            subject: revoker.public(),
            agreement_key: AgreementKey::from_seed(&[REVOKER_SEED.wrapping_add(1); 32]).public(),
            role: Role::Runtime,
            scopes: vec![],
            may_pair: false,
            may_revoke: true,
            not_before_ms: TIME_MS - 86_400_000,
            not_after_ms: TIME_MS + 86_400_000,
            label: "the runtime that may revoke".into(),
        },
    )];
    let account = wmlhub_keys::account_id(&root.public());
    sign_revocations(&revoker, &chain, account, TIME_MS, &[phone.id()], &[certificate_hash(before)])
}

#[test]
fn the_vectors_open_with_this_implementation() {
    let raw = std::fs::read_to_string(path()).expect("vectors/seal-v1.json is checked in");
    let v: Value = serde_json::from_str(&raw).expect("valid json");
    assert_eq!(v["version"], VERSION);
    let (root, runtime, phone) = cast();

    // the parties are who the file says they are
    assert_eq!(v["account"]["root_public"], hex(&root.public()));
    assert_eq!(v["principals"]["runtime"]["principal_id"], hex(&runtime.id()));
    assert_eq!(v["principals"]["phone"]["certificate"], hex(&phone.chain[0].encode_to_vec()));

    // The revocation list, read back from the file, and rebuilt: signing is deterministic, so the bytes must match.
    let (_, before, _) = renewal(&root);
    let list =
        RevocationList::decode(unhex(v["revocation"]["list"].as_str().expect("hex")).as_slice()).expect("a list");
    assert_eq!(list.encode_to_vec(), revocation(&root, &phone, &before).encode_to_vec(), "signing is deterministic");
    let at = v["revocation"]["verify_at_ms"].as_u64().expect("a time");
    let revoked = verify_revocations(&root.public(), &list, at, None).expect("the list verifies");
    assert!(revoked.revokes(&phone.chain), "it names the phone");
    assert!(revoked.revokes(std::slice::from_ref(&before)), "and the approver's old certificate");
    assert!(!revoked.revokes(&runtime.chain), "and nothing else");

    // The renewal, read back from the file rather than rebuilt, so the checked-in bytes are what verifies.
    let cert = |key: &str| {
        Certificate::decode(unhex(v["renewal"][key].as_str().expect("hex")).as_slice()).expect("a certificate")
    };
    let (delegate, renewed) = (cert("delegate"), cert("renewed"));
    let at = v["renewal"]["verify_at_ms"].as_u64().expect("a time");
    let out = verify_chain(&root.public(), &[renewed, delegate], at).expect("the renewal verifies");
    assert_eq!(out.leaf.scopes, vec![scope::APPROVE.to_owned()], "a scope only the root may grant");
    assert!(
        verify_chain(&root.public(), std::slice::from_ref(&cert("before")), at).is_err(),
        "and the certificate it renews is expired, which is the whole point of renewing it"
    );

    // a hello signature over the transcript the file records
    let transcript = hello_transcript(
        HUB,
        &CHALLENGE_NONCE,
        &phone.id(),
        Role::Client,
        &array::<32>(v["hello"]["account_id"].as_str().unwrap()),
    );
    assert_eq!(hex(&transcript), v["hello"]["transcript"].as_str().unwrap(), "the transcript is built as documented");
    verify_hello(&phone.identity.public(), &transcript, &unhex(v["hello"]["signature"].as_str().unwrap()))
        .expect("the hello signature verifies");

    // the command opens for the runtime, and its result opens for the phone
    let mut runtime_receiver = runtime.receiver(&root);
    let command = unhex(v["command"]["sealed"].as_str().unwrap());
    let opened = runtime_receiver.open(&phone.id(), &command, TIME_MS).expect("the command opens");
    assert_eq!(hex(&opened.body), v["command"]["body"].as_str().unwrap());
    assert_eq!(opened.scope, v["command"]["scope"].as_str().unwrap());
    assert_eq!(hex(&opened.nonce), v["command"]["nonce"].as_str().unwrap());

    let mut phone_receiver = phone.receiver(&root);
    let result = unhex(v["result"]["sealed"].as_str().unwrap());
    let answered = phone_receiver.open(&runtime.id(), &result, TIME_MS).expect("the result opens");
    assert_eq!(hex(&answered.body), v["result"]["body"].as_str().unwrap());
    assert_eq!(hex(&answered.answers.expect("a result answers a command")), v["command"]["nonce"]);

    // the grant opens, and the frame opens under the key it carried
    let grant_bytes = unhex(v["grant"]["sealed"].as_str().unwrap());
    let grant = open_grant(&mut phone_receiver, &runtime.id(), &grant_bytes, TIME_MS).expect("the grant opens");
    assert_eq!(hex(&grant.key), v["grant"]["key"].as_str().unwrap());
    assert_eq!(hex(&grant.key_id), v["grant"]["key_id"].as_str().unwrap());
    assert_eq!(hex(&grant.channel), v["grant"]["channel"].as_str().unwrap());

    let mut reader = StreamReader::new(&grant);
    let published = reader.open(&unhex(v["frame"]["frame"].as_str().unwrap())).expect("the frame opens");
    assert_eq!(hex(&published.batch), v["frame"]["batch"].as_str().unwrap());
    assert_eq!(published.counter, v["frame"]["counter"].as_u64().unwrap());

    // channel names are a pure function of the key, the purpose and the subject
    let channel_key = ChannelKey::from_bytes(CHANNEL_KEY);
    for entry in v["channels"].as_array().expect("channels") {
        let purpose = entry["purpose"].as_str().unwrap();
        let subject = unhex(entry["subject"].as_str().unwrap());
        assert_eq!(hex(&channel_key.channel(purpose, &subject)), entry["channel"].as_str().unwrap(), "{purpose}");
    }

    // the stream key id is derived from the key
    assert_eq!(hex(&StreamKey::from_bytes(STREAM_KEY).id()), v["grant"]["key_id"].as_str().unwrap());
}

#[test]
#[ignore]
fn write_vectors() {
    let (root, runtime, phone) = cast();
    let (laptop_cert, before, renewed) = renewal(&root);
    let account = wmlhub_keys::account_id(&root.public());
    let transcript = hello_transcript(HUB, &CHALLENGE_NONCE, &phone.id(), Role::Client, &account);

    let (command, nonce) =
        seal_command(&phone.sender(), &runtime.recipient(), scope::DRIVE, b"session.send hello", TIME_MS).unwrap();
    let result = seal_result(&runtime.sender(), &phone.recipient(), &nonce, b"sent", TIME_MS).unwrap();

    let channel_key = ChannelKey::from_bytes(CHANNEL_KEY);
    let channel = channel_key.channel("events", b"5f3a9c21");
    let key = StreamKey::from_bytes(STREAM_KEY);
    let grant = wrap_key(&runtime.sender(), &phone.recipient(), &channel, &key, 1, TIME_MS).unwrap();
    let frame = seal_frame(&runtime.sender(), &channel, &key, 1, b"the night's events").unwrap();

    let channels: Vec<Value> = [("events", &b"5f3a9c21"[..]), ("keys", &b"5f3a9c21"[..]), ("events", &b"box-1"[..])]
        .into_iter()
        .map(|(purpose, subject)| {
            json!({
                "purpose": purpose,
                "subject": hex(subject),
                "channel": hex(&channel_key.channel(purpose, subject)),
            })
        })
        .collect();

    let vectors = json!({
        "version": VERSION,
        "what": "Vectors for a second implementation of wmlhub-seal (docs/VECTORS.md). Hex throughout.",
        "suite": {
            "hpke": "RFC 9180 base mode, DHKEM(X25519, HKDF-SHA256) 0x0020, HKDF-SHA256 0x0001, AES-256-GCM 0x0002",
            "signatures": "Ed25519 over label || 0x00 || bytes",
            "labels": {
                "certificate": "wmlhub/cert/v1",
                "hello": "wmlhub/hello/v1",
                "command": "wmlhub/command/v1",
                "grant": "wmlhub/grant/v1",
                "stream": "wmlhub/stream/v1",
                "seal_info": "wmlhub/seal/v1",
                "grant_info": "wmlhub/keygrant/v1",
                "stream_key_id": "wmlhub/streamkey-id/v1",
                "channel": "wmlhub/channel/v1",
            },
            "time_ms": TIME_MS,
        },
        "account": {
            "root_seed": hex(&[ROOT_SEED; 32]),
            "root_public": hex(&root.public()),
            "account_id": hex(&account),
        },
        "principals": {
            "runtime": runtime.described(RUNTIME_SEED),
            "phone": phone.described(PHONE_SEED),
        },
        "revocation": {
            "what": "A revocation list. Verify it under the account root at verify_at_ms with no list held: it names \
    the phone entirely and the approver's expired certificate by hash. Signing the same body with the revoker's key must \
    reproduce `list` byte for byte, since Ed25519 is deterministic.",
            "revoker_seed": hex(&[REVOKER_SEED; 32]),
            "list": hex(&revocation(&root, &phone, &before).encode_to_vec()),
            "verify_at_ms": TIME_MS,
            "principals": [hex(&phone.id())],
            "certificates": [hex(&certificate_hash(&before))],
        },
        "renewal": {
            "what": "A delegate re-issuing a scope it could never have granted. Verify [renewed, delegate] under the account root at verify_at_ms: it holds `approve`, which only the root may grant, and the predecessor is expired.",
            "delegate_seed": hex(&[LAPTOP_SEED; 32]),
            "subject_seed": hex(&[APPROVER_SEED; 32]),
            "delegate": hex(&laptop_cert.encode_to_vec()),
            "before": hex(&before.encode_to_vec()),
            "renewed": hex(&renewed.encode_to_vec()),
            "verify_at_ms": TIME_MS,
            "scopes": [scope::APPROVE],
        },
        "hello": {
            "hub": HUB,
            "challenge_nonce": hex(&CHALLENGE_NONCE),
            "principal": "phone",
            "role": Role::Client as i32,
            "account_id": hex(&account),
            "transcript": hex(&transcript),
            "signature": hex(&wmlhub_keys::sign_hello(&phone.identity, &transcript)),
        },
        "command": {
            "from": "phone",
            "to": "runtime",
            "scope": scope::DRIVE,
            "body": hex(b"session.send hello"),
            "nonce": hex(&nonce),
            "time_ms": TIME_MS,
            "info": hex(&info(b"wmlhub/seal/v1\0", &phone.id(), &runtime.id())),
            "sealed": hex(&command),
        },
        "result": {
            "from": "runtime",
            "to": "phone",
            "answers": hex(&nonce),
            "body": hex(b"sent"),
            "time_ms": TIME_MS,
            "sealed": hex(&result),
        },
        "grant": {
            "from": "runtime",
            "to": "phone",
            "channel": hex(&channel),
            "key": hex(&STREAM_KEY),
            "key_id": hex(&key.id()),
            "from_counter": 1,
            "info": hex(&info(b"wmlhub/keygrant/v1\0", &runtime.id(), &phone.id())),
            "sealed": hex(&grant),
        },
        "frame": {
            "publisher": "runtime",
            "channel": hex(&channel),
            "counter": 1,
            "batch": hex(b"the night's events"),
            "frame": hex(&frame),
        },
        "channel_key": hex(&CHANNEL_KEY),
        "channels": channels,
    });
    std::fs::create_dir_all(path().parent().unwrap()).unwrap();
    std::fs::write(path(), format!("{}\n", serde_json::to_string_pretty(&vectors).unwrap())).unwrap();
    eprintln!("wrote {}", path().display());
}

/// The HPKE info, built the way the documentation says to, so the file records what an implementer must construct.
fn info(label: &[u8], from: &[u8; 32], to: &[u8; 32]) -> Vec<u8> {
    let mut info = label.to_vec();
    info.extend_from_slice(from);
    info.extend_from_slice(to);
    info
}
