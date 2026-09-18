//! A real account, over a real hub, with nothing faked: two clients log in with certificate chains, exchange a sealed
//! command and its result, and read an encrypted stream whose key arrived over the hub. If the client and the hub ever
//! disagree about the protocol or the transcript, this is what says so.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpListener;
use wmlhub::registry::{OpenLimits, Registration, Registry};
use wmlhub_client::{Client, Config, Event, Pairing, StreamKey, StreamReader, seal_frame, wrap_key};
use wmlhub_keys::{CertSpec, Identity, PublicKey, issue, principal_id, scope};
use wmlhub_proto::v1::{Certificate, Kind, Role};
use wmlhub_seal::{AgreementKey, Recipient, Sender};

/// `issue`, which now refuses a spec every verifier would reject.
fn issue_ok(issuer: &Identity, spec: &CertSpec) -> Certificate {
    issue(issuer, spec).expect("a certificate this issuer may make")
}

const HUB: &str = "hub.test";
const EVENTS: &[u8] = b"events-channel";
const KEYS: &[u8] = b"keys-channel";

fn state_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("wmlhub-client-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

async fn start(name: &str) -> String {
    let registry = Registry::open(state_dir(name), Registration::Open, OpenLimits::default()).unwrap();
    let config = wmlhub::Config {
        auth: wmlhub::Auth::Keys { hub_name: HUB.into(), registry: Arc::new(registry) },
        ..wmlhub::Config::default()
    };
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(wmlhub::serve(listener, config, 1));
    format!("ws://{addr}")
}

/// One principal's keys and the certificate the root issued it.
struct Device {
    seed: [u8; 32],
    identity: Identity,
    agreement_seed: [u8; 32],
    chain: Vec<Certificate>,
    role: Role,
}

impl Device {
    fn new(root: &Identity, seed: u8, role: Role, scopes: &[&str]) -> Self {
        Self::issued_by(root, seed, role, scopes, false)
    }

    /// A device the root allowed to pair others, which is what makes losing one phone survivable.
    fn pairer(root: &Identity, seed: u8) -> Self {
        Self::issued_by(root, seed, Role::Client, &[scope::VIEW], true)
    }

    fn issued_by(root: &Identity, seed: u8, role: Role, scopes: &[&str], may_pair: bool) -> Self {
        let identity_seed = [seed; 32];
        let identity = Identity::from_seed(identity_seed);
        let agreement_seed = [seed.wrapping_add(80); 32];
        let cert = issue_ok(
            root,
            &CertSpec {
                subject: identity.public(),
                agreement_key: AgreementKey::from_seed(&agreement_seed).public(),
                role,
                scopes: scopes.iter().map(|s| (*s).to_owned()).collect(),
                may_pair,
                not_before_ms: now_ms() - 3_600_000,
                not_after_ms: now_ms() + 3_600_000,
                label: String::new(),
            },
        );
        Self { seed: identity_seed, identity, agreement_seed, chain: vec![cert], role }
    }

    fn id(&self) -> [u8; 32] {
        principal_id(&self.identity.public())
    }

    fn recipient(&self) -> Recipient {
        Recipient { principal: self.id(), agreement_key: AgreementKey::from_seed(&self.agreement_seed).public() }
    }

    fn sender(&self) -> Sender<'_> {
        Sender { identity: &self.identity, chain: &self.chain }
    }

    fn config(&self, url: &str, root: PublicKey, hub_name: &str) -> Config {
        Config {
            url: url.to_owned(),
            hub_name: hub_name.to_owned(),
            identity: Identity::from_seed(self.seed),
            agreement: AgreementKey::from_seed(&self.agreement_seed),
            chain: self.chain.clone(),
            account_root: root,
            role: self.role,
            invite: Vec::new(),
        }
    }
}

/// The next event, or a panic naming what we were waiting for rather than hanging the suite.
async fn next(client: &mut Client, what: &str) -> Event {
    match tokio::time::timeout(Duration::from_secs(5), client.next()).await {
        Ok(Ok(event)) => event,
        Ok(Err(e)) => panic!("waiting for {what}: {e:?}"),
        Err(_) => panic!("waiting for {what}: the hub went quiet"),
    }
}

/// Read events until one matches, so presence and backfill markers never make a test flaky.
async fn until<T>(client: &mut Client, what: &str, mut pick: impl FnMut(Event) -> Option<T>) -> T {
    for _ in 0..20 {
        let event = next(client, what).await;
        if let Event::Error(e) = &event {
            panic!("waiting for {what}: hub said {:?} {}", e.code(), e.message);
        }
        if let Some(found) = pick(event) {
            return found;
        }
    }
    panic!("waiting for {what}: twenty events went by without it");
}

#[tokio::test]
async fn an_account_drives_a_runtime_and_reads_its_stream_through_the_hub() {
    let url = start("e2e").await;
    let root = Identity::from_seed([1; 32]);
    let runtime = Device::new(&root, 2, Role::Runtime, &[]);
    let phone = Device::new(&root, 3, Role::Client, &[scope::VIEW, scope::DRIVE]);

    let mut rt = Client::connect(runtime.config(&url, root.public(), HUB)).await.unwrap();
    let mut ph = Client::connect(phone.config(&url, root.public(), HUB)).await.unwrap();
    assert_eq!(rt.principal(), runtime.id());
    assert_eq!(ph.account(), rt.account(), "one account, two principals");

    // The phone asks for the runtime's stream and for the channel its keys come on.
    ph.subscribe(&runtime.id(), KEYS, None).await.unwrap();
    ph.subscribe(&runtime.id(), EVENTS, None).await.unwrap();
    until(&mut ph, "the events backfill", |e| match e {
        Event::Backfilled(b) if b.stream.as_ref().is_some_and(|s| s.channel == EVENTS) => Some(()),
        _ => None,
    })
    .await;

    // The runtime grants the phone the stream key, then publishes an encrypted batch.
    let key = StreamKey::generate().unwrap();
    let wrapped = wrap_key(&runtime.sender(), &phone.recipient(), EVENTS, &key, 1, now_ms()).unwrap();
    rt.publish(KEYS, Kind::SessionEvents, wrapped.into()).await.unwrap();
    let frame = seal_frame(&runtime.sender(), EVENTS, &key, 1, b"the night's events").unwrap();
    rt.publish(EVENTS, Kind::SessionEvents, frame.into()).await.unwrap();

    let grant = until(&mut ph, "the wrapped key", |e| match e {
        Event::Published { stream, payload, sender, .. } if stream.channel == KEYS => Some((sender, payload)),
        _ => None,
    })
    .await;
    let grant = ph.open_grant(&grant.0, &grant.1).unwrap();
    let mut reader = StreamReader::new(&grant);

    let published = until(&mut ph, "the published batch", |e| match e {
        Event::Published { stream, payload, .. } if stream.channel == EVENTS => Some(payload),
        _ => None,
    })
    .await;
    let opened = reader.open(&published).unwrap();
    assert_eq!(opened.counter, 1);
    assert_eq!(opened.skipped, 0);
    assert_eq!(opened.batch, b"the night's events");

    // The phone drives the runtime, and the runtime answers.
    let nonce = ph.command(&runtime.recipient(), scope::DRIVE, b"session.send hello").await.unwrap();
    let command = until(&mut rt, "the command", |e| match e {
        Event::Command(opened) => Some(opened),
        _ => None,
    })
    .await;
    assert_eq!(command.from, phone.id());
    assert_eq!(command.scope, scope::DRIVE);
    assert_eq!(command.body, b"session.send hello");
    assert_eq!(command.nonce, nonce);

    rt.result(&phone.recipient(), &command.nonce, b"sent").await.unwrap();
    let result = until(&mut ph, "the result", |e| match e {
        Event::Result(opened) => Some(opened),
        _ => None,
    })
    .await;
    assert_eq!(result.answers, Some(nonce));
    assert_eq!(result.body, b"sent");
    assert_eq!(result.from, runtime.id());
}

#[tokio::test]
async fn a_hub_that_names_itself_something_else_is_refused_before_anything_is_signed() {
    let url = start("wrong-hub").await;
    let root = Identity::from_seed([1; 32]);
    let phone = Device::new(&root, 3, Role::Client, &[scope::VIEW]);
    let error = Client::connect(phone.config(&url, root.public(), "another.hub")).await.unwrap_err();
    assert!(matches!(&error, wmlhub_client::ClientError::WrongHub { offered, .. } if offered == HUB), "{error:?}");
}

#[tokio::test]
async fn a_certificate_from_another_root_is_refused_by_the_hub() {
    let url = start("other-root").await;
    let (root, other) = (Identity::from_seed([1; 32]), Identity::from_seed([9; 32]));
    let phone = Device::new(&other, 3, Role::Client, &[scope::VIEW]);
    // the chain is signed by `other`, but the hello claims the account of `root`
    let error = Client::connect(phone.config(&url, root.public(), HUB)).await.unwrap_err();
    assert!(
        matches!(&error, wmlhub_client::ClientError::Refused(e) if e.message == "hello did not verify"),
        "{error:?}"
    );
}

fn now_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64
}

/// What the pairing device shows the person, from the offer the hub was holding.
fn offered_fingerprint(offer: &[u8]) -> (String, wmlhub_proto::v1::PairingOffer) {
    use wmlhub_proto::prost::Message;
    let offer = wmlhub_proto::v1::PairingOffer::decode(offer).expect("an offer");
    let identity: [u8; 32] = offer.identity_key.as_slice().try_into().expect("32 bytes");
    let agreement: [u8; 32] = offer.agreement_key.as_slice().try_into().expect("32 bytes");
    (wmlhub_keys::pairing::fingerprint_hex(&identity, &agreement), offer)
}

#[tokio::test]
async fn a_new_device_pairs_through_the_hub_and_then_logs_in_with_what_it_was_given() {
    use wmlhub_proto::prost::Message;
    let url = start("pairing").await;
    let root = Identity::from_seed([1; 32]);
    // the device that can issue certificates is already paired, and is logged in
    let phone = Device::new(&root, 3, Role::Client, &[scope::VIEW, scope::DRIVE]);
    let mut ph = Client::connect(phone.config(&url, root.public(), HUB)).await.unwrap();

    // the new device: keys, a code, and nothing else
    let new_identity = Identity::from_seed([42; 32]);
    let new_agreement = AgreementKey::from_seed(&[43; 32]);
    let code = wmlhub_keys::pairing::PairingCode::generate().unwrap();
    let offer = wmlhub_proto::v1::PairingOffer {
        identity_key: new_identity.public().to_vec(),
        agreement_key: new_agreement.public().to_vec(),
        role: Role::Runtime as i32,
        label: "the laptop".into(),
        offered_at_ms: now_ms(),
    }
    .encode_to_vec();
    let mut pairing = Pairing::offer(&url, &code.hash(), offer).await.unwrap();

    // the person types the code into the phone, which fetches the offer and shows its fingerprint
    let typed = wmlhub_keys::pairing::PairingCode::parse(&code.as_str().to_lowercase()).unwrap();
    let fetched = ph.pairing_offered(&typed.hash()).await.unwrap();
    let (shown, offered) = offered_fingerprint(&fetched);
    assert_eq!(offered.label, "the laptop");
    assert_eq!(
        shown,
        wmlhub_keys::pairing::fingerprint_hex(&new_identity.public(), &new_agreement.public()),
        "what the phone shows is what the new device shows"
    );

    // the person confirms, so the phone issues a certificate and seals it to the offered key
    let certificate = issue_ok(
        &root,
        &CertSpec {
            subject: new_identity.public(),
            agreement_key: new_agreement.public(),
            role: Role::Runtime,
            scopes: Vec::new(),
            may_pair: false,
            not_before_ms: now_ms() - 1000,
            not_after_ms: now_ms() + 3_600_000,
            label: offered.label.clone(),
        },
    );
    // sealed to the key the offer carried, because it also hands over the account's channel key
    let channel_key = [77u8; 32];
    let paired_with = wmlhub_proto::v1::PairedWith {
        chain: vec![certificate],
        account_root: root.public().to_vec(),
        channel_key: channel_key.to_vec(),
    };
    let offered_agreement: [u8; 32] = offered.agreement_key.as_slice().try_into().unwrap();
    let sealed = wmlhub_seal::seal_pairing_answer(&offered_agreement, &paired_with).unwrap();
    let answer = wmlhub_proto::v1::PairingAnswer { sealed }.encode_to_vec();
    ph.pairing_answer(&typed.hash(), answer).await.unwrap();

    // the new device opens it with the key it offered, and logs in with what was inside
    let got = pairing.answer().await.unwrap();
    let got = wmlhub_proto::v1::PairingAnswer::decode(got.as_slice()).unwrap();
    let opened = wmlhub_seal::open_pairing_answer(&AgreementKey::from_seed(&[43; 32]), &got.sealed).unwrap();
    assert_eq!(opened.account_root, root.public().to_vec());
    assert_eq!(opened.channel_key, channel_key.to_vec(), "and the account's channel key came with it");
    assert_eq!(opened.chain.len(), 1, "the root issued it, so the chain is one certificate");

    let paired = Client::connect(Config {
        url: url.clone(),
        hub_name: HUB.into(),
        identity: Identity::from_seed([42; 32]),
        agreement: AgreementKey::from_seed(&[43; 32]),
        chain: opened.chain,
        account_root: root.public(),
        role: Role::Runtime,
        invite: Vec::new(),
    })
    .await
    .unwrap();
    assert_eq!(paired.account(), ph.account(), "it is on the account that paired it");

    // and the two can now talk
    ph.subscribe(&paired.principal(), b"events", None).await.unwrap();
    until(&mut ph, "the backfill", |e| matches!(e, Event::Backfilled(_)).then_some(())).await;
}

#[tokio::test]
async fn a_device_the_root_allowed_to_pair_hands_over_its_own_certificate_too() {
    use wmlhub_proto::prost::Message;
    let url = start("pairing-delegate").await;
    let root = Identity::from_seed([11; 32]);
    // the root is not here: a phone it allowed to pair is, which is the case losing a phone survives
    let delegate = Device::pairer(&root, 12);
    let mut ph = Client::connect(delegate.config(&url, root.public(), HUB)).await.unwrap();

    let new_identity = Identity::from_seed([13; 32]);
    let new_agreement = AgreementKey::from_seed(&[14; 32]);
    let code = wmlhub_keys::pairing::PairingCode::generate().unwrap();
    let offer = wmlhub_proto::v1::PairingOffer {
        identity_key: new_identity.public().to_vec(),
        agreement_key: new_agreement.public().to_vec(),
        role: Role::BoxConnector as i32,
        label: "the gpu box".into(),
        offered_at_ms: now_ms(),
    }
    .encode_to_vec();
    let mut pairing = Pairing::offer(&url, &code.hash(), offer).await.unwrap();

    ph.pairing_offered(&code.hash()).await.unwrap();
    let certificate = issue(
        &delegate.identity,
        &CertSpec {
            subject: new_identity.public(),
            agreement_key: new_agreement.public(),
            role: Role::BoxConnector,
            scopes: Vec::new(),
            may_pair: false,
            not_before_ms: now_ms() - 1000,
            // inside the delegate's own window: a certificate may not outlive the one that issued it
            not_after_ms: now_ms() + 1_800_000,
            label: "the gpu box".into(),
        },
    );
    // the delegate's own certificate goes with it, or the new device holds a chain that stops at a key it has no
    // reason to trust
    let paired_with = wmlhub_proto::v1::PairedWith {
        chain: vec![certificate, delegate.chain[0].clone()],
        account_root: root.public().to_vec(),
        channel_key: [15u8; 32].to_vec(),
    };
    let sealed = wmlhub_seal::seal_pairing_answer(&new_agreement.public(), &paired_with).unwrap();
    ph.pairing_answer(&code.hash(), wmlhub_proto::v1::PairingAnswer { sealed }.encode_to_vec()).await.unwrap();

    let got = wmlhub_proto::v1::PairingAnswer::decode(pairing.answer().await.unwrap().as_slice()).unwrap();
    let opened = wmlhub_seal::open_pairing_answer(&AgreementKey::from_seed(&[14; 32]), &got.sealed).unwrap();
    assert_eq!(opened.chain.len(), 2, "the leaf, and the certificate of the device that issued it");

    let paired = Client::connect(Config {
        url: url.clone(),
        hub_name: HUB.into(),
        identity: Identity::from_seed([13; 32]),
        agreement: AgreementKey::from_seed(&[14; 32]),
        chain: opened.chain,
        account_root: root.public(),
        role: Role::BoxConnector,
        invite: Vec::new(),
    })
    .await
    .expect("a chain through a delegate verifies at the hub");
    assert_eq!(paired.account(), ph.account(), "it is on the account the delegate belongs to");
}

#[tokio::test]
async fn a_pairing_code_cannot_be_taken_over_and_only_the_first_answer_is_kept() {
    let url = start("pairing-contested").await;
    let root = Identity::from_seed([1; 32]);
    let phone = Device::new(&root, 3, Role::Client, &[scope::VIEW]);
    let mut ph = Client::connect(phone.config(&url, root.public(), HUB)).await.unwrap();

    let code = wmlhub_keys::pairing::PairingCode::generate().unwrap();
    let offer = |label: &str| {
        use wmlhub_proto::prost::Message;
        wmlhub_proto::v1::PairingOffer {
            identity_key: vec![1; 32],
            agreement_key: vec![2; 32],
            role: Role::Client as i32,
            label: label.into(),
            offered_at_ms: now_ms(),
        }
        .encode_to_vec()
    };
    let _held = Pairing::offer(&url, &code.hash(), offer("mine")).await.unwrap();
    // a second device offering under the same code is refused: two devices on one slot is how a hub would pair itself
    assert!(Pairing::offer(&url, &code.hash(), offer("theirs")).await.is_err());

    ph.pairing_answer(&code.hash(), b"first".to_vec()).await.unwrap();
    assert!(ph.pairing_answer(&code.hash(), b"second".to_vec()).await.is_err(), "only the first answer is kept");

    // and a code nobody offered is simply unavailable
    let unknown = wmlhub_keys::pairing::PairingCode::generate().unwrap();
    assert!(ph.pairing_offered(&unknown.hash()).await.is_err());
}
