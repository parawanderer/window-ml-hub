//! A real account, over a real hub, with nothing faked: two clients log in with certificate chains, exchange a sealed
//! command and its result, and read an encrypted stream whose key arrived over the hub. If the client and the hub ever
//! disagree about the protocol or the transcript, this is what says so.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpListener;
use wmlhub::registry::{OpenLimits, Registration, Registry};
use wmlhub_client::{Client, Config, Event, StreamKey, StreamReader, seal_frame, wrap_key};
use wmlhub_keys::{CertSpec, Identity, PublicKey, issue, principal_id, scope};
use wmlhub_proto::v1::{Certificate, Kind, Role};
use wmlhub_seal::{AgreementKey, Recipient, Sender};

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
        let identity_seed = [seed; 32];
        let identity = Identity::from_seed(identity_seed);
        let agreement_seed = [seed.wrapping_add(80); 32];
        let cert = issue(
            root,
            &CertSpec {
                subject: identity.public(),
                agreement_key: AgreementKey::from_seed(&agreement_seed).public(),
                role,
                scopes: scopes.iter().map(|s| (*s).to_owned()).collect(),
                may_pair: false,
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
