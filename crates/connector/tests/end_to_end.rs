//! A box, a hub and a phone, with only the box faked: the connector reads a real HTTP stream of real frames and
//! publishes them through a real hub, and a subscriber decrypts what comes out.
//!
//! What is actually being checked is the rule the design turns on: every frame reaches the subscriber BYTE FOR BYTE,
//! on the channel its kind belongs to, and nothing an edge carries is ever coalesced or dropped.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use prost::Message;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, watch};
use wmlhub::registry::{OpenLimits, Registration, Registry};
use wmlhub_box::schema::{EventFrame, InfoResponse};
use wmlhub_client::{Client, Config, Event};
use wmlhub_connector::grant::GRANT_COMMAND;
use wmlhub_connector::revoked::Revocations;
use wmlhub_connector::run::PENDING_FRAMES;
use wmlhub_connector::serve::{Revoking, Serving};
use wmlhub_connector::state::State;
use wmlhub_connector::{Channels, Events, Relay, Relayed, Target};
use wmlhub_keys::{CertSpec, Identity, issue, principal_id, scope};
use wmlhub_proto::v1::{Certificate, Kind, Role};
use wmlhub_seal::{AgreementKey, ChannelKey, Recipient, Sender, StreamKey, StreamReader, wrap_key};

/// `issue`, which now refuses a spec every verifier would reject.
fn issue_ok(issuer: &Identity, spec: &CertSpec) -> Certificate {
    issue(issuer, spec).expect("a certificate this issuer may make")
}

const HUB: &str = "hub.test";

/// One frame the fake box sends, and where it must end up.
struct Expected {
    kind: &'static str,
    info: bool,
    lands: Relayed,
}

fn script() -> Vec<Expected> {
    vec![
        Expected { kind: "hello", info: false, lands: Relayed::Consumed },
        Expected { kind: "sample", info: false, lands: Relayed::Sample { counter: 1, coalesce: b"s" } },
        Expected { kind: "estimate", info: false, lands: Relayed::Edge { counter: 1 } },
        Expected { kind: "load.start", info: false, lands: Relayed::Edge { counter: 2 } },
        // a sample carrying info may never be superseded: info is sent only when it changed
        Expected { kind: "sample", info: true, lands: Relayed::Sample { counter: 2, coalesce: b"" } },
        Expected { kind: "heartbeat", info: false, lands: Relayed::Sample { counter: 3, coalesce: b"h" } },
        Expected { kind: "load.complete", info: false, lands: Relayed::Edge { counter: 3 } },
        // a kind this connector has never heard of is relayed losslessly, not dropped
        Expected { kind: "something.the.fork.added", info: false, lands: Relayed::Edge { counter: 4 } },
    ]
}

fn frame_bytes(n: usize, e: &Expected) -> Vec<u8> {
    EventFrame {
        v: Some(1),
        kind: Some(e.kind.to_owned()),
        t: Some(n as i64 * 100),
        at_ms: Some(1_800_000_000_000 + n as i64 * 100),
        r#box: "mlbox".into(),
        info: e.info.then(InfoResponse::default),
        ..Default::default()
    }
    .encode_to_vec()
}

/// A box that serves one chunked `/api/events` response, in awkward pieces.
async fn fake_box(frames: Vec<Vec<u8>>) -> (String, tokio::task::JoinHandle<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/api/events", listener.local_addr().unwrap());
    let handle = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut request = vec![0u8; 1024];
        let read = socket.read(&mut request).await.unwrap();
        let request = String::from_utf8_lossy(&request[..read]).into_owned();

        let head = "HTTP/1.1 200 OK\r\nContent-Type: application/protobuf; delimited=varint\r\n\
                    Transfer-Encoding: chunked\r\n\r\n";
        socket.write_all(head.as_bytes()).await.unwrap();

        // every frame, length-prefixed, then cut into chunks that fall wherever they like
        let mut body = Vec::new();
        for frame in &frames {
            wmlhub_frame::write_frame(frame, wmlhub_frame::MAX_FRAME_BYTES, &mut body).unwrap();
        }
        for piece in body.chunks(7) {
            socket.write_all(format!("{:x}\r\n", piece.len()).as_bytes()).await.unwrap();
            socket.write_all(piece).await.unwrap();
            socket.write_all(b"\r\n").await.unwrap();
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        socket.write_all(b"0\r\n\r\n").await.unwrap();
        request
    });
    (url, handle)
}

fn state_dir(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("wmlhub-conn-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

async fn start_hub(name: &str) -> String {
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

struct Device {
    seed: [u8; 32],
    identity: Identity,
    agreement_seed: [u8; 32],
    chain: Vec<Certificate>,
    role: Role,
}

impl Device {
    fn new(root: &Identity, seed: u8, role: Role, scopes: &[&str]) -> Self {
        Self::issued(root, seed, role, scopes, false)
    }

    /// The runtime the root allowed to sign the account's revocation lists.
    fn revoker(root: &Identity, seed: u8) -> Self {
        Self::issued(root, seed, Role::Runtime, &[], true)
    }

    fn issued(root: &Identity, seed: u8, role: Role, scopes: &[&str], may_revoke: bool) -> Self {
        let identity_seed = [seed; 32];
        let identity = Identity::from_seed(identity_seed);
        let agreement_seed = [seed.wrapping_add(90); 32];
        let chain = vec![issue_ok(
            root,
            &CertSpec {
                subject: identity.public(),
                agreement_key: AgreementKey::from_seed(&agreement_seed).public(),
                role,
                scopes: scopes.iter().map(|s| (*s).to_owned()).collect(),
                may_pair: false,
                may_revoke,
                not_before_ms: now_ms() - 3_600_000,
                not_after_ms: now_ms() + 3_600_000,
                label: String::new(),
            },
        )];
        Self { seed: identity_seed, identity, agreement_seed, chain, role }
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

    fn config(&self, url: &str, root: &Identity) -> Config {
        Config {
            url: url.to_owned(),
            hub_name: HUB.into(),
            identity: Identity::from_seed(self.seed),
            agreement: AgreementKey::from_seed(&self.agreement_seed),
            chain: self.chain.clone(),
            account_root: root.public(),
            role: self.role,
            invite: Vec::new(),
        }
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64
}

/// A connector that has never heard of a revoker: grants as it did before revocation existed.
fn nobody_revoked<'a>(root: &Identity, channel_key: &'a ChannelKey, state: &'a State) -> Revoking<'a> {
    Revoking { channel_key, revocations: Revocations::new(root.public(), None, BTreeSet::new(), None), state }
}

#[tokio::test]
async fn a_boxs_frames_reach_a_subscriber_byte_for_byte_on_the_right_channels() {
    let script = script();
    let frames: Vec<Vec<u8>> = script.iter().enumerate().map(|(n, e)| frame_bytes(n, e)).collect();
    let (box_url, box_task) = fake_box(frames.clone()).await;
    let hub_url = start_hub("e2e").await;

    let root = Identity::from_seed([5; 32]);
    let connector = Device::new(&root, 6, Role::BoxConnector, &[]);
    let phone = Device::new(&root, 7, Role::Client, &[scope::VIEW]);

    let mut conn_client = Client::connect(connector.config(&hub_url, &root)).await.unwrap();
    let mut phone_client = Client::connect(phone.config(&hub_url, &root)).await.unwrap();

    let channel_key = ChannelKey::from_bytes([8; 32]);
    let channels = Channels {
        edge: channel_key.channel("box.edges", b"mlbox").to_vec(),
        sample: channel_key.channel("box.samples", b"mlbox").to_vec(),
    };
    let key = StreamKey::from_bytes([9; 32]);

    // the phone subscribes, and is granted the stream key over the hub
    phone_client.subscribe(&connector.id(), &channels.edge, None).await.unwrap();
    phone_client.subscribe(&connector.id(), &channels.sample, None).await.unwrap();
    for channel in [&channels.edge, &channels.sample] {
        let wrapped = wrap_key(&connector.sender(), &phone.recipient(), channel, &key, 1, now_ms()).unwrap();
        conn_client.direct(phone.id(), Kind::Command, wrapped).await.unwrap();
    }

    // the connector reads the box and republishes every frame
    let target = Target::parse(&box_url).unwrap();
    let mut events = Events::open(&target, Some(60_000)).await.unwrap();
    let mut relay = Relay::new(connector.sender(), key, channels.clone());
    let mut landed = Vec::new();
    for _ in 0..script.len() {
        let frame = events.next_frame().await.unwrap();
        landed.push(relay.frame(&mut conn_client, &frame).await.unwrap());
    }
    assert_eq!(landed, script.iter().map(|e| e.lands.clone()).collect::<Vec<_>>(), "each frame's channel and counter");

    let request = box_task.await.unwrap();
    assert!(request.contains("Accept: application/protobuf"), "the connector asked for the binary stream");
    assert!(request.contains("?since=60000"), "and for the backfill it may have missed");

    // the phone reads both streams and gets the box's own bytes back
    let mut readers = Vec::new();
    let mut edges = Vec::new();
    let mut samples = Vec::new();
    for _ in 0..40 {
        let event = tokio::time::timeout(Duration::from_secs(5), phone_client.next()).await.unwrap().unwrap();
        match event {
            Event::Unopened { sender, payload, .. } => {
                let grant = phone_client.open_grant(&sender, &payload).unwrap();
                readers.push(StreamReader::new(&grant));
            }
            Event::Published { stream, payload, .. } => {
                let reader = readers
                    .iter_mut()
                    .find(|r| r.channel() == stream.channel)
                    .expect("a grant for this stream arrived first");
                let opened = reader.open(&payload).unwrap();
                if stream.channel == channels.edge { &mut edges } else { &mut samples }.push(opened.batch);
            }
            _ => {}
        }
        if edges.len() == 4 && samples.len() == 3 {
            break;
        }
    }

    let expected_edges: Vec<Vec<u8>> = script
        .iter()
        .enumerate()
        .filter(|(_, e)| matches!(e.lands, Relayed::Edge { .. }))
        .map(|(n, _)| frames[n].clone())
        .collect();
    let expected_samples: Vec<Vec<u8>> = script
        .iter()
        .enumerate()
        .filter(|(_, e)| matches!(e.lands, Relayed::Sample { .. }))
        .map(|(n, _)| frames[n].clone())
        .collect();
    assert_eq!(edges, expected_edges, "every edge, in order, as the box wrote it");
    assert_eq!(samples, expected_samples, "every sample, as the box wrote it");
}

/// A box that serves one response per connection, from a script, and records what was asked for each time.
async fn fake_box_sequence(responses: Vec<Vec<Vec<u8>>>) -> (String, Arc<std::sync::Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/api/events", listener.local_addr().unwrap());
    let asked = Arc::new(std::sync::Mutex::new(Vec::new()));
    let recorded = asked.clone();
    tokio::spawn(async move {
        for frames in responses {
            let Ok((mut socket, _)) = listener.accept().await else { return };
            let mut request = vec![0u8; 1024];
            let read = socket.read(&mut request).await.unwrap();
            recorded.lock().unwrap().push(String::from_utf8_lossy(&request[..read]).into_owned());

            let head = "HTTP/1.1 200 OK\r\nContent-Type: application/protobuf; delimited=varint\r\n\
                        Transfer-Encoding: chunked\r\n\r\n";
            socket.write_all(head.as_bytes()).await.unwrap();
            let mut body = Vec::new();
            for frame in &frames {
                wmlhub_frame::write_frame(frame, wmlhub_frame::MAX_FRAME_BYTES, &mut body).unwrap();
            }
            socket.write_all(format!("{:x}\r\n", body.len()).as_bytes()).await.unwrap();
            socket.write_all(&body).await.unwrap();
            socket.write_all(b"\r\n").await.unwrap();
            // and then the box goes away mid-stream, which is what a restart or a dropped network looks like
            drop(socket);
        }
    });
    (url, asked)
}

/// The next event, or a panic naming what we were waiting for rather than hanging the suite.
async fn next(client: &mut Client, what: &str) -> Event {
    match tokio::time::timeout(Duration::from_secs(5), client.next()).await {
        Ok(Ok(event)) => event,
        Ok(Err(e)) => panic!("waiting for {what}: {e:?}"),
        Err(_) => panic!("waiting for {what}: the hub went quiet"),
    }
}

/// Everything the box side has handed over, published. The loop does this itself; a test drives it a step at a time
/// so that each pass can be asserted on.
async fn drain(serving: &mut Serving<'_>, client: &mut Client, frames: &mut mpsc::Receiver<Vec<u8>>) {
    while let Ok(frame) = frames.try_recv() {
        serving.publish(client, &frame).await.expect("published");
    }
}

#[tokio::test]
async fn a_reconnect_asks_for_what_it_missed_and_publishes_nothing_twice() {
    let edge = Expected { kind: "gen.end", info: false, lands: Relayed::Edge { counter: 0 } };
    let frames: Vec<Vec<u8>> = (0..5).map(|n| frame_bytes(n, &edge)).collect();
    // the second connection replays the last two and adds two more, which is what `since` buys
    let (box_url, asked) = fake_box_sequence(vec![frames[..3].to_vec(), frames[1..].to_vec(), Vec::new()]).await;
    let hub_url = start_hub("reconnect").await;

    let root = Identity::from_seed([15; 32]);
    let connector = Device::new(&root, 16, Role::BoxConnector, &[]);
    let mut client = Client::connect(connector.config(&hub_url, &root)).await.unwrap();

    let channel_key = ChannelKey::from_bytes([18; 32]);
    let channels = Channels {
        edge: channel_key.channel("box.edges", b"mlbox").to_vec(),
        sample: channel_key.channel("box.samples", b"mlbox").to_vec(),
    };
    let key = StreamKey::from_bytes([19; 32]);
    let state = State::at(state_dir("reconnect-state"));

    let (tx, mut rx) = mpsc::channel(PENDING_FRAMES);
    let (published_tx, published_rx) = watch::channel(None);
    let mut conn = wmlhub_connector::Connector::new(Target::parse(&box_url).unwrap(), tx, published_rx);
    let mut serving =
        Serving::new(connector.sender(), key, channels, nobody_revoked(&root, &channel_key, &state), published_tx);

    let first = conn.pass(&now_ms).await.unwrap();
    assert_eq!(first.forwarded, 3, "everything the first connection carried");
    drain(&mut serving, &mut client, &mut rx).await;
    assert_eq!(serving.counts().published, 3);

    let second = conn.pass(&now_ms).await.unwrap();
    assert_eq!(second.forwarded, 4, "the box replayed two: this side hands over what it reads, duplicates and all");
    drain(&mut serving, &mut client, &mut rx).await;
    assert_eq!(serving.counts().published, 5, "only what was new");
    assert_eq!(serving.counts().duplicates, 2, "the replayed frames are recognised, not republished");

    let asked = asked.lock().unwrap().clone();
    assert!(!asked[0].contains("since="), "the first connection has nothing to resume from");
    assert!(asked[1].contains("?since="), "the second asks for the gap: {}", asked[1].lines().next().unwrap());
}

#[tokio::test]
async fn a_device_that_may_view_asks_for_the_key_and_reads_the_stream() {
    let script = script();
    let frames: Vec<Vec<u8>> = script.iter().enumerate().map(|(n, e)| frame_bytes(n, e)).collect();
    let edges = script.iter().filter(|e| matches!(e.lands, Relayed::Edge { .. })).count();
    let (box_url, _box_task) = fake_box(frames).await;
    let hub_url = start_hub("granted").await;

    let root = Identity::from_seed([25; 32]);
    let connector = Device::new(&root, 26, Role::BoxConnector, &[]);
    let phone = Device::new(&root, 27, Role::Client, &[scope::VIEW]);
    let mut client = Client::connect(connector.config(&hub_url, &root)).await.unwrap();
    let mut phone_client = Client::connect(phone.config(&hub_url, &root)).await.unwrap();

    // What a device knows without being told: the connector's principal, from the paired-devices list, and the
    // account's channel key, from its own pairing. That is enough to name the channels.
    let channel_key = ChannelKey::from_bytes([28; 32]);
    let channels = Channels {
        edge: channel_key.channel("box.edges", &connector.id()).to_vec(),
        sample: channel_key.channel("box.samples", &connector.id()).to_vec(),
    };
    phone_client.subscribe(&connector.id(), &channels.edge, None).await.unwrap();
    phone_client.subscribe(&connector.id(), &channels.sample, None).await.unwrap();
    // and it has no key: the connector chose one, and nothing has handed it over
    phone_client.command(&connector.recipient(), scope::VIEW, GRANT_COMMAND.as_bytes()).await.unwrap();

    let key = StreamKey::generate().unwrap();
    let state = State::at(state_dir("granted-state"));
    let (tx, mut rx) = mpsc::channel(PENDING_FRAMES);
    let (published_tx, published_rx) = watch::channel(None);
    let mut conn = wmlhub_connector::Connector::new(Target::parse(&box_url).unwrap(), tx, published_rx);
    let revoking = nobody_revoked(&root, &channel_key, &state);
    let mut serving = Serving::new(connector.sender(), key, channels.clone(), revoking, published_tx);

    let reading = async {
        let mut readers: Vec<StreamReader> = Vec::new();
        let (mut waiting, mut read) = (Vec::new(), 0usize);
        for _ in 0..60 {
            match next(&mut phone_client, "the key, then the stream").await {
                // the grant: a key wrapped to this device, which arrives as an envelope no command opener wants
                Event::Unopened { sender, payload, .. } => {
                    let grant = phone_client.open_grant(&sender, &payload).expect("a grant for a stream");
                    readers.push(StreamReader::new(&grant));
                    // whatever arrived before the key did is readable now
                    waiting.retain(|(channel, payload): &(Vec<u8>, Vec<u8>)| {
                        match readers.iter_mut().find(|r| r.channel() == channel) {
                            Some(reader) => {
                                reader.open(payload).expect("the box's own bytes");
                                read += 1;
                                false
                            }
                            None => true,
                        }
                    });
                }
                Event::Published { stream, payload, .. } => {
                    match readers.iter_mut().find(|r| r.channel() == stream.channel) {
                        Some(reader) => {
                            reader.open(&payload).expect("the box's own bytes");
                            read += 1;
                        }
                        None => waiting.push((stream.channel, payload.to_vec())),
                    }
                }
                _ => {}
            }
            if read >= edges {
                return readers.len();
            }
        }
        panic!("the phone read {read} of {edges} edges with {} grants", readers.len());
    };

    let granted = tokio::select! {
        granted = reading => granted,
        _ = conn.run(&now_ms) => unreachable!("the box side stopped"),
        e = serving.run(&mut client, &mut rx, &now_ms) => unreachable!("the connector stopped: {e:?}"),
    };
    assert_eq!(granted, 2, "one grant per channel, both from asking once");
    assert_eq!(serving.counts().granted, 1, "and the connector answered exactly one command");
}

/// What a device got back for asking the connector for its key.
#[derive(Debug, PartialEq)]
enum Answer {
    /// both wrapped keys arrived
    Granted,
    /// a result, naming why not
    Refused(Vec<u8>),
}

async fn ask(device: &mut Client, connector: &Device) -> Answer {
    device.command(&connector.recipient(), scope::VIEW, GRANT_COMMAND.as_bytes()).await.unwrap();
    let mut keys = 0;
    loop {
        match next(device, "a grant or a refusal").await {
            Event::Unopened { .. } => {
                keys += 1;
                if keys == 2 {
                    return Answer::Granted;
                }
            }
            Event::Result(result) => return Answer::Refused(result.body),
            _ => {}
        }
    }
}

#[tokio::test]
async fn a_revoked_device_is_refused_the_rest_read_on_and_a_week_of_silence_stops_new_grants() {
    let hub_url = start_hub("revoked").await;
    let root = Identity::from_seed([35; 32]);
    let connector = Device::new(&root, 36, Role::BoxConnector, &[]);
    let revoker = Device::revoker(&root, 37);
    let phone = Device::new(&root, 38, Role::Client, &[scope::VIEW]);
    let tablet = Device::new(&root, 39, Role::Client, &[scope::VIEW]);

    let mut client = Client::connect(connector.config(&hub_url, &root)).await.unwrap();
    // The connector has never heard of a revoker. It learns of this one from presence, verifies the chain itself, and
    // follows its list from then on.
    let mut revoker_client = Client::connect(revoker.config(&hub_url, &root)).await.unwrap();
    let mut phone_client = Client::connect(phone.config(&hub_url, &root)).await.unwrap();
    let mut tablet_client = Client::connect(tablet.config(&hub_url, &root)).await.unwrap();

    let channel_key = ChannelKey::from_bytes([40; 32]);
    let channels = Channels {
        edge: channel_key.channel("box.edges", &connector.id()).to_vec(),
        sample: channel_key.channel("box.samples", &connector.id()).to_vec(),
    };
    let state = State::at(state_dir("revoked-state"));
    // The connector's clock, which this test moves a week on without waiting one. The hub and the devices keep real
    // time, so only the connector's own decisions see the jump.
    let clock = Arc::new(std::sync::atomic::AtomicU64::new(now_ms()));
    let connector_now = {
        let clock = clock.clone();
        move || clock.load(std::sync::atomic::Ordering::Relaxed)
    };
    let (_frames_tx, mut frames) = mpsc::channel(PENDING_FRAMES);
    let (published_tx, _published_rx) = watch::channel(None);
    let revoking = nobody_revoked(&root, &channel_key, &state);
    let mut serving =
        Serving::new(connector.sender(), StreamKey::generate().unwrap(), channels, revoking, published_tx);

    let script = async {
        assert_eq!(ask(&mut phone_client, &connector).await, Answer::Granted, "before any list");

        let list = wmlhub_keys::revocation::sign_revocations(
            &revoker.identity,
            &revoker.chain,
            wmlhub_keys::account_id(&root.public()),
            now_ms(),
            &[phone.id()],
            &[],
        );
        let revocations = channel_key.channel("revocations", &revoker.id());
        revoker_client.publish(&revocations, Kind::SessionEvents, list.encode_to_vec().into()).await.unwrap();

        // The list and the phone's next ask reach the connector by different routes, so the phone asks until the
        // list has landed. What it must never do is stay granted.
        let mut refused = None;
        for _ in 0..50 {
            match ask(&mut phone_client, &connector).await {
                Answer::Refused(why) => {
                    refused = Some(why);
                    break;
                }
                Answer::Granted => tokio::time::sleep(Duration::from_millis(50)).await,
            }
        }
        assert_eq!(refused.as_deref(), Some(&b"revoked"[..]), "the phone is told, rather than met with silence");
        assert_eq!(ask(&mut tablet_client, &connector).await, Answer::Granted, "and the tablet reads on");

        // A week and a day with nothing from the revoker: nobody new is granted, and the refusal says since when.
        let listed = clock.load(std::sync::atomic::Ordering::Relaxed);
        clock.store(
            listed + wmlhub_connector::revoked::FRESHNESS_FLOOR_MS + 86_400_000,
            std::sync::atomic::Ordering::Relaxed,
        );
        match ask(&mut tablet_client, &connector).await {
            Answer::Refused(why) => assert!(why.starts_with(b"stale "), "{}", String::from_utf8_lossy(&why)),
            Answer::Granted => panic!("granted on a list more than a week old"),
        }
    };
    tokio::select! {
        _ = script => {}
        e = serving.run(&mut client, &mut frames, &connector_now) => panic!("the connector stopped: {e:?}"),
    }
    let counts = serving.counts();
    assert_eq!((counts.lists, counts.rotations), (1, 1), "one list, naming somebody new, so one rotation");
    assert!(counts.revoked >= 2, "the phone once, and the tablet after a week of silence");

    // and it is written down: a restart knows the phone is revoked without hearing the list again
    let kept = state.revocations(&root.public()).unwrap();
    assert!(kept.held().is_some_and(|held| held.revokes(&phone.chain)));
}
