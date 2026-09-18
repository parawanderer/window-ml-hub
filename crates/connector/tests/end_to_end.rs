//! A box, a hub and a phone, with only the box faked: the connector reads a real HTTP stream of real frames and
//! publishes them through a real hub, and a subscriber decrypts what comes out.
//!
//! What is actually being checked is the rule the design turns on: every frame reaches the subscriber BYTE FOR BYTE,
//! on the channel its kind belongs to, and nothing an edge carries is ever coalesced or dropped.

use std::sync::Arc;
use std::time::Duration;

use prost::Message;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use wmlhub::registry::{OpenLimits, Registration, Registry};
use wmlhub_box::schema::{EventFrame, InfoResponse};
use wmlhub_client::{Client, Config, Event};
use wmlhub_connector::{Channels, Events, Relay, Relayed, Target};
use wmlhub_keys::{CertSpec, Identity, issue, principal_id, scope};
use wmlhub_proto::v1::{Certificate, Kind, Role};
use wmlhub_seal::{AgreementKey, ChannelKey, Recipient, Sender, StreamKey, StreamReader, wrap_key};

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
        let identity_seed = [seed; 32];
        let identity = Identity::from_seed(identity_seed);
        let agreement_seed = [seed.wrapping_add(90); 32];
        let chain = vec![issue(
            root,
            &CertSpec {
                subject: identity.public(),
                agreement_key: AgreementKey::from_seed(&agreement_seed).public(),
                role,
                scopes: scopes.iter().map(|s| (*s).to_owned()).collect(),
                may_pair: false,
                not_before_ms: 0,
                not_after_ms: 0,
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
    let mut relay = Relay::new(connector.sender(), &key, channels.clone());
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
    let relay = Relay::new(connector.sender(), &key, channels);
    let mut conn = wmlhub_connector::Connector::new(Target::parse(&box_url).unwrap(), relay);

    let first = conn.pass(&mut client, &now_ms).await.unwrap();
    assert_eq!(first.published, 3, "everything the first connection carried");

    let second = conn.pass(&mut client, &now_ms).await.unwrap();
    assert_eq!(second.published, 2, "only what was new");
    assert_eq!(second.duplicates, 2, "the replayed frames are recognised, not republished");

    let asked = asked.lock().unwrap().clone();
    assert!(!asked[0].contains("since="), "the first connection has nothing to resume from");
    assert!(asked[1].contains("?since="), "the second asks for the gap: {}", asked[1].lines().next().unwrap());
}
