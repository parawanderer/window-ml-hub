//! A connector pairing the way an operator does it: keys on disk, a code and a fingerprint on the terminal, somebody
//! confirming it on a device that may pair, and the connector logging in with what it was given.
//!
//! The parts this cannot test are the two that are not code: that a person actually compares the fingerprint, and
//! that they refuse it when it differs. What it does test is that the fingerprint the terminal prints is the one the
//! other device computes, and that an answer naming anything but this connector is refused rather than stored.

use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpListener;
use wmlhub::registry::{OpenLimits, Registration, Registry};
use wmlhub_client::{Client, Config};
use wmlhub_connector::pair::{Offer, PairError};
use wmlhub_connector::state::{Keys, State};
use wmlhub_keys::pairing::{PairingCode, fingerprint_hex};
use wmlhub_keys::{CertSpec, Identity, issue, principal_id, scope};
use wmlhub_proto::prost::Message;
use wmlhub_proto::v1::{Certificate, PairedWith, PairingAnswer, PairingOffer, Role};
use wmlhub_seal::{AgreementKey, seal_pairing_answer};

const HUB: &str = "hub.test";
const CHANNEL_KEY: [u8; 32] = [33; 32];

fn dir(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("wmlbox-pairing-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

async fn start_hub(name: &str) -> String {
    let registry = Registry::open(dir(&format!("hub-{name}")), Registration::Open, OpenLimits::default()).unwrap();
    let config = wmlhub::Config {
        auth: wmlhub::Auth::Keys { hub_name: HUB.into(), registry: Arc::new(registry) },
        ..wmlhub::Config::default()
    };
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(wmlhub::serve(listener, config, 1));
    format!("ws://{addr}")
}

fn now_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64
}

/// The device the person confirms on: paired already, and allowed to pair others.
struct Phone {
    identity: Identity,
    chain: Vec<Certificate>,
}

impl Phone {
    fn new(root: &Identity) -> Self {
        let identity = Identity::from_seed([2; 32]);
        let agreement = AgreementKey::from_seed(&[3; 32]);
        let chain = vec![issue(
            root,
            &CertSpec {
                subject: identity.public(),
                agreement_key: agreement.public(),
                role: Role::Client,
                scopes: vec![scope::VIEW.into()],
                may_pair: true,
                not_before_ms: now_ms() - 3_600_000,
                not_after_ms: now_ms() + 3_600_000,
                label: "the phone".into(),
            },
        )];
        Self { identity, chain }
    }

    async fn connect(&self, url: &str, root: &Identity) -> Client {
        Client::connect(Config {
            url: url.to_owned(),
            hub_name: HUB.into(),
            identity: Identity::from_seed([2; 32]),
            agreement: AgreementKey::from_seed(&[3; 32]),
            chain: self.chain.clone(),
            account_root: root.public(),
            role: Role::Client,
            invite: Vec::new(),
        })
        .await
        .unwrap()
    }

    /// A certificate this phone issues, over whichever keys it is handed: the honest case passes the offered ones.
    fn issue_for(&self, subject: &Identity, agreement_key: [u8; 32]) -> Certificate {
        issue(
            &self.identity,
            &CertSpec {
                subject: subject.public(),
                agreement_key,
                role: Role::BoxConnector,
                scopes: Vec::new(),
                may_pair: false,
                not_before_ms: now_ms() - 1_000,
                not_after_ms: now_ms() + 1_800_000,
                label: "the gpu box".into(),
            },
        )
    }
}

/// The offer the hub is holding, once it is there. A connector leaves it a moment after the test asks for it, so
/// this is the only place a delay belongs: everywhere else a wait is a bug.
async fn offer_in_slot(client: &mut Client, code: &PairingCode) -> PairingOffer {
    for _ in 0..40 {
        if let Ok(bytes) = client.pairing_offered(&code.hash()).await {
            return PairingOffer::decode(bytes.as_slice()).expect("an offer");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("the offer never reached the hub");
}

#[tokio::test]
async fn a_connector_pairs_at_a_terminal_and_logs_in_with_what_it_was_given() {
    let url = start_hub("terminal").await;
    let root = Identity::from_seed([1; 32]);
    let phone = Phone::new(&root);
    let mut ph = phone.connect(&url, &root).await;

    let state = State::at(dir("terminal-box"));
    let keys = state.generate_keys().unwrap();
    let offer = Offer::new(&keys, "the gpu box", now_ms()).unwrap();
    let code = PairingCode::parse(offer.code()).expect("the code it printed is a code");
    let shown = offer.fingerprint();

    let confirm = async {
        // the person has typed the code; this is the screen they compare against the terminal's
        let offered = offer_in_slot(&mut ph, &code).await;
        let identity: [u8; 32] = offered.identity_key.as_slice().try_into().unwrap();
        let agreement: [u8; 32] = offered.agreement_key.as_slice().try_into().unwrap();
        assert_eq!(fingerprint_hex(&identity, &agreement), shown, "both screens show the same fingerprint");
        assert_eq!(offered.label, "the gpu box");
        assert_eq!(offered.role(), Role::BoxConnector, "it asked to be what it is");

        let paired = PairedWith {
            chain: vec![phone.issue_for(&keys.identity, agreement), phone.chain[0].clone()],
            account_root: root.public().to_vec(),
            channel_key: CHANNEL_KEY.to_vec(),
        };
        let sealed = seal_pairing_answer(&agreement, &paired).unwrap();
        ph.pairing_answer(&code.hash(), PairingAnswer { sealed }.encode_to_vec()).await.unwrap();
    };

    let mut left = offer.leave(&url).await.expect("the hub holds the offer");
    let (paired, ()) = tokio::join!(left.answer(Duration::from_secs(20), now_ms), confirm);
    let paired = paired.expect("the answer is for this connector and verifies");
    assert_eq!(paired.channel_key, CHANNEL_KEY.to_vec(), "and the account's channel key came with it");
    state.write_paired(&paired).unwrap();

    // what a restart does: read the state back, and log in with it
    let restarted = State::at(state.dir());
    let keys = restarted.keys().unwrap().expect("its keys");
    let stored = restarted.paired().unwrap().expect("what it was paired with");
    let client = Client::connect(Config {
        url: url.clone(),
        hub_name: HUB.into(),
        identity: keys.identity,
        agreement: keys.agreement,
        chain: stored.chain,
        account_root: root.public(),
        role: Role::BoxConnector,
        invite: Vec::new(),
    })
    .await
    .expect("a connector logs in with what pairing gave it");
    assert_eq!(client.account(), ph.account(), "it is on the account that paired it");
}

#[tokio::test]
async fn an_answer_naming_another_principal_is_refused_rather_than_stored() {
    let url = start_hub("substituted").await;
    let root = Identity::from_seed([1; 32]);
    let phone = Phone::new(&root);
    let mut ph = phone.connect(&url, &root).await;

    let state = State::at(dir("substituted-box"));
    let keys = state.generate_keys().unwrap();
    let offer = Offer::new(&keys, "the gpu box", now_ms()).unwrap();
    let code = PairingCode::parse(offer.code()).unwrap();

    let answer = async {
        let offered = offer_in_slot(&mut ph, &code).await;
        let agreement: [u8; 32] = offered.agreement_key.as_slice().try_into().unwrap();
        // what a hub that substituted the keys ends up doing: the certificate is for a principal it controls, and it
        // seals it to the key the connector actually offered so that it opens
        let someone_else = Identity::from_seed([99; 32]);
        let paired = PairedWith {
            chain: vec![phone.issue_for(&someone_else, agreement), phone.chain[0].clone()],
            account_root: root.public().to_vec(),
            channel_key: CHANNEL_KEY.to_vec(),
        };
        let sealed = seal_pairing_answer(&agreement, &paired).unwrap();
        ph.pairing_answer(&code.hash(), PairingAnswer { sealed }.encode_to_vec()).await.unwrap();
    };

    let mut left = offer.leave(&url).await.expect("the hub holds the offer");
    let (refused, ()) = tokio::join!(left.answer(Duration::from_secs(20), now_ms), answer);
    assert!(
        matches!(refused, Err(PairError::NotMine)),
        "a certificate for another principal is not this connector's: {refused:?}"
    );
    assert!(state.paired().unwrap().is_none(), "and nothing was written");
}

#[tokio::test]
async fn keys_are_the_connectors_own_and_a_pairing_never_replaces_them() {
    let state = State::at(dir("keys"));
    let keys = state.generate_keys().unwrap();
    let before = principal_id(&keys.identity.public());
    state
        .write_paired(&PairedWith { chain: Vec::new(), account_root: vec![7; 32], channel_key: CHANNEL_KEY.to_vec() })
        .unwrap();
    // pairing again with another account: the certificate is replaced, the principal is not
    state
        .write_paired(&PairedWith { chain: Vec::new(), account_root: vec![8; 32], channel_key: CHANNEL_KEY.to_vec() })
        .unwrap();
    let after: Keys = state.keys().unwrap().unwrap();
    assert_eq!(principal_id(&after.identity.public()), before, "whatever was granted to it stays granted to it");
    assert_eq!(state.paired().unwrap().unwrap().account_root, vec![8; 32]);
}
