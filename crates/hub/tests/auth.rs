//! The authenticated hub end to end: real websocket clients with real keys and certificate chains, against both
//! registration modes. Every refusal case builds exactly one defect, because an authentication check that lets a
//! forged hello through looks identical to one that works until somebody forges one.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};
use wmlhub::registry::{OpenLimits, Registration, Registry};
use wmlhub_keys::{CertSpec, Identity, account_id, hello_transcript, issue, principal_id, sign_hello};
use wmlhub_proto::v1::{self, Certificate, Envelope, Frame, Kind, Role, envelope::To, error::Code, frame::Body};
use wmlhub_proto::{decode_frames, encode_frames};

type Ws = WebSocketStream<MaybeTlsStream<TcpStream>>;
const MAX: usize = 1 << 20;
const HUB: &str = "hub.test";

fn state_dir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("wmlhub-auth-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    d
}

async fn start(dir: &PathBuf, mode: Registration, open: OpenLimits) -> String {
    let registry = Registry::open(dir, mode, open).unwrap();
    let config = wmlhub::Config {
        auth: wmlhub::Auth::Keys { hub_name: HUB.into(), registry: Arc::new(registry) },
        ..wmlhub::Config::default()
    };
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(wmlhub::serve(listener, config, 1));
    format!("ws://{addr}")
}

/// A device of an account: its identity, its chain to the root, and its role.
struct Device {
    key: Identity,
    chain: Vec<Certificate>,
    role: Role,
}

fn device(root: &Identity, seed: u8, role: Role) -> Device {
    let key = Identity::from_seed([seed; 32]);
    let spec = CertSpec {
        subject: key.public(),
        agreement_key: [5; 32],
        role,
        scopes: vec![wmlhub_keys::scope::VIEW.into(), wmlhub_keys::scope::DRIVE.into()],
        may_pair: false,
        not_before_ms: 0,
        not_after_ms: 0,
        label: format!("device {seed}"),
    };
    Device { chain: vec![issue(root, &spec)], key, role }
}

/// What a hello may be tampered with, one field at a time.
#[derive(Default)]
struct Tamper {
    sign_for_hub: Option<&'static str>,
    use_nonce: Option<Vec<u8>>,
    claim_principal: Option<Vec<u8>>,
    claim_role: Option<Role>,
    claim_root: Option<[u8; 32]>,
}

async fn recv(ws: &mut Ws) -> Option<Vec<Frame>> {
    loop {
        match tokio::time::timeout(Duration::from_secs(5), ws.next()).await.expect("hub went quiet") {
            Some(Ok(Message::Binary(b))) => return Some(decode_frames(&b, MAX).unwrap()),
            Some(Ok(Message::Ping(_) | Message::Pong(_))) => continue,
            _ => return None,
        }
    }
}

async fn expect(ws: &mut Ws, pred: impl Fn(&Body) -> bool) -> Body {
    loop {
        for f in recv(ws).await.expect("socket closed while waiting") {
            if let Some(body) = f.body.filter(|b| pred(b)) {
                return body;
            }
        }
    }
}

/// Connect, answer the challenge as `dev` of the account `root`, and return the socket with the hub's answer
/// (`Welcome` or `Error`) and the nonce that was signed.
async fn login(url: &str, root: &Identity, dev: &Device, invite: &[u8], tamper: Tamper) -> (Ws, Body, Vec<u8>) {
    let mut ws = tokio_tungstenite::connect_async(url).await.unwrap().0;
    let Body::Challenge(challenge) = expect(&mut ws, |b| matches!(b, Body::Challenge(_))).await else { unreachable!() };
    assert_eq!(challenge.hub, HUB);

    // A forger holds its OWN device key, so it signs exactly what it claims: the claim has to be caught by binding
    // it to the certificate, not by the signature failing to match.
    let principal = tamper.claim_principal.unwrap_or(principal_id(&dev.key.public()).to_vec());
    let role = tamper.claim_role.unwrap_or(dev.role);
    let account = account_id(&tamper.claim_root.unwrap_or(root.public()));
    let nonce = tamper.use_nonce.clone().unwrap_or(challenge.nonce.clone());
    let transcript = hello_transcript(tamper.sign_for_hub.unwrap_or(HUB), &nonce, &principal, role, &account);
    let hello = v1::Hello {
        protocol: 1,
        principal,
        role: role as i32,
        account_root: tamper.claim_root.unwrap_or(root.public()).to_vec(),
        chain: dev.chain.clone(),
        signature: sign_hello(&dev.key, &transcript),
        invite: invite.to_vec(),
        ..Default::default()
    };
    ws.send(Message::binary(encode_frames(&[Frame { body: Some(Body::Hello(hello)) }], MAX).unwrap())).await.unwrap();
    let answer = expect(&mut ws, |b| matches!(b, Body::Welcome(_) | Body::Error(_))).await;
    (ws, answer, challenge.nonce)
}

fn welcomed(answer: &Body) -> bool {
    matches!(answer, Body::Welcome(_))
}

fn refused(answer: &Body, code: Code) -> bool {
    matches!(answer, Body::Error(e) if e.code() == code)
}

/// Refused by verification itself, not by something that happens to share its code (a duplicate principal is also
/// `UNAUTHENTICATED`).
fn did_not_verify(answer: &Body) -> bool {
    matches!(answer, Body::Error(e) if e.code() == Code::Unauthenticated && e.message == "hello did not verify")
}

// ------------------------------ invite mode (the default) ------------------------------

#[tokio::test]
async fn invite_mode_refuses_a_new_account_without_an_invite() {
    let dir = state_dir("invite-none");
    let url = start(&dir, Registration::Invite, OpenLimits::default()).await;
    let root = Identity::from_seed([1; 32]);
    let (_, answer, _) = login(&url, &root, &device(&root, 10, Role::Client), b"", Tamper::default()).await;
    assert!(refused(&answer, Code::Unauthenticated));
}

#[tokio::test]
async fn an_invite_registers_one_account_whose_other_devices_then_need_none() {
    let dir = state_dir("invite-flow");
    let url = start(&dir, Registration::Invite, OpenLimits::default()).await;
    let token = Registry::create_invite(&dir, Duration::from_secs(3600), now_ms()).unwrap();

    let root = Identity::from_seed([1; 32]);
    let (_, answer, _) =
        login(&url, &root, &device(&root, 10, Role::Client), token.as_bytes(), Tamper::default()).await;
    assert!(welcomed(&answer));
    let (_, answer, _) = login(&url, &root, &device(&root, 11, Role::Runtime), b"", Tamper::default()).await;
    assert!(welcomed(&answer), "a second device of a registered account needs no invite");

    let stranger = Identity::from_seed([2; 32]);
    let (_, answer, _) =
        login(&url, &stranger, &device(&stranger, 20, Role::Client), token.as_bytes(), Tamper::default()).await;
    assert!(refused(&answer, Code::Unauthenticated), "an invite is single use");
}

#[tokio::test]
async fn a_registered_account_survives_a_hub_restart() {
    let dir = state_dir("invite-restart");
    let token = Registry::create_invite(&dir, Duration::from_secs(3600), now_ms()).unwrap();
    let root = Identity::from_seed([1; 32]);
    let first = start(&dir, Registration::Invite, OpenLimits::default()).await;
    let (_, answer, _) =
        login(&first, &root, &device(&root, 10, Role::Client), token.as_bytes(), Tamper::default()).await;
    assert!(welcomed(&answer));

    let second = start(&dir, Registration::Invite, OpenLimits::default()).await;
    let (_, answer, _) = login(&second, &root, &device(&root, 10, Role::Client), b"", Tamper::default()).await;
    assert!(welcomed(&answer));
}

#[tokio::test]
async fn an_expired_invite_is_refused() {
    let dir = state_dir("invite-expired");
    let url = start(&dir, Registration::Invite, OpenLimits::default()).await;
    let token = Registry::create_invite(&dir, Duration::from_secs(0), now_ms() - 10_000).unwrap();
    let root = Identity::from_seed([1; 32]);
    let (_, answer, _) =
        login(&url, &root, &device(&root, 10, Role::Client), token.as_bytes(), Tamper::default()).await;
    assert!(refused(&answer, Code::Unauthenticated));
}

// ------------------------------ open mode ------------------------------

#[tokio::test]
async fn open_mode_registers_a_new_account_without_an_invite() {
    let dir = state_dir("open");
    let url = start(&dir, Registration::Open, OpenLimits::default()).await;
    let root = Identity::from_seed([1; 32]);
    let (_, answer, _) = login(&url, &root, &device(&root, 10, Role::Client), b"", Tamper::default()).await;
    assert!(welcomed(&answer));
    assert_eq!(Registry::list_accounts(&dir).unwrap().len(), 1);
}

#[tokio::test]
async fn open_mode_rate_limits_new_accounts_but_never_known_ones() {
    let dir = state_dir("open-rate");
    let limits = OpenLimits { per_address: 1, ..OpenLimits::default() };
    let url = start(&dir, Registration::Open, limits).await;
    let (a, b) = (Identity::from_seed([1; 32]), Identity::from_seed([2; 32]));
    let (_, answer, _) = login(&url, &a, &device(&a, 10, Role::Client), b"", Tamper::default()).await;
    assert!(welcomed(&answer));
    let (_, answer, _) = login(&url, &b, &device(&b, 20, Role::Client), b"", Tamper::default()).await;
    assert!(refused(&answer, Code::Limit));
    let (_, answer, _) = login(&url, &a, &device(&a, 11, Role::Runtime), b"", Tamper::default()).await;
    assert!(welcomed(&answer));
}

// ------------------------------ what a forged or broken hello gets ------------------------------

async fn open_hub(name: &str) -> String {
    start(&state_dir(name), Registration::Open, OpenLimits { per_address: 100, ..OpenLimits::default() }).await
}

#[tokio::test]
async fn a_signature_made_for_another_hub_is_refused() {
    let url = open_hub("forge-hub").await;
    let root = Identity::from_seed([1; 32]);
    let tamper = Tamper { sign_for_hub: Some("other.hub"), ..Tamper::default() };
    let (_, answer, _) = login(&url, &root, &device(&root, 10, Role::Client), b"", tamper).await;
    assert!(did_not_verify(&answer), "{answer:?}");
}

#[tokio::test]
async fn a_signature_over_another_connections_nonce_is_refused() {
    let url = open_hub("forge-nonce").await;
    let root = Identity::from_seed([1; 32]);
    let dev = device(&root, 10, Role::Client);
    let (_, answer, old_nonce) = login(&url, &root, &dev, b"", Tamper::default()).await;
    assert!(welcomed(&answer));
    let dev2 = device(&root, 10, Role::Client);
    let replay = Tamper { use_nonce: Some(old_nonce), ..Tamper::default() };
    let (_, answer, _) = login(&url, &root, &dev2, b"", replay).await;
    assert!(did_not_verify(&answer), "{answer:?}");
}

#[tokio::test]
async fn claiming_an_account_root_the_chain_does_not_reach_is_refused() {
    let url = open_hub("forge-root").await;
    let (root, victim) = (Identity::from_seed([1; 32]), Identity::from_seed([2; 32]));
    let tamper = Tamper { claim_root: Some(victim.public()), ..Tamper::default() };
    let (_, answer, _) = login(&url, &root, &device(&root, 10, Role::Client), b"", tamper).await;
    assert!(did_not_verify(&answer), "{answer:?}");
}

#[tokio::test]
async fn claiming_another_principal_is_refused() {
    let url = open_hub("forge-principal").await;
    let root = Identity::from_seed([1; 32]);
    let tamper = Tamper { claim_principal: Some(principal_id(&[7; 32]).to_vec()), ..Tamper::default() };
    let (_, answer, _) = login(&url, &root, &device(&root, 10, Role::Client), b"", tamper).await;
    assert!(did_not_verify(&answer), "{answer:?}");
}

#[tokio::test]
async fn claiming_a_role_the_certificate_does_not_grant_is_refused() {
    let url = open_hub("forge-role").await;
    let root = Identity::from_seed([1; 32]);
    let tamper = Tamper { claim_role: Some(Role::Runtime), ..Tamper::default() };
    let (_, answer, _) = login(&url, &root, &device(&root, 10, Role::Client), b"", tamper).await;
    assert!(did_not_verify(&answer), "{answer:?}");
}

#[tokio::test]
async fn an_expired_certificate_is_refused() {
    let url = open_hub("expired-cert").await;
    let root = Identity::from_seed([1; 32]);
    let mut dev = device(&root, 10, Role::Client);
    let key = Identity::from_seed([10; 32]);
    dev.chain = vec![issue(
        &root,
        &CertSpec {
            subject: key.public(),
            agreement_key: [5; 32],
            role: Role::Client,
            scopes: vec![],
            may_pair: false,
            not_before_ms: 0,
            not_after_ms: 1,
            label: String::new(),
        },
    )];
    let (_, answer, _) = login(&url, &root, &dev, b"", Tamper::default()).await;
    assert!(did_not_verify(&answer), "{answer:?}");
}

#[tokio::test]
async fn a_development_style_hello_is_refused_by_an_authenticating_hub() {
    let url = open_hub("dev-hello").await;
    let mut ws = tokio_tungstenite::connect_async(&url).await.unwrap().0;
    expect(&mut ws, |b| matches!(b, Body::Challenge(_))).await;
    let hello = v1::Hello {
        protocol: 1,
        principal: b"phone".to_vec(),
        role: Role::Client as i32,
        account_credential: b"alice".to_vec(),
        ..Default::default()
    };
    ws.send(Message::binary(encode_frames(&[Frame { body: Some(Body::Hello(hello)) }], MAX).unwrap())).await.unwrap();
    let answer = expect(&mut ws, |b| matches!(b, Body::Welcome(_) | Body::Error(_))).await;
    assert!(did_not_verify(&answer), "{answer:?}");
}

// ------------------------------ accounts stay apart ------------------------------

#[tokio::test]
async fn two_accounts_cannot_reach_each_other() {
    let url = open_hub("isolation").await;
    let (alice, mallory) = (Identity::from_seed([1; 32]), Identity::from_seed([2; 32]));
    let runtime = device(&alice, 10, Role::Runtime);
    let runtime_id = principal_id(&runtime.key.public()).to_vec();
    let (_rt, answer, _) = login(&url, &alice, &runtime, b"", Tamper::default()).await;
    assert!(welcomed(&answer));
    let (mut spy, answer, _) = login(&url, &mallory, &device(&mallory, 20, Role::Client), b"", Tamper::default()).await;
    assert!(welcomed(&answer));

    let cmd =
        Envelope { to: Some(To::Principal(runtime_id)), kind: Kind::Command as i32, r#ref: 3, ..Default::default() };
    spy.send(Message::binary(encode_frames(&[Frame { body: Some(Body::Envelope(cmd)) }], MAX).unwrap())).await.unwrap();
    let answer = expect(&mut spy, |b| matches!(b, Body::Error(_))).await;
    assert!(refused(&answer, Code::Unavailable));
}

fn now_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64
}
