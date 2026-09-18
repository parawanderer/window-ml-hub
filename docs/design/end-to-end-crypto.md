# Proposal: keys, accounts and end-to-end encryption

**Status: decided 2026-09-17; being built** (identities and certificates: `crates/keys`; commands and results:
`crates/seal`). Roadmap steps 5 and 6. Built on the finding
[`webcrypto-in-mv3-worker.md`](../findings/webcrypto-in-mv3-worker.md). The requirements are window-ml
`docs/spec/RUNTIME_HUB.md` §Security: the hub relays ciphertext and routing metadata only, cannot read or forge a
command, every command is signed with a nonce and a clock window, keys never reach the page's main world.

## The traffic the design has to fit

The relay protocol ([`PROTOCOL.md`](../PROTOCOL.md)) carries two shapes, and they want different cryptography:

- **Direct** (commands and results): one sender, one recipient, both usually online.
- **Published** (session events, the index, telemetry): one publisher, **many subscribers**, and **retained in a
  ring** so a subscriber who was offline when an envelope was sent decrypts it later. A phone that opens the app in
  the morning reads the night's events from the ring.

The second shape decides the choice.

## Options

| | Noise (pairwise handshakes) | libsodium boxes | **HPKE-style boxes on WebCrypto** (recommended) |
| --- | --- | --- | --- |
| Works for a recipient offline at send time (rings) | no: a session needs both ends to have handshaken, and ring replay would need old session state | yes | yes |
| Fan-out to many subscribers | one session per pair: N encryptions per event | per recipient, or a wrapped group key | a stream key wrapped to each device |
| Native in the MV3 worker | the AES-GCM suites are, but no Noise implementation is | no: XSalsa20/ChaCha20 are not in WebCrypto | yes, every primitive |
| Non-extractable private keys | no: JavaScript implementations hold key bytes | no | yes |
| Standard | Noise framework | NaCl constructions | RFC 9180 (HPKE), with a Rust implementation (`hpke` crate) |
| Forward secrecy per message | yes, within a session | no | no for static-key boxes; bounded by stream key rotation |

**Recommendation: HPKE-style boxes** with suite DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-256-GCM, and Ed25519
signatures. Noise solves a problem this system mostly does not have (long interactive pairwise sessions) and fails
the one it does (a ring read later by many devices). MLS (RFC 9420) is the full group protocol and would be the
answer if device sets churned constantly; it is far heavier and not needed for a person's handful of devices. Noted as
the upgrade path, not the start.

## The design

### Identities

- **Every principal** (runtime, device, agent client, box connector) has an **Ed25519 identity key** and an **X25519
  key agreement key**, both generated non-extractable where the platform allows it (the extension: `CryptoKey` in
  IndexedDB, in the service worker).
- **The X25519 public key is bound to the identity** by an Ed25519 signature over it, because WebCrypto cannot derive
  one from the other.
- **A principal id is `SHA-256(Ed25519 public key)`**, which is what `Hello.principal` becomes.

### Certificates expire, and that is the revocation that always works

Every certificate carries both `not_before_ms` and `not_after_ms`, and may not be valid for longer than
`MAX_CERTIFICATE_MS` (90 days). "Valid forever" is not something a certificate can say.

The reason is what revocation costs otherwise. A runtime's allowlist stops a revoked device at once and needs nothing
from the hub, which is the mechanism that matters (window-ml `docs/spec/CHAT_PAGE.md` §Pairing). What it cannot reach
is an account nobody is watching: no runtime online, no list anywhere, and a certificate that never ends. With a
window, a device that stops being renewed stops having access, so revoking is simply not renewing, and every other
gap is bounded by the same clock.

Renewal is an ordinary sealed command: a device whose certificate is still valid asks the root or a `may_pair`
delegate, which answers with a new certificate for the same subject key while that device is still on the runtime's
allowlist. Nothing new on the hub, and nothing to distribute.

**`approve`, `control` and `admin` are the account root's to grant**: a delegate cannot pass them on even when it
holds them, because a phone that may approve a click should not thereby be able to pair another phone. Scopes still
only narrow; this is the shorter list that does not travel at all.

A **box connector's** certificate may never set `may_pair` or carry `approve` or `control`: it relays one machine's
telemetry. Encoding that in the verifier beats documenting it, since an issuer that gets it wrong is then refused
rather than trusted — and `issue` refuses it too, so that is learned where it happened rather than on somebody
else's machine.

### Accounts (step 5), from the same keys

- **An account is a root Ed25519 key**, created on the first device and kept there, never exported (decision 4). The
  account id is `SHA-256(root public key)`. The root signs certificates only; the first device also gets its own
  identity key, certified by the root, to log in with.
- **Pairing a device or runtime** is the root key (or a device holding a delegated grant) signing a **device
  certificate**: the new principal's identity key, its role, its scopes, an expiry. Done in person: the runtime shows
  a QR code or short code, the device confirms it (`RUNTIME_HUB.md` §Security 2).
- **Renewing one is a different act**, and the difference is what lets a delegate do it. Pairing issues for a NEW
  subject with scopes chosen then; renewal re-issues an EXISTING subject's certificate, unchanged but for its window,
  and therefore grants nothing that was not already granted. A renewal carries the certificate it renews, verified
  under the root, so `verify_chain` can tell the two apart; without it, nothing but the root could keep a device
  holding `approve` alive past 90 days, once per device and scattered across the year
  ([`revocation.md`](revocation.md)).
- **The hub authenticates `Hello` with that chain**: the principal signs a challenge the hub sends, and presents its
  certificate. The hub verifies signatures with public keys only. It learns the account id and the principal id, which
  it sees already, and holds no secret it could leak. This replaces a separate account password or token.
- **Creating an account** would otherwise be free for anyone who can reach the hub, which is a denial-of-service
  question for the hub operator, not a security one; decision 3 makes it a setting.

### Commands and results (direct)

A command is `{ to, scope, body, nonce, time }` (spec §Security 4), then:

1. **Signed** by the sender's Ed25519 identity key.
2. **Sealed** to the recipient's X25519 key: an ephemeral X25519 key, HKDF over the shared secret with both
   principals' ids as context, AES-256-GCM. The ephemeral public key travels with the ciphertext.
3. **Verified** by the runtime: the certificate chain reaches its account root, the scope covers the command, the
   nonce is new, and `time` is within the window (proposed: 60 s, nonces kept for the window).

A command result is sealed back the same way and names the command's nonce.

As built (`crates/seal`, wire format `proto/wmlhub/v1/seal.proto`):

- **HPKE base mode**, suite (0x0020, 0x0001, 0x0002), checked against the RFC 9180 test vector for that suite. `info`
  is `"wmlhub/seal/v1" || 0x00 || from || to`, both 32-byte principal ids; `aad` is empty. The hub-stamped
  `Envelope.sender` is the `from` the recipient uses, so a hub that claims another sender gets a ciphertext that does
  not open, and one delivered to the wrong principal does not decrypt either.
- **Signed inside the seal**: `SignedCommand { body, signature, chain }`, the signature over
  `"wmlhub/command/v1" || 0x00 || body`, so the hub cannot see whose signature it carries. The chain rides along
  (under 1 KB) so a recipient needs no directory to check scope.
- **Checked in order of cost**: size (1 MiB), decrypt, chain to the account root, the chain's leaf is the stamped
  sender, signature, `from` and `to`, clock (60 s either way), scope (a command) or `answers` (a result), and last the
  nonce, so only an authenticated command inside its window can occupy the replay window.
- **Replay window**: 16-byte nonces per sender, kept until two windows plus a millisecond after arrival, which is the
  last moment a command dated a window ahead could still pass the clock. It holds 65,536 and refuses when full
  rather than forgetting a live nonce, and **each sender has its own share of it** (`MAX_REPLAY_PER_SENDER`, 4,096):
  the window is shared by every device of an account, so without a share one noisy or hostile device would refuse
  every other device for two windows by filling it. With one, it locks only itself out.
- **Cost** (M4, release, one core, three rounds of 2,000; `seal_and_open_costs`): a 64 B command seals to 483 B (419 B
  of chain, signature, HPKE key and tag) in 57 us and opens in 80 us; 4 KB: 63 us and 82-84 us; 64 KB: 155-162 us and
  143-152 us. Opening is one X25519 decapsulation and two Ed25519 verifications (the certificate and the command), so
  a runtime spends well under a millisecond per command however large a phone's queue of them.

### Published streams

- **Each stream has a symmetric stream key** (AES-256-GCM), chosen by the publisher, identified by a short key id.
- **The stream key is wrapped** (sealed as above) to every device currently allowed to view, and the wrapped copies
  are published on a key channel of the publisher, so a device that comes online later finds its copy in the ring.
- **Each event is encrypted under the stream key and signed by the publisher.** Without the signature, any device
  holding the stream key could forge a runtime's events to the other devices; with it, a compromised phone can read
  what it was allowed to read and nothing more. Signing costs one Ed25519 signature per envelope; batching events
  (the protocol already batches ~100 ms) makes that one per batch.
- **Rotation**: unpairing a device, or a time limit, rotates the stream key; the new key is wrapped only to the
  remaining devices. Old ring entries stay readable by whoever held the old key, which is inherent: they were
  delivered.
- **Channel names** are an HMAC of the session id under an account-wide channel key, as `PROTOCOL.md` asks, so the hub
  cannot join a session to box traffic by name. As built (`ChannelKey::channel`): HMAC-SHA256 over
  `"wmlhub/channel/v1" || purpose || 0x00 || subject`, truncated to 16 bytes, where `purpose` separates a session's
  events from its keys. Two accounts watching the same box get different channel names for it.
- **Box telemetry** is the same shape with the box connector as publisher: the "group key per box" the spec
  describes is this stream key.

As built (`crates/seal/src/stream.rs`):

- **A frame** is `StreamFrame { key_id, counter, nonce, ciphertext, signature }` in an envelope's payload. The key id
  is `SHA-256("wmlhub/streamkey-id/v1" || 0x00 || key)[..8]`, so a publisher and a subscriber agree on it without
  extra state. AES-256-GCM with a fresh 12-byte nonce.
- **The signature covers a header and the ciphertext**: `publisher || len(channel) || channel || key_id || counter ||
  nonce`, under the label `"wmlhub/stream/v1"`. That header is also the AEAD's associated data. Moving a frame to
  another channel, relabelling its key, renumbering it or splicing another frame's ciphertext onto it each stop it
  verifying. (Tested by removing each binding in turn: the channel, key id and counter are load-bearing; the
  publisher id and the associated data are redundant while a reader gets the publisher's key from a grant, and are
  kept for when one does not.)
- **Counters are the publisher's own**, from 1, across rotations. A reader refuses a counter it has passed (a hub that
  replays or reorders) and reports how many were skipped, which for session events means the ring was truncated.
- **A frame's nonce is random**, 96 bits, though the header beside it already carries a counter and a key id that a
  nonce could be derived from for free. Random is the safer default here: a publisher that restarts, keeps its stream
  key and resumes its counter would re-use a derived nonce on different plaintext, which is the catastrophic AES-GCM
  failure, while a random one survives it. The collision risk it trades that for is about n^2 / 2^97 — roughly 2^-33
  after 2^32 frames under one key, which no session's event stream reaches. Deriving one safely would need a
  per-publisher epoch that changes whenever the counter resets, which is more mechanism than 12 bytes a frame is
  worth.
- **A grant** is `GrantBody { from, to, nonce, time_ms, channel, key_id, key, from_counter }`, signed under
  `"wmlhub/grant/v1"` and sealed with info `"wmlhub/keygrant/v1"`, so a command can never be opened as a grant or a
  grant as a command. It is checked exactly as a command is (chain, sender, signature, addressing, clock, replay), and
  it carries the publisher's chain: that is how a subscriber learns the key that signs the stream's frames.
  `from_counter` is **enforced**, not advisory: a reader refuses a frame below the first counter the grant covers, so
  a device paired this morning cannot read last night out of a ring the hub still holds. A grant's channel is bounded
  by the relay's `max_id_bytes`, since a channel the hub would not route is a stream that cannot exist.
- **Cost** (M4, release, three rounds of 2,000; `frame_costs`): a 512 B batch becomes a 623 B frame, sealed in 10 us
  and opened in 25 us; 8 KB: 21-22 us and 31-32 us; 64 KB: 100-105 us and 80-84 us. A frame carries 111 bytes over its
  batch.

### Replay and ordering

- Commands: nonce plus clock window, as above.
- Events: the publisher's own counter inside the signed plaintext (the session contract's `cursor`), so a hub that
  replays or reorders ring entries is detected by the client rather than trusted. The hub's `seq` stays a routing
  aid only.

### What the hub still learns

Unchanged from the spec: account and principal ids, who is online, sizes, timing, channel identifiers (keyed, so not
session hashes), and envelope kinds. Payload padding to size buckets for session events stays open.

## Decisions (2026-09-17)

1. **HPKE-style boxes** (X25519, HKDF-SHA256, AES-256-GCM, Ed25519 signatures), with MLS kept as the upgrade path if
   device sets start churning.
2. **An account is a root key**; devices hold certificates chaining to it, and the hub verifies them with public
   keys only. No separate hub password or token.
3. **Registration is a setting**: `invite` (the default: a new account root needs an operator-issued, single-use
   invite) or `open` (any valid root, rate limited per source address). Both modes are tested.
4. **No root key export, and the root does not live in a runtime.** Losing the account costs a re-pairing, not data,
   and a paper copy is a standing credential that can mint a device with `approve`. Instead, the root can give a
   second device you own a `may_pair` certificate, so losing one device is survivable; losing all of them means a new
   account. Revoking is the same shape: the runtime holds a never-delegable `may_revoke` rather than the root itself,
   because a stolen `may_revoke` can lock every device out, which the root fixes by re-pairing, while a stolen root
   mints a device nobody can distinguish from your own for as long as the attacker keeps renewing it.
5. **One Ed25519 signature per published envelope**, with events batched into envelopes (~100 ms). The signature
   covers the publisher's own counter, the channel and the stream key id, so a hub that replays, reorders or splices
   envelopes is caught by the client.

## Not decided here

The pairing UI, device certificate format details (a small protobuf message is the obvious choice), the exact HPKE
`info` strings, and test vectors shared between Rust and the extension. Those come with the implementation, with
vectors checked on both sides the way the framing's were.
