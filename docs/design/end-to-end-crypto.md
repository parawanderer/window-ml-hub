# Proposal: keys, accounts and end-to-end encryption

**Status: proposal, awaiting a decision** (2026-09-17). Roadmap steps 5 and 6. Built on the finding
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

### Accounts (step 5), from the same keys

- **An account is a root Ed25519 key**, created on the first device and kept there (or exported once to paper for
  recovery; to decide). The account id is `SHA-256(root public key)`.
- **Pairing a device or runtime** is the root key (or a device holding a delegated grant) signing a **device
  certificate**: the new principal's identity key, its role, its scopes, an expiry. Done in person: the runtime shows
  a QR code or short code, the device confirms it (`RUNTIME_HUB.md` §Security 2).
- **The hub authenticates `Hello` with that chain**: the principal signs a challenge the hub sends, and presents its
  certificate. The hub verifies signatures with public keys only. It learns the account id and the principal id, which
  it sees already, and holds no secret it could leak. This replaces a separate account password or token.
- **Creating an account** is therefore free for anyone who can reach the hub, which is a denial-of-service question
  for the hub operator, not a security one: rate limits per source address, or an operator-issued invite required to
  register a new root key. (To decide; an invite is simplest for a personal hub.)

### Commands and results (direct)

A command is `{ to, scope, body, nonce, time }` (spec §Security 4), then:

1. **Signed** by the sender's Ed25519 identity key.
2. **Sealed** to the recipient's X25519 key: an ephemeral X25519 key, HKDF over the shared secret with both
   principals' ids as context, AES-256-GCM. The ephemeral public key travels with the ciphertext.
3. **Verified** by the runtime: the certificate chain reaches its account root, the scope covers the command, the
   nonce is new, and `time` is within the window (proposed: 60 s, nonces kept for the window).

A command result is sealed back the same way and names the command's nonce.

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
  cannot join a session to box traffic by name.
- **Box telemetry** is the same shape with the box connector as publisher: the "group key per box" the spec
  describes is this stream key.

### Replay and ordering

- Commands: nonce plus clock window, as above.
- Events: the publisher's own counter inside the signed plaintext (the session contract's `cursor`), so a hub that
  replays or reorders ring entries is detected by the client rather than trusted. The hub's `seq` stays a routing
  aid only.

### What the hub still learns

Unchanged from the spec: account and principal ids, who is online, sizes, timing, channel identifiers (keyed, so not
session hashes), and envelope kinds. Payload padding to size buckets for session events stays open.

## Decisions needed

1. **HPKE-style boxes** over Noise and libsodium, with MLS as the later upgrade path. (Recommended.)
2. **Accounts as root keys with device certificates**, verified by the hub, instead of a separate hub credential.
   (Recommended.)
3. **Registering a new account**: open with rate limits, or an operator invite. (Suggest: invite, for now.)
4. **Root key recovery**: none (lose every device, start a new account), or a one-time export to paper.
5. **Signing every published envelope** (or batch) with the publisher's identity key. (Recommended.)

## Not decided here

The pairing UI, device certificate format details (a small protobuf message is the obvious choice), the exact HPKE
`info` strings, and test vectors shared between Rust and the extension. Those come with the implementation, with
vectors checked on both sides the way the framing's were.
