# Proposal: pairing a device, a runtime or a connector

**Status: built, except the two UIs that drive it.** The slot store (`crates/hub/src/pairing.rs`), the code and
fingerprint (`crates/keys/src/pairing.rs`), the four frames (`PairOffer`, `PairFetch`, `PairAnswer`, `Paired`), the
hub's handling of them, and both client sides (`Pairing::offer` and `Client::pairing_offered` / `pairing_answer`).
An end-to-end test pairs a device that has no certificate and then logs in with what it was given.

What is left is the chat page's pairing UI; the connector's terminal side is `wmlbox pair`
(`crates/connector/src/pair.rs`), which prints the code and the fingerprint and refuses an answer that does not name
its own keys. The last thing between the hub and real use: every principal needs a
certificate, and nothing issues one yet. It blocks the connector's binary (roadmap step 7), the extension's connector
(step 8), and the chat page's pairing UI, which the UI session builds against whatever this decides.

Requirements are window-ml `docs/spec/RUNTIME_HUB.md` §Security 2 ("pairing is done in person, a QR code or a short
code shown on the runtime, confirmed on the device") and decision 4 of
[`end-to-end-crypto.md`](end-to-end-crypto.md): no root key export, and a second device may hold `may_pair` so losing
one device is survivable.

## The problem in one paragraph

A new principal has keys and nothing else. It cannot log in, because logging in needs a certificate, and a certificate
can only be issued by the account root or a delegate holding `may_pair` — which lives on another device, usually in
someone's pocket. So something has to carry two small blobs between two devices that have no channel yet: the new
principal's public keys one way, and a certificate the other. The hub is the only thing both can reach, and the hub is
exactly what must not be trusted with it.

## What the hub may and may not do

The certificate is signed by a key the hub never sees, so a hub cannot mint a device. What a hub in the middle CAN do
is lie about which keys are being paired: substitute its own public keys, get the person to confirm a fingerprint that
matches the hub's key rather than the new device's, and end up holding a certificate for a principal it controls. So
the property that has to hold is:

> **The human confirms the same fingerprint on both devices, and that fingerprint covers the new principal's keys.**

Everything below is arranged so a hub that substitutes anything changes the fingerprint the person is asked about.

## Options

| | A: two QR codes | B: hub-mediated, short code | C: hub-mediated, code from the new device |
| --- | --- | --- | --- |
| New principal sends | QR on its screen | keys, under a code the hub assigns | keys, under a code it chose |
| Certificate returns by | a second QR, read by the new device | the hub, sealed to its agreement key | the hub, sealed to its agreement key |
| Needs a camera on | both | the paired device only (or typing) | the paired device only (or typing) |
| Works for a headless connector | no | yes | yes |
| What a hostile hub can do | nothing: it is not in the path | substitute keys, but the fingerprint changes | as B |
| New pre-auth surface | none | a pairing slot | a pairing slot |

**Recommendation: C**, with A available wherever both ends have a screen and a camera, because C is the only one that
pairs a headless box connector and a service worker that cannot open a camera.

The difference between B and C is who chooses the code, and it matters: if the hub assigns it, a hub can hand the same
code to two devices and pair the wrong one. If the new device chooses it and it is carried by the human, the hub only
ever sees a code it did not pick.

## The flow (option C)

1. **The new principal generates its keys** (identity, agreement), and a **pairing code**: 8 characters of Crockford
   base32 from a CSPRNG, 40 bits. It shows the code, and the fingerprint of its own keys, on whatever screen it has;
   a headless connector prints them.
2. **It opens a pairing socket to the hub** and sends `PairingOffer { code_hash, identity_key, agreement_key, role,
   label }`, where `code_hash` is SHA-256 of the code. The hub stores it in a **pairing slot** keyed by `code_hash`,
   for 10 minutes. The hub never learns the code itself, so a hub that leaks its slots leaks nothing usable.
3. **The person types or scans the code on a paired device** (one holding the root, or `may_pair`). That device asks
   the hub for the slot by `code_hash`, and is given the offer.
4. **The paired device shows the fingerprint** it computed from the offered keys. The person checks it matches what
   the new principal is showing. This is the step that stops a hub in the middle, and it is the only step that cannot
   be skipped for convenience.
5. **The person confirms, and picks scopes** (the UI proposes a default per role). The paired device issues the
   certificate, seals it to the offered agreement key, and posts it back to the slot. What it seals is the whole
   chain, leaf first: one certificate when the root issued it, two when a device holding `may_pair` did, because a
   device given only the leaf could verify nothing above the key that signed it.
6. **The new principal takes the answer**, opens it with the agreement key it offered, verifies the certificate
   chains to the account root inside, and logs in normally. The slot is deleted on first collection.

**The answer is sealed to the key the offer carried**, because it hands over more than a certificate: it carries the
account's **channel key**, without which a device cannot name any of the account's streams. The certificate is
public, but there is no reason to put it in the clear beside a key that is not, and a hub that could read a slot would
otherwise learn the name of every channel the account uses. HPKE with its own label, no principal ids bound in —
neither side has a certificate for the other yet, which is the situation pairing exists to fix, and what binds it
instead is the person comparing a fingerprint of the very key it seals to.

The fingerprint is `SHA-256("wmlhub/pairing/v1" || identity_key || agreement_key)`. `crates/keys` hands back the
digest and a twelve-character hex rendering for where words are wrong (a connector printing to a terminal); the word
rendering belongs to whichever UI shows it, and window-ml's session owns that choice, including whether words beat a
number for people comparing two screens quickly.

The code is eight characters of Crockford base32 (40 bits), read back however a person typed it — lower case, spaces,
hyphens, and the confusions that alphabet exists for (`O` as `0`, `I` and `L` as `1`). The hub is told
`SHA-256("wmlhub/pairing-code/v1" || code)` and never the code.

## What this costs the hub, and what bounds it

A pairing slot is the hub's only unauthenticated write, so it is the thing to be strict about:

- **Per slot**: `code_hash` (32 bytes), one offer (keys, role, a label, bounded at 256 bytes), one sealed certificate
  (bounded at `MAX_CERT_BYTES` plus the seal). Nothing else, and nothing the hub reads.
- **Lifetime**: 10 minutes, and deleted on first collection. A slot is a promise to hold two blobs, not storage.
- **Count**: a global cap (proposed 1,024 open slots) and a per-source-address rate (proposed 3 an hour, as open
  registration already has), so slots cannot be farmed to exhaust memory or to grind `code_hash`.
- **Grinding**: 40 bits of code with a 10-minute window and a per-address rate is not worth attacking, but the slot
  lookup is also answered at a fixed rate per address, so a hit and a miss cost the same.
- **The offer is public to whoever has the code.** That is the point, and it is why the code is short-lived: the
  offer carries no secret, only public keys the person is about to confirm.

## Revocation, and what a headless connector does (decided 2026-09-18)

From the UI session's answer (window-ml `tmp/hub-revocation-and-headless-pairing.md`), which is worth reading for the
argument rather than only the conclusions.

- **The authoritative revocation is the runtime's allowlist**, which takes effect at once and needs nothing from the
  hub. That property is what keeps the hub trusted with routing only, and it is not moving into the hub.
- **Expiry is what the allowlist cannot reach**, so every certificate now carries a bounded window (above). This was
  settled first because it cannot be retrofitted once long-lived certificates exist.
- **Revoking a device must rotate every stream key it held** and re-grant to the devices that remain, because
  nothing else stops it decrypting what is published afterwards. `from_counter` is the other half: the new key is
  granted from the counter it begins at, so the remaining devices read on and nothing is re-encrypted. Rotation on
  unpair is part of the pairing work, not a later item: a revocation that leaves the stream readable is not one.
- **A hub-side revocation list is resource control, not security**, and is deferred until after pairing lands. A
  revoked device can still connect and spend the account's budget until its certificate expires; the runtime refuses
  its commands throughout. When it is built it is a small signed list per account, monotonically versioned so an
  older list cannot be rolled back over a newer one, and the security statement stays "the runtime decides".
- **Revocation names a certificate by the SHA-256 of its transmitted body**, or a device by its subject key. The body
  is verified exactly as transmitted, so its hash is a stable identifier and no schema field is needed.
- **A headless connector pairs through the same protocol**, because the box must generate its own key: a private key
  that arrives from elsewhere is a private key that existed elsewhere. Two ways for a person to approve it, and the
  difference is stated rather than hidden:
  - **Attended**: the connector prints the comparison code, the operator confirms it in the pairing UI. Nothing is
    trusted but the two screens.
  - **Unattended**: the operator generates a one-time token in the pairing UI and puts it in the box's config, where
    the box's other configuration already comes from. The connector redeems it once, inside a bounded window, for a
    certificate with no `may_pair` and a narrow scope set. **This trusts the channel the token travelled on**, which
    the attended path does not. Acceptable for a box an operator provisions; not offered to a phone.

## What is still open

- **Whether a pairing slot lives in the relay or beside the registry.** It is account-less until the certificate is
  issued, which argues for the registry (where open registration's rate limiting already lives) rather than the
  relay's per-account structures.
- **What a renewal command looks like** in the session contract's terms, since it is a command like any other and the
  chat page renders the paired-device list that offers it.
- The word list for fingerprints, which should be the one the extension already ships if it has one.

## Why not simpler

- **"Let the hub issue certificates."** Then the hub is the account, and every promise in `end-to-end-crypto.md`
  disappears. Never.
- **"Skip the fingerprint; the code is enough."** The code authenticates the SLOT, not the keys in it. A hub that
  swaps the keys in a slot pairs itself, and nobody notices without the fingerprint.
- **"Use the invite mechanism that already exists."** An operator invite admits an ACCOUNT to a hub; it says nothing
  about which keys belong to a person, and it is issued by the hub's operator rather than by the account.
