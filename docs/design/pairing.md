# Proposal: pairing a device, a runtime or a connector

**Status: proposed 2026-09-18, not built.** The last thing between the hub and real use: every principal needs a
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
   certificate, seals it to the offered agreement key, and posts it back to the slot.
6. **The new principal takes the certificate**, verifies it chains to the account root it was told to expect, and logs
   in normally. The slot is deleted on first collection.

The fingerprint is `SHA-256("wmlhub/pairing/v1" || identity_key || agreement_key)`, rendered as six words from a fixed
list, or twelve hex characters where words are wrong (a printed connector). Six words is about 60 bits against a
prepared list, which is the number that matters: a hub gets one attempt, in front of a person who is comparing.

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

## What is still open

- **Whether a pairing slot lives in the relay or beside the registry.** It is account-less until the certificate is
  issued, which argues for the registry (where open registration's rate limiting already lives) rather than the
  relay's per-account structures.
- **Revocation**, which this design does not address at all: unpairing today means rotating stream keys and letting
  the certificate expire. A short `not_after` on a paired device's certificate, with re-pairing as renewal, may be
  enough and is worth deciding before the first long-lived certificate is issued.
- **Whether a connector pairs at all**, or whether a box connector is configured with a certificate by the operator
  who runs it, the way a server gets a TLS certificate. For a self-hosted hub, the operator and the account holder
  are usually the same person.
- The word list for fingerprints, which should be the one the extension already ships if it has one.

## Why not simpler

- **"Let the hub issue certificates."** Then the hub is the account, and every promise in `end-to-end-crypto.md`
  disappears. Never.
- **"Skip the fingerprint; the code is enough."** The code authenticates the SLOT, not the keys in it. A hub that
  swaps the keys in a slot pairs itself, and nobody notices without the fingerprint.
- **"Use the invite mechanism that already exists."** An operator invite admits an ACCOUNT to a hub; it says nothing
  about which keys belong to a person, and it is issued by the hub's operator rather than by the account.
