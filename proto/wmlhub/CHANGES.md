# Changes to `wmlhub/v1`, newest first

The hub owns these schemas and other repositories vendor them ([`../../docs/SCHEMAS.md`](../../docs/SCHEMAS.md)).
From a reader's side a change is invisible until something needs it, so this file is the record, and
`tools/check-schema-changes.sh` refuses a change that does not touch it.

**It is not only the schema.** A second implementation reproduces the chain rules, the domain-separation labels, the
bounds and the channel derivation, and none of those lives in a `.proto`: `NEVER_DELEGABLE` is a Rust constant, and
adding a name to it means the hub refuses a chain a reader still accepts, which is a divergence with no failing
test on either side. So `crates/keys/src/lib.rs` and `crates/seal/src/{lib,stream}.rs` are watched here too.

**If you vendor these files**: pin them with a `<name>.proto.pin.json` carrying the git blob id, and run
`tools/check-pins.sh --upstream` (20 lines of bash in this repo, copyable) on a schedule. That tells you upstream has
moved without depending on anybody remembering to say so. This file tells you what moved and whether you care.

Everything so far is additive: a peer that has never seen a field does not send it, and one that does not know a
field ignores it. Nothing here has required a reader to change to keep working; two have required a reader to change
to keep being CORRECT, and they are marked.

## v0.2.0 — `may_revoke` and `renews` on `CertificateBody`

**A verifier must implement renewal or it will refuse a renewed device.** Marked, because nothing breaks until a
runtime renews something and then it breaks on the reader's side only.

- `CertificateBody.may_revoke` (11): may sign the account's revocation lists. Granted only by the root, never by a
  delegate, and never renewed by one either.
- `CertificateBody.renews` (12): the certificate this one re-issues. A certificate carrying one is exempt from
  `ScopeWidened` and `NotDelegable`, bought strictly — see the field comment, and
  [`../../docs/VECTORS.md`](../../docs/VECTORS.md) step 3 for the three ways to pass that check by accident.
- `vectors/seal-v1.json` is at version 3 with a `renewal` block, which is how a second implementation checks it.

## v0.1.0 — the first pinnable schema

`hub.proto`, `identity.proto` and `seal.proto` as [`../../docs/PROTOCOL.md`](../../docs/PROTOCOL.md) describes them.

Two things that had already changed before the tag and are worth naming, because a copy taken from `main` earlier in
the day has them backwards:

- **`CertificateBody` requires BOTH ends of its window**, and nothing may be valid for longer than
  `MAX_CERTIFICATE_MS` (90 days). An earlier draft read `not_after_ms: 0` as "no expiry"; a reader that still
  believes that will accept a certificate this design refuses. Expiry is the one revocation that needs no list, no
  hub and nobody online, so this one matters. `vectors/seal-v1.json` went to version 2 for it.
- **`Presence.chain`** carries the chain a principal presented when it came online. Without it a runtime knows a
  phone is online and has no way to seal anything to it, because the leaf's agreement key is only in the chain.
- **The pairing messages** (`PairingOffer`, `PairingAnswer`, `PairedWith`) arrived with
  [`../../docs/design/pairing.md`](../../docs/design/pairing.md). `PairedWith.channel_key` is the account's channel
  key: channel names are an HMAC under it, so a device can name every channel it needs from the moment it is paired.
