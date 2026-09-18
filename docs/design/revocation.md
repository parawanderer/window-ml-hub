# Proposal: revoking a device, once it already holds keys

**Status: the two changes to `keys` are BUILT; the lists and the rotation are not.** The five questions below are
all answered: the four in Decided, and where the account root key lives, which decided that the runtime holds a
never-delegable `may_revoke` rather than the root itself. `CertificateBody` now carries `may_revoke` and `renews`,
and `verify_chain` enforces both rules (`crates/keys`, with a renewal in `vectors/seal-v1.json` so the TypeScript
implementation is held to the same rule). `version` as a timestamp is part of the list format, which is still
unbuilt. The argument this continues is window-ml `tmp/hub-revocation-and-headless-pairing.md` (the UI
session's answer, worth reading for the reasoning) and [`pairing.md`](pairing.md) §Revocation, which settled the
two halves that could not wait: every certificate now carries a bounded window, and a headless connector pairs
through the same protocol as a phone.

What is left is the half that was deferred until pairing existed. Pairing exists.

## The problem in one paragraph

Revoking a device at the runtime is immediate and needs nothing from anybody: the runtime checks its own allowlist
on every command, so a revoked device stops being answered the moment a person clicks. That is the authoritative
revocation and it is not moving. But an allowlist only governs what the runtime itself answers, and by the time a
device is revoked it may already hold things the runtime cannot reach: a stream key that opens frames published
afterwards, and a certificate that other principals will keep accepting until it expires.

## The concrete instance, in shipped code

`wmlbox run` grants its stream key to any principal that asks with a valid certificate granting `view`
([`box-connector.md`](box-connector.md) §Who gets the key). A connector has no allowlist and no way to hear about a
revocation, so today a revoked device asks and is granted, for as long as its certificate is valid. Expiry bounds
that at 90 days, and a runtime that renews before lapse will be renewing sooner, but it is a bound measured in
weeks rather than in seconds.

This is not an argument against the ask-based grant; it is the same gap the design has named since the beginning,
now with a name and a line number. The connector is simply the first publisher that is not the runtime.

## What must stay true

- **The runtime decides.** A hub that could revoke could also decline to, and the whole design rests on the hub
  being trusted with routing and nothing else. Anything the hub holds here is an optimisation that is safe to be
  stale, wrong or absent.
- **No new trust in anybody.** Whatever carries a revocation is signed by a key that is already trusted for this
  account, and verified by whoever acts on it.
- **A revocation that cannot be delivered is refused, not queued.** Design (a) from `tmp/hub-rotation-state-and-renewal.md`:
  a revoke while the runtime is offline is refused, so "revoked" never means "revoked in a few hours". The rotation
  rollup carries what is still owed while the runtime works through it.

## The two mechanisms, and why they are not the same thing

| | A: the runtime tells the publishers | B: the runtime tells the hub |
| --- | --- | --- |
| Fixes | a revoked device reading a stream it was granted | a revoked device connecting and spending the account's budget |
| Authority | the runtime, directly | the hub, on the runtime's word |
| If it fails | the stream stays readable: this one must work | wasted work, nothing unsafe |
| Trusts the hub with | routing, as before | refusing a connection it is told to refuse |
| Needed for | correctness | resource control |

**Build A first and treat B as optional.** B looks like the bigger piece and is the smaller one: if the hub refuses
a revoked device's connection then a connector never hears from it, which fixes A by accident — and a security
property that holds by accident of an optimisation is one that disappears the first time the optimisation is stale.

### A: a sealed revocation to each publisher

A revocation is an ordinary sealed command from the runtime to a publisher, carrying a **revocation list** the
publisher verifies for itself:

```
RevocationList {
  account_root       the key this list is signed under, so a list names the account it belongs to
  version            monotonic; a publisher refuses a version it has already passed
  issued_at_ms
  repeated Revoked   { subject_key } or { certificate_hash }: the device entirely, or one certificate of it
  signature          Ed25519 under "wmlhub/revocation/v1" over the body
}
```

Revoking by the **SHA-256 of the transmitted certificate body** needs no schema field: the body is verified exactly
as transmitted, so its hash is a stable identifier for one certificate. Revoking by **subject key** is "this device
entirely, including whatever it is renewed into", which is what a person means by unpairing.

What a publisher does with one:

1. Verify the signature against the account root it already holds, and refuse a version at or below the one it has.
2. **Rotate the stream key.** A new key means a new key id, and the counter it is granted from is where the new key
   begins, so the devices that remain read on and nothing is re-encrypted.
3. Refuse a future `box.grant` from anything the list names.

The devices that remain need no notification: frames start arriving under a key id they do not hold, which is
already the signal to ask again (the same signal a connector restart produces). That is what makes this cheap for
the connector, which has no directory of the account's devices and now needs none.

### B: a signed list the hub keeps

The same list, posted to the hub over an authenticated connection, kept per account, newest version wins and an
older one is refused. The hub then refuses a connection whose leaf is named. Its whole value is that a revoked
device stops costing the account its connection and work budget. If the hub holds an older list than a runtime
does, nothing is unsafe: the runtime still refuses its commands and the publishers still refuse to grant to it.

## What this costs the hub, and what bounds it

Only B costs the hub anything, and it is deliberately small: one list per account, at most one version kept, a
bounded number of entries (proposed 256, with a list that would exceed it being a device inventory rather than a
revocation), and a bounded size. It is written only by a principal that has already authenticated on that account
and holds the root or a delegate that may pair.

## Decided (2026-09-18, window-ml `tmp/chat-page-revocation-answers.md`)

The chat-page session answered all four, and the answers are worth their reasons rather than only their verdicts.

- **The root signs; `admin` is permission to ASK.** Not a `may_pair` delegate, for three reasons: a list is rendered
  from one runtime's allowlist, and two signers means two lists that can disagree with no way for a UI to say which
  is true; `may_pair` creates something NARROWER than itself, which is what makes delegation safe, while revoking
  acts on a peer and possibly on the device that delegated you; and a phone that could both pair and revoke is an
  account takeover from one lost device.
- **Catch-up is a pull, with a push as a nicety.** The answer to `box.grant` carries the current list version, which
  costs one field and is checked at the only moment that matters: when a publisher is about to hand out a key. A
  publisher offline for a week learns before it grants anything. The runtime also pushes on change to whatever
  presence says is there, best-effort, with no acknowledgements and no retries, so the guarantee does not depend on
  presence being accurate. One guarantee and one optimisation, which is the same split as A and B above.
- **`device.revoke` returns as soon as the allowlist is updated**, not after the publishers are told. The allowlist
  is the authoritative act and it is immediate; blocking on N publishers would make the one action people press when
  they are worried the slowest thing in the product, with its latency set by the least responsive connector on the
  account. It would also be a lie either way, since an offline connector cannot be told at all. `rotation` is what
  carries the rest.
- **A box connector is a publisher the runtime pushes to.** Its being on the paired-device list with no other
  relationship to the runtime is not an objection: the list is enough to reach it, and revocation IS the
  relationship. A revoked phone's `rotation.streams` counts the connector's channels too, or the list says nothing
  is owed while the phone can still read a box.

## Where the root key lives (2026-09-18, window-ml `tmp/chat-page-root-key-answer.md`)

**Not in a browser profile: the runtime holds `may_revoke`, never the root.** The chat-page session refused the
first option on an asymmetry the hub session had not weighed. A stolen `may_revoke` is recoverable — a laptop that
can revoke can lock every device out, which is a bad afternoon the root fixes by re-pairing. A stolen root is not:
it mints a device nobody can distinguish from the person's own, for as long as the attacker keeps renewing it, and
that is exactly the property `NEVER_DELEGABLE` exists to protect. A runtime is also the thing most likely to be
left logged in on a laptop in a bag.

So option three from the list above, as proposed there:

- **`may_revoke` is a certificate field, never delegable**, granted explicitly at the root the way `admin` is, and
  granted to the runtime at pairing so a revocation can be signed with the root nowhere near.
- **Exactly one principal holds it at a time.** The list's `version` is per account and monotonic, so two signers
  race and the loser's revocation is refused as stale, which is the worst possible way for a revocation to fail.
  A second runtime that may revoke is the root's decision to re-place, not a default.

### `version` is a timestamp, because the holder is replaceable

The hub session's own argument for one signer assumed the signer never changes. It does: a lost laptop is the case
`may_revoke` was chosen for, and the root then grants it elsewhere. A counter cannot survive that — the new holder
would have to learn the current version from somewhere before its first list is accepted, and the only somewhere is
a publisher it has not yet spoken to.

So `version` is epoch milliseconds at signing. Monotonic per account with no coordination, and handover carries no
state. A publisher refuses a version at or below the one it holds, and also one more than `CLOCK_WINDOW_MS` ahead
of its own clock, so a signer with a fast clock costs at most a minute rather than locking the account out of
revoking until the year on its wrist arrives. That is the same defence `seal` already applies to a command's time.

### Renewal is not pairing, and `verify_chain` has to learn the difference

The chat-page session's sharpest point, and it is a real hole in the shipped rule. A delegate may issue only scopes
it holds and never a `NEVER_DELEGABLE` one, so nothing but the root can re-issue a certificate carrying `approve`,
`control` or `admin`. With `MAX_CERTIFICATE_MS` at 90 days, that reads as "produce the root device four times a
year or your phone stops approving" — and once per powerful device, scattered across the calendar, not once per
account.

Pairing issues a certificate for a NEW subject with scopes chosen then. Renewal re-issues an EXISTING subject's
certificate, unchanged but for its window. The first grants something; the second grants nothing that was not
already granted, which is why a delegate may do it for scopes it could not itself grant.

Concretely, `CertificateBody` gains an optional embedded predecessor, and a certificate that carries one is
exempted from `ScopeWidened` and `NotDelegable` — the two checks that make delegation safe, so the exemption is
bought strictly:

1. The predecessor's signature verifies **under the account root**, never under a delegate. Renewals do not chain,
   so a delegate cannot bootstrap one into a wider one.
2. The predecessor's window is **not** checked. An expired predecessor is the normal case; that is the point.
3. Every other field is **equal**: `subject`, `agreement_key`, `role`, `scopes` (as a set), `may_pair`. The
   agreement key matters most and is the field a loose rule would lose: it is where sealed commands go, so a
   delegate free to change it could redirect everything sealed to an approver into a key it holds, without ever
   holding the approver's identity key.
4. `OutlivesIssuer` still applies. A renewal cannot outlive the runtime's own certificate.

Point 4 is why this is worth the rule rather than the cheaper alternative of aligning every device's window with
the runtime's at each root visit. Alignment drifts the moment a device is paired mid-window, and the only way to
stop it drifting is to truncate that device to whatever is left, which hands a device paired on day 89 a one-day
certificate. Under renewal the device gets its full window, then a short one, then a shorter one as the runtime's
own expiry approaches, and none of that is visible to anybody, because a delegate's renewal is silent and a root's
is a person fetching a device out of a drawer. The root visit does not disappear; it collapses to one per account
per window, for the runtime's own certificate, which is a visit the person was making anyway.

**What it costs, stated rather than discovered: letting a device lapse stops being a way to remove it.** Today an
un-renewed device falls out of the account on its own. Once the runtime renews everything on its allowlist, a
device leaves only by being revoked, and the allowlist is the thing that has to be right. That is a fair trade
given `device.revoke` exists, and it is the reason the allowlist rather than expiry is called the authoritative
act at the top of this document.

The fallback, if this is not built: renewal of a device holding `approve`, `control` or `admin` requires the root,
and those devices lapse unless the person re-blesses them. Coherent, defensible as a deliberate re-blessing, and
the chat-page session said it would accept it. It should be a decision rather than a consequence.

### What the paired-devices list has to show

`mayRevoke` goes on `DeviceInfo` beside `mayPair`. It is not the noise a flag true on every account once would be,
because *which* row carries it is the thing a person needs before acting: **revoking the holder of `may_revoke`
removes the account's ability to revoke anything**, until the root grants it again. That row is the one the UI
should refuse to revoke without saying so, and a holder revoking itself should be refused outright.


## Why not simpler

- **"Let the hub revoke."** Then the hub is the account. Never, and it is the same answer as in `pairing.md`.
- **"Rely on expiry."** Expiry is what works with nobody online, which is why it was settled first, and it is
  measured in weeks. A person who unpairs a phone means now.
- **"Rotate on a timer instead."** A time-limited key bounds nothing here: a revoked device holding a valid
  certificate simply asks for the new key and passes the same check. Rotation is only a revocation when something
  tells the publisher who to refuse.
