# Proposal: revoking a device, once it already holds keys

**Status: proposed, nothing built. The four questions below are answered** (see Decided), and one new one is open:
where the account root key lives, which decides whether a revocation can be signed when a person asks for it. The argument it continues is window-ml `tmp/hub-revocation-and-headless-pairing.md`
(the UI session's answer, worth reading for the reasoning) and [`pairing.md`](pairing.md) §Revocation, which settled
the two halves that could not wait: every certificate now carries a bounded window, and a headless connector pairs
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

## The one this raises, which decides whether the above holds

**Where does the account root key live?** The answers above assume something online can sign when a person revokes.
If the root lives on a device kept apart, then `device.revoke` updates the allowlist at once and nothing is signed
until that device is reachable, so publishers keep granting to the revoked device and the "returns at once" answer
needs a sentence about what is still owed for longer than the rollup implies.

Three ways out, and this is the hub session's recommendation rather than a decision:

- **The runtime holds the root.** Simplest, and it is already close to true: a runtime that renews the devices on
  its allowlist before they lapse has to issue certificates, which needs the root or a `may_pair` delegate. The cost
  is that the account's root key lives in a browser profile, and losing the profile loses the account unless it was
  backed up.
- **The runtime holds `may_pair` only, and revocation waits for the root.** Honest, and the UI has to say "revoked
  here; the keys rotate when <device> is next online", which is a worse sentence than the one we agreed.
- **A separate `may_revoke`, granted at the runtime and never delegable.** It keeps every reason from answer 1: one
  signer per runtime, a power the root grants explicitly rather than one that rides along with pairing, and a stolen
  phone that does not have it. It costs a certificate field and a rule in `verify_chain`.

I would build the third if the root cannot be assumed online, and the first if it can. Either way the list's
`version` is per account and monotonic, so whatever signs must be the only thing that signs, or two signers race and
the loser's revocation is refused as stale.

## Why not simpler

- **"Let the hub revoke."** Then the hub is the account. Never, and it is the same answer as in `pairing.md`.
- **"Rely on expiry."** Expiry is what works with nobody online, which is why it was settled first, and it is
  measured in weeks. A person who unpairs a phone means now.
- **"Rotate on a timer instead."** A time-limited key bounds nothing here: a revoked device holding a valid
  certificate simply asks for the new key and passes the same check. Rotation is only a revocation when something
  tells the publisher who to refuse.
