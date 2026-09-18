# Proposal: revoking a device, once it already holds keys

**Status: proposed, nothing built.** The argument it continues is window-ml `tmp/hub-revocation-and-headless-pairing.md`
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

## What is open, and what I would like the UI session to decide

These are the questions where the runtime's shape decides mine, so I would rather ask than guess.

- **Who may sign a list?** The account root is obvious. A device holding `may_pair` is the interesting case: it can
  create a device, so it is odd if it cannot un-create one, but a delegate revoking something the root granted is a
  wider power than delegating. My inclination is the root only, with the `admin` scope being what lets a phone ASK
  the runtime to do it (`device.revoke`), rather than the phone signing anything itself.
- **How does a publisher that was offline catch up?** It comes back with an old version and nothing tells it. Either
  it asks on connect (a `box.grant` answer could carry the current version, which is the cheap version), or the
  runtime pushes to whatever presence says is there. The first is one field; the second is a protocol.
- **Does `device.revoke` return before or after the publishers have been told?** The rotation rollup we agreed
  answers "after, but tell the person what is still owed", and that is what the `rotation` field on `DeviceInfo`
  renders. This proposal is the thing that makes that field non-zero for a while.
- **Is a box connector a publisher the runtime knows about?** It is on the account's paired-device list, so it is in
  `device.list`, but the runtime has no other relationship with it. Telling it about a revocation means sending it a
  sealed command, which the runtime can do from the list alone.

## Why not simpler

- **"Let the hub revoke."** Then the hub is the account. Never, and it is the same answer as in `pairing.md`.
- **"Rely on expiry."** Expiry is what works with nobody online, which is why it was settled first, and it is
  measured in weeks. A person who unpairs a phone means now.
- **"Rotate on a timer instead."** A time-limited key bounds nothing here: a revoked device holding a valid
  certificate simply asks for the new key and passes the same check. Rotation is only a revocation when something
  tells the publisher who to refuse.
