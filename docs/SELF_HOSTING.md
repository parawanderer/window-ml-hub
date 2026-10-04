# Running your own hub

For someone comfortable with Docker and not necessarily with Rust. You need Docker (with Compose) and this
repository; nothing else is installed on the machine.

**Be aware of where the project is.** The hub runs, authenticates and relays, but the window.ml extension does not
connect to it yet (that is the last step on [`ROADMAP.md`](ROADMAP.md)). Set one up now to try it or to get ready;
there is nothing to point a browser at yet.

## What the hub is, in one paragraph

A small relay. Browsers running the window.ml extension and your devices (a phone) connect out to it; it passes
encrypted messages between them and cannot read them. It keeps nothing on disk except which accounts may use it and
the invites you have issued. See the [README](../README.md) for how it fits with the extension.

## 1. Choose how people will reach it

The hub speaks plain websockets on port 8787 and **expects something in front of it to provide TLS**. Pick one:

| Option | Good for | TLS from | Hub name |
| --- | --- | --- | --- |
| **Tailscale** | just you and your devices | Tailscale | `<machine>.<tailnet>.ts.net` |
| **Caddy** | reachable from anywhere, a domain you control | Let's Encrypt, automatic | your domain, such as `hub.example.com` |
| **Local only** | trying it out | none (loopback) | anything, such as `localhost` |

The **hub name** matters: it is signed into every login, so it must be exactly the hostname clients use to reach the
hub (no `https://`, no port). A mismatch shows up as logins refused with "hello did not verify".

## 2. Configure

```bash
git clone https://github.com/parawanderer/window-ml-hub.git
cd window-ml-hub
cp .env.example .env
```

Edit `.env`:

- `WMLHUB_HUB_NAME`: the hub name from the table above.
- `WMLHUB_REGISTRATION`: `invite` (the default) or `open`, see [Registration](#registration).

## 3. Start it

### Tailscale (or local only)

```bash
docker compose up -d
docker compose logs hub          # expect: serving ... registration=Invite
```

The hub is now on `127.0.0.1:8787` of this machine. For Tailscale, expose it to your tailnet with HTTPS:

```bash
tailscale serve --bg --https=443 http://127.0.0.1:8787
```

Clients then connect to `wss://<machine>.<tailnet>.ts.net`.

**Serve and HTTPS certificates have to be enabled for the tailnet first, and the failure is a hang rather than an
error.** The command prints an enable link and waits for somebody to follow it; it does not exit non-zero, and
piping it into `head` or `tail` holds the link back until an EOF that never comes, so what you see is a command that
never returns. Enabling it is a tailnet-admin action, so whoever is setting the hub up may not be able to finish
this step at all. The check that needs no running command is:

```bash
tailscale status --json | jq .CertDomains     # null = HTTPS certificates are off for this tailnet
```

Enabling HTTPS also publishes your machine names to the public Certificate Transparency logs, which is a decision
rather than a step.

**Any port works, and the hub's name is not the port.** `--https=8787` keeps 443 free for whatever else may want
the bare name later. `WMLHUB_HUB_NAME` stays the bare hostname either way, because that is what is signed into
every login; only the URL clients are configured with carries the port
(`wss://<machine>.<tailnet>.ts.net:8787`).

**A plain `GET` to the hub returns 502, and that is the hub working.** It drops anything that is not a websocket
upgrade, and the proxy reports the dropped upstream, so a browser visit is the one check you should not trust. Ask
for the upgrade instead:

```bash
curl -s -i -N --http1.1 -H 'Connection: Upgrade' -H 'Upgrade: websocket' \
  -H 'Sec-WebSocket-Version: 13' -H 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==' \
  https://<name>:<port>/ | head -1          # want: HTTP/1.1 101 Switching Protocols
```

### Caddy (public, automatic HTTPS)

Point a DNS record for your hub name at the machine, open ports 80 and 443, then:

```bash
cd deploy/caddy
cp ../../.env .env
docker compose up -d
docker compose logs caddy        # expect a certificate to be obtained for your hub name
```

Clients connect to `wss://<your hub name>`.

## 4. Let yourself in

With registration `invite`, a new account needs an invite. Create one (from the directory whose compose file you
started):

```bash
docker compose exec hub wmlhub invite create
```

It prints a token like `wmlhub-invite-4f1c...`. It works **once**, for **7 days** (`--ttl-hours` to change that), and
only the first account to use it is registered. Other devices of that same account need no invite.

```bash
docker compose exec hub wmlhub invite list       # outstanding invites
docker compose exec hub wmlhub accounts list     # registered accounts, and each one's revocation signer
```

To withdraw an invite before it is used, delete its file: `invite list` shows the start of its name, and the file is
in the `invites` directory of the data volume.

### One device signs an account's revocations

An account removes a lost or stolen device by publishing a signed revocation list, and **exactly one** of its devices
may sign that list (`may_revoke`, granted at pairing). The hub holds the account to it: a second device presenting
that grant is refused its login, with "another device signs this account's revocations; pair this one again without
that grant". The reason is not tidiness. A list's version is a timestamp, so two signers race, and the one whose
clock trails has its removal refused as stale: the device you were removing stays.

`accounts list` says which principal signs for each account, and until when: a grant lasts 90 days, and once it has
run out the record is spent, so the next device granted `may_revoke` takes the account with nothing for you to do.
When the signing device is gone and you would rather not wait, forget it:

```bash
docker compose exec hub wmlhub accounts clear-revoker <account-id>
```

## Registration

| Mode | Who can register a new account | Use when |
| --- | --- | --- |
| `invite` (default) | whoever holds an invite you created | almost always, including on Tailscale |
| `open` | anyone who can reach the hub, limited to 3 new accounts per source address and 60 overall per hour | a hub you deliberately offer to others |

Registration only decides who may *use* the hub's relay. It never gives anyone access to your sessions: those are
end-to-end encrypted, and your runtimes only accept commands from devices you paired.

**Behind Caddy or any other proxy**, every connection appears to come from the proxy's address, so every
per-address limit becomes one limit shared by everybody. Tell the hub what is in front of it and it reads the real
client address instead:

```bash
WMLHUB_TRUSTED_PROXIES=172.16.0.0/12      # the docker network Caddy is on; 127.0.0.1 if it shares the host
```

`X-Forwarded-For` is a header anybody can write, so the hub reads it **only** from an address listed here, and the
client is the rightmost entry that is not itself listed. Without that rule the header would be a way to be rate
limited as somebody else.

Setting it also turns the connection rate on (60 a minute per client, `WMLHUB_CONNECTIONS_PER_MINUTE`), because
naming your proxies is what makes a per-address limit mean anything. With nothing named, the hub cannot tell an
unnamed proxy from no proxy at all, so it leaves the limit off and says so at startup; if nothing is in front of
your hub, set the rate yourself.

For `open` registration, also lower `WMLHUB_OPEN_TOTAL` to what you are willing to admit per hour
(`WMLHUB_OPEN_PER_ADDRESS` is per client once your proxies are named).

## Backups and upgrades

- **Everything worth keeping is in the `wmlhub-data` volume**: registered accounts, outstanding invites, and which
  device signs each account's revocations. Losing it means accounts must register again (with new invites); no
  messages or sessions are lost, since the hub never held any.
- **Upgrade**: `git pull && docker compose up -d --build`. The volume is kept, so nothing re-registers.

### Upgrading without losing anybody's sessions

You will not. A session's history lives on the RUNTIME that ran it, never here, so there is nothing on the hub to
preserve and no migration to run. Concretely, an upgrade costs the seconds the container takes to come back:

- **Every device reconnects on its own**, retrying with a backoff capped at half a minute. Nobody signs in again.
- **Nothing re-pairs.** Certificates and the account's channel key live in the devices; the hub holds no device keys
  and cannot issue one. Even losing the whole volume costs one invite per account, not a re-pairing.
- **A client watching a live session** is told the stream restarted and pages the history back from the runtime
  (`session.backfill`), because the hub's retained ring is in memory and a restart empties it. What it shows is the
  runtime's own record, so a transcript survives even though the ring did not. If the runtime is asleep at that
  moment, the client keeps what it has and fills in when the runtime is back.
- **Each stream gets a fresh key**, which is how a new connection behaves anyway: a runtime generates one per stream
  per connection and grants it again to every device present.

So the only reason to delete an account is to change something the account itself holds, and session history is not
it.

**It is not without interruption, though.** Measured twice on a real box (v0.4.0 to v0.4.2, then to v0.4.3): the
container is recreated and a runtime reconnects 0.7 to 1.0 seconds after the hub is serving again. What is not
preserved is the CONNECTION, so anything measuring how long a client has been connected starts again from the
restart. If somebody is watching a long-lived connection, tell them before you upgrade: a figure read out of a log
that has a restart in it is not the figure they think it is.

**One upgrade has a visible consequence**, from the version that began enforcing one revocation signer per account:
the hub starts with no record of who signs, so the first device that logs in holding `may_revoke` claims the account.
On an account where one device holds it, that is simply correct. On an account that acquired two before the rule
existed, the other device is refused its login with "another device signs this account's revocations". It is loud,
it affects nothing else, and the fix touches no sessions:

1. Pair the browser that should NOT sign again, without that grant.
2. `wmlhub accounts clear-revoker <account-id>`.
3. Let the device that should sign reconnect; it claims the account within half a minute.

`wmlhub accounts list` shows who claimed it, which is how you tell whether any of this applies to you.

## All settings

Every setting is an environment variable. The compose file sets the first four; the rest have defaults.

| Variable | Default | Meaning |
| --- | --- | --- |
| `WMLHUB_HUB_NAME` | (required) | the hostname clients use; signed into every login |
| `WMLHUB_REGISTRATION` | `invite` | `invite` or `open` |
| `WMLHUB_LISTEN` | `0.0.0.0:8787` in the image | address inside the container |
| `WMLHUB_STATE_DIR` | `/data` in the image | where accounts and invites are kept |
| `WMLHUB_OPEN_PER_ADDRESS` | `3` | open mode: new accounts per source address per hour |
| `WMLHUB_OPEN_TOTAL` | `60` | open mode: new accounts overall per hour |
| `WMLHUB_ACCOUNT_BYTES_PER_SECOND` | `8388608` (8 MiB) | work one account may cause per second; past it the hub reads that account more slowly, dropping nothing |
| `WMLHUB_ACCOUNT_BURST_BYTES` | `33554432` (32 MiB) | how much of that work may arrive at once |
| `WMLHUB_SHARDS` | `0` (four per core) | independent relay locks; accounts are spread across them |
| `WMLHUB_MAX_PENDING_SOCKETS` | `256` | sockets that have not authenticated yet, at once |
| `WMLHUB_MAX_PAIRING_SOCKETS` | `64` | devices being paired at once; one holds its place while a person carries a code |
| `WMLHUB_MAX_HELLO_BYTES` | `65536` | the largest first message accepted, before anything in it is decoded |
| `WMLHUB_CONNECTIONS_PER_MINUTE` | `0` (off) | connections one source address may open; leave off behind a proxy, set it when the hub is exposed directly |
| `WMLHUB_CONNECTION_BURST` | `0` | how much of that allowance may be spent at once |

`docker compose exec hub wmlhub serve --help` prints the same list.

## Troubleshooting

| Symptom | Likely cause |
| --- | --- |
| compose refuses to start: "set WMLHUB_HUB_NAME" | `.env` missing, or not in the directory you ran compose from |
| logins refused, "hello did not verify" | the hub name in `.env` differs from the hostname clients connect to; or a device certificate expired |
| "this hub needs an invite to register an account" | registration is `invite` and the account is new: create an invite |
| "invite not valid" | already used, expired, or mistyped |
| "too many new accounts; try later" | open registration limit reached |
| clients cannot connect at all through Caddy | DNS not pointing at the machine yet, or ports 80/443 closed; check `docker compose logs caddy` |
| permission denied on `/data` | a bind mount owned by another user replaced the named volume; use the named volume from the compose file, or `chown 10001` the directory |
