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
docker compose exec hub wmlhub accounts list     # registered accounts
```

To withdraw an invite before it is used, delete its file: `invite list` shows the start of its name, and the file is
in the `invites` directory of the data volume.

## Registration

| Mode | Who can register a new account | Use when |
| --- | --- | --- |
| `invite` (default) | whoever holds an invite you created | almost always, including on Tailscale |
| `open` | anyone who can reach the hub, limited to 3 new accounts per source address and 60 overall per hour | a hub you deliberately offer to others |

Registration only decides who may *use* the hub's relay. It never gives anyone access to your sessions: those are
end-to-end encrypted, and your runtimes only accept commands from devices you paired.

**Behind Caddy or any other proxy**, every connection appears to come from the proxy's address, so the per-address
limit acts as one shared limit. That is fine for `invite`; for `open`, lower `WMLHUB_OPEN_TOTAL` to what you are
willing to admit per hour. Both limits are environment variables (`WMLHUB_OPEN_PER_ADDRESS`, `WMLHUB_OPEN_TOTAL`).

## Backups and upgrades

- **Everything worth keeping is in the `wmlhub-data` volume**: registered accounts and outstanding invites. Losing it
  means accounts must register again (with new invites); no messages or sessions are lost, since the hub never held
  any.
- **Upgrade**: `git pull && docker compose up -d --build`.

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
