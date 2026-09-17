# Finding: websocket traffic keeps an MV3 service worker alive

**Answered 2026-09-17**, on Chrome for Testing 151.0.7922.34 (headless, macOS arm64). This closes the first open
question in `RUNTIME_HUB.md`: the extension's hub connector can hold its websocket in the service worker, and does
not need the offscreen document.

## Result

| Variant | Traffic | Worker |
| --- | --- | --- |
| `worker-sends` | the worker sends a message every 20 s | alive for the whole 7 minutes: one boot, socket never closed |
| `server-sends` | the server sends every 20 s, the worker only receives | alive for the whole 7 minutes: one boot, socket never closed |
| `idle` (control) | socket open, nothing sent | evicted at 30 s, socket closed |

- **Either direction counts.** A message received resets the idle timer as well as one sent, so a subscriber that
  only listens (a runtime waiting for commands, with the hub sending periodic pings) stays alive.
- **No five-minute cap applied.** Both traffic variants passed 400 s on one boot.
- **The control is what makes this mean anything.** Without it, a harness that kept workers alive for another reason
  would read as the same result. Eviction at exactly 30 s shows the ordinary idle rule was in force.

## Method

`tools/mv3-ws-probe/probe.mjs`: three unpacked extensions, each in its own headless Chromium with its own profile and
a local no-dependency websocket server. The worker reports a random boot id on connect, so a restart shows as a new
id. **No debugger or Playwright is attached**: an attached CDP session keeps workers alive and would have made every
variant look immortal.

## What it means for the connector

- Keep the socket in the service worker, and send or expect traffic at least every 20 to 25 seconds while connected;
  a hub ping on that interval is enough.
- The worker can still die (browser restart, extension reload, a crash, Chrome's memory pressure), so the connector
  reconnects and resubscribes from its last position on every boot, as the session contract's `since` already
  provides for.
- Re-run the probe on a new major Chrome before relying on this: it is browser behaviour, not a published guarantee.
