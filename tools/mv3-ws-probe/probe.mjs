// Does websocket traffic keep an MV3 service worker alive? Three variants, each its own Chromium + extension +
// server port, NO CDP attached (an attached debugger keeps workers alive and would spoil the result).
//   worker-sends : the SW sends a message every 20s
//   server-sends : the server sends a message every 20s, the SW only listens
//   idle         : socket open, no traffic (the control: must show eviction, or the harness proves nothing)
import http from "node:http";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { spawn } from "node:child_process";

// Usage: CHROME=/path/to/chrome [MINUTES=7] node tools/mv3-ws-probe/probe.mjs
// Any Chromium works; Playwright's is at `node -e 'console.log(require("playwright").chromium.executablePath())'`.
// Read the log: a variant whose boot id never changes and whose socket never closes stayed alive for the whole run.
const CHROME = process.env.CHROME;
if (!CHROME) { console.error("set CHROME to a Chromium binary"); process.exit(2); }
const MINUTES = Number(process.env.MINUTES || 7);
const here = fs.mkdtempSync(path.join(os.tmpdir(), "mv3-ws-probe-"));
const t0 = Date.now();
const stamp = () => ((Date.now() - t0) / 1000).toFixed(1).padStart(6) + "s";

function sendText(sock, s) {
    const b = Buffer.from(s);
    const head = b.length < 126 ? Buffer.from([0x81, b.length]) : Buffer.from([0x81, 126, b.length >> 8, b.length & 255]);
    sock.write(Buffer.concat([head, b]));
}

function server(name, port, serverSends) {
    const log = (m) => console.log(`${stamp()} [${name}] ${m}`);
    const srv = http.createServer();
    srv.on("upgrade", (req, sock) => {
        const key = req.headers["sec-websocket-key"];
        const acc = crypto.createHash("sha1").update(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").digest("base64");
        sock.write(`HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${acc}\r\n\r\n`);
        log("socket opened");
        let buf = Buffer.alloc(0);
        const iv = serverSends ? setInterval(() => sendText(sock, "server-ping"), 20000) : null;
        sock.on("data", (d) => {
            buf = Buffer.concat([buf, d]);
            while (buf.length >= 2) {
                const op = buf[0] & 15; let len = buf[1] & 127; let off = 2;
                if (len === 126) { if (buf.length < 4) return; len = buf.readUInt16BE(2); off = 4; }
                if (buf.length < off + 4 + len) return;
                const mask = buf.subarray(off, off + 4); const p = Buffer.from(buf.subarray(off + 4, off + 4 + len));
                for (let i = 0; i < p.length; i++) p[i] ^= mask[i % 4];
                buf = buf.subarray(off + 4 + len);
                if (op === 1) log(`recv ${p.toString()}`);
                else if (op === 8) log("close frame");
                else if (op === 9) sock.write(Buffer.from([0x8a, 0]));
            }
        });
        sock.on("close", () => { if (iv) clearInterval(iv); log("socket CLOSED"); });
        sock.on("error", () => {});
    });
    srv.listen(port, "127.0.0.1");
    return srv;
}

function extension(name, port, workerSends) {
    const dir = path.join(here, "ext-" + name);
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, "manifest.json"), JSON.stringify({
        manifest_version: 3, name: "ws-probe-" + name, version: "1", background: { service_worker: "sw.js" },
    }));
    fs.writeFileSync(path.join(dir, "sw.js"), `
const boot = Math.random().toString(16).slice(2, 8);
const born = Date.now();
function open() {
  const ws = new WebSocket("ws://127.0.0.1:${port}");
  ws.onopen = () => {
    ws.send("hello boot=" + boot + " " + navigator.userAgent.match(/Chrome\\/[\\d.]+/)[0]);
    ${workerSends ? `setInterval(() => ws.send("tick boot=" + boot + " alive=" + Math.round((Date.now() - born) / 1000) + "s"), 20000);` : ""}
  };
  ws.onmessage = (e) => { ${workerSends ? "" : `ws.send("got " + e.data + " boot=" + boot + " alive=" + Math.round((Date.now() - born) / 1000) + "s");`} };
  ws.onclose = () => setTimeout(open, 1000);
}
open();
`);
    // idle variant: the onmessage echo never fires (server sends nothing), so the socket is silent.
    return dir;
}

const variants = [
    { name: "worker-sends", port: 18731, workerSends: true, serverSends: false },
    { name: "server-sends", port: 18732, workerSends: false, serverSends: true },
    { name: "idle", port: 18733, workerSends: false, serverSends: false },
];
const procs = [];
for (const v of variants) {
    server(v.name, v.port, v.serverSends);
    const ext = extension(v.name, v.port, v.workerSends);
    const profile = fs.mkdtempSync(path.join(here, "profile-" + v.name + "-"));
    procs.push(spawn(CHROME, [
        "--headless=new", `--user-data-dir=${profile}`, `--disable-extensions-except=${ext}`, `--load-extension=${ext}`,
        "--no-first-run", "--no-default-browser-check", "about:blank",
    ], { stdio: "ignore" }));
}
setTimeout(() => {
    for (const p of procs) p.kill();
    console.log(`${stamp()} done (scratch files in ${here})`);
    process.exit(0);
}, MINUTES * 60000);
