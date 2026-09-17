// Which WebCrypto primitives does an MV3 extension SERVICE WORKER have? The extension's hub connector holds keys and
// encrypts there (keys never reach the page), so this, not the page's crypto, is what the E2E design can rely on.
//
// Usage: CHROME=/path/to/chrome node tools/webcrypto-probe/probe.mjs
// Prints one JSON object: each operation tried, and whether it worked (with the error when not).
import http from "node:http";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";

const CHROME = process.env.CHROME;
if (!CHROME) { console.error("set CHROME to a Chromium binary"); process.exit(2); }
const dir = fs.mkdtempSync(path.join(os.tmpdir(), "webcrypto-probe-"));

const server = http.createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
        res.end("ok");
        console.log(body);
        finish(0);
    });
});
server.listen(0, "127.0.0.1", () => {
    const port = server.address().port;
    const ext = path.join(dir, "ext");
    fs.mkdirSync(ext);
    fs.writeFileSync(path.join(ext, "manifest.json"), JSON.stringify({
        manifest_version: 3, name: "webcrypto-probe", version: "1", background: { service_worker: "sw.js" },
        host_permissions: [`http://127.0.0.1:${port}/*`],
    }));
    fs.writeFileSync(path.join(ext, "sw.js"), `
const s = crypto.subtle;
const results = { userAgent: navigator.userAgent };
async function t(name, fn) {
  try { const v = await fn(); results[name] = v === undefined ? true : v; }
  catch (e) { results[name] = "FAIL: " + (e && e.name) + ": " + (e && e.message); }
}
(async () => {
  const data = new TextEncoder().encode("probe");
  await t("Ed25519 generate+sign+verify", async () => {
    const k = await s.generateKey({ name: "Ed25519" }, false, ["sign", "verify"]);
    const sig = await s.sign({ name: "Ed25519" }, k.privateKey, data);
    return await s.verify({ name: "Ed25519" }, k.publicKey, sig, data);
  });
  await t("Ed25519 non-extractable private key", async () => {
    const k = await s.generateKey({ name: "Ed25519" }, false, ["sign", "verify"]);
    try { await s.exportKey("pkcs8", k.privateKey); return "exportable (unexpected)"; } catch { return "not exportable"; }
  });
  await t("X25519 generate+deriveBits", async () => {
    const a = await s.generateKey({ name: "X25519" }, false, ["deriveBits"]);
    const b = await s.generateKey({ name: "X25519" }, false, ["deriveBits"]);
    const x = new Uint8Array(await s.deriveBits({ name: "X25519", public: b.publicKey }, a.privateKey, 256));
    const y = new Uint8Array(await s.deriveBits({ name: "X25519", public: a.publicKey }, b.privateKey, 256));
    return x.every((v, i) => v === y[i]);
  });
  await t("X25519 raw public key export", async () => {
    const a = await s.generateKey({ name: "X25519" }, false, ["deriveBits"]);
    return (await s.exportKey("raw", a.publicKey)).byteLength;
  });
  await t("AES-256-GCM", async () => {
    const k = await s.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const c = await s.encrypt({ name: "AES-GCM", iv }, k, data);
    return new TextDecoder().decode(await s.decrypt({ name: "AES-GCM", iv }, k, c)) === "probe";
  });
  await t("ChaCha20-Poly1305", async () => {
    const k = await s.generateKey({ name: "ChaCha20-Poly1305" }, false, ["encrypt"]);
    return !!k;
  });
  await t("HKDF-SHA256", async () => {
    const base = await s.importKey("raw", crypto.getRandomValues(new Uint8Array(32)), "HKDF", false, ["deriveBits"]);
    return (await s.deriveBits({ name: "HKDF", hash: "SHA-256", salt: new Uint8Array(32), info: new Uint8Array(0) }, base, 256)).byteLength;
  });
  await t("HMAC-SHA256", async () => {
    const k = await s.generateKey({ name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    return (await s.sign("HMAC", k, data)).byteLength;
  });
  await t("SHA-512", async () => (await s.digest("SHA-512", data)).byteLength);
  await t("ECDSA P-256", async () => {
    const k = await s.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"]);
    const sig = await s.sign({ name: "ECDSA", hash: "SHA-256" }, k.privateKey, data);
    return await s.verify({ name: "ECDSA", hash: "SHA-256" }, k.publicKey, sig, data);
  });
  await t("CryptoKey storable in IndexedDB", () => new Promise((resolve, reject) => {
    const open = indexedDB.open("probe", 1);
    open.onupgradeneeded = () => open.result.createObjectStore("k");
    open.onerror = () => reject(open.error);
    open.onsuccess = async () => {
      const k = await s.generateKey({ name: "Ed25519" }, false, ["sign", "verify"]);
      const tx = open.result.transaction("k", "readwrite");
      tx.objectStore("k").put(k.privateKey, "priv");
      tx.oncomplete = () => {
        const get = open.result.transaction("k").objectStore("k").get("priv");
        get.onsuccess = async () => {
          const sig = await s.sign({ name: "Ed25519" }, get.result, data);
          resolve(await s.verify({ name: "Ed25519" }, k.publicKey, sig, data));
        };
        get.onerror = () => reject(get.error);
      };
      tx.onerror = () => reject(tx.error);
    };
  }));
  await fetch("http://127.0.0.1:${port}/", { method: "POST", body: JSON.stringify(results, null, 2) });
})();
`);
    const profile = path.join(dir, "profile");
    chrome = spawn(CHROME, ["--headless=new", `--user-data-dir=${profile}`, `--disable-extensions-except=${ext}`,
        `--load-extension=${ext}`, "--no-first-run", "--no-default-browser-check", "about:blank"], { stdio: "ignore" });
});
let chrome;
const timer = setTimeout(() => { console.error("timed out: the worker never reported"); finish(1); }, 30000);
function finish(code) { clearTimeout(timer); chrome?.kill(); server.close(); process.exit(code); }
