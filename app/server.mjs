// Key server node: the prototype's KeyServer running inside a Tinfoil enclave.
// The operator drives it over HTTPS (with a shared token); its log, watcher and
// phones are reached through the operator, who is not trusted: every answer is
// checked against the watcher's signatures and the hardware's attestations.
import http from "node:http";
import { timingSafeEqual } from "node:crypto";
import { readFileSync } from "node:fs";
import { unb64 } from "./crypto.mjs";
import { KeyServer } from "./keyServer.mjs";
import { remoteHost } from "./remoteHost.mjs";
import { tinfoilPlatform } from "./tinfoil.mjs";

const VERSION = "v0.2.2";
const config = JSON.parse(readFileSync(new URL("./config.json", import.meta.url), "utf8"));
const { HOST_URL, OPERATOR_TOKEN } = process.env;

let platform = null;
let server = null;
let started = false;

async function keyServer() {
  platform ??= await tinfoilPlatform();
  server ??= new KeyServer({ config, platform, host: remoteHost(HOST_URL, OPERATOR_TOKEN) });
  return server;
}

const authorized = (req) => {
  const given = Buffer.from(req.headers.authorization ?? "");
  const expected = Buffer.from(`Bearer ${OPERATOR_TOKEN}`);
  return Boolean(OPERATOR_TOKEN) && given.length === expected.length && timingSafeEqual(given, expected);
};

const routes = {
  "/rpc/start": async () => {
    const s = await keyServer();
    if (!started) { await s.start(); started = true; }
    return { measurement: s.measurement, version: VERSION };
  },
  "/rpc/pair": async ({ device }) => (await keyServer()).pair(device),
  "/rpc/install": async ({ device, build }) => (await keyServer()).install(device, { ...build, bytes: unb64(build.bytes) }),
  "/rpc/challenge": async () => (await keyServer()).handoffChallenge(),
  "/rpc/attest": async ({ nonce }) => (await keyServer()).attestation(nonce),
  "/rpc/handoff": async (body) => (await keyServer()).handoff(body),
  "/rpc/receive": async ({ sealed }) => (await keyServer()).receive(sealed),
};

const send = (res, status, value) => {
  res.writeHead(status, { "content-type": "application/json", "cache-control": "no-store" });
  res.end(JSON.stringify(value));
};

http.createServer(async (req, res) => {
  const { pathname } = new URL(req.url, "http://node");
  try {
    if (req.method === "GET" && pathname === "/health") {
      return send(res, 200, { ok: true, version: VERSION, measurement: platform?.measurement ?? null });
    }
    const route = req.method === "POST" && routes[pathname];
    if (!route) return send(res, 404, { error: "not found" });
    if (!authorized(req)) return send(res, 401, { error: "unauthorized" });
    let size = 0;
    const chunks = [];
    for await (const chunk of req) {
      size += chunk.length;
      if (size > 4_000_000) return send(res, 413, { error: "too large" });
      chunks.push(chunk);
    }
    const body = chunks.length ? JSON.parse(Buffer.concat(chunks)) : {};
    send(res, 200, { result: (await route(body)) ?? null });
  } catch (error) {
    send(res, 400, { error: error.message });
  }
}).listen(Number(process.env.PORT || 8080), "0.0.0.0");
