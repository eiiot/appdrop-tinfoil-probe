// The key server's front door. The operator calls it over HTTPS, and opens a
// WebSocket per phone operation. On that WebSocket, { to: "phone" } and
// { from: "phone" } messages are the pipe, relayed to and from the phone;
// { to: "operator" } and { from: "operator" } messages are between the
// operator and the key server (the pairing code, the IPA's bytes, the result).
import http from "node:http";
import { timingSafeEqual } from "node:crypto";
import { WebSocketServer } from "ws";
import { makeChannel } from "../shared/phoneProtocol.mjs";

export function createServer({ keyServer, token, version }) {
  const authorized = (offered) => {
    const given = Buffer.from(String(offered ?? ""));
    const expected = Buffer.from(String(token ?? ""));
    return Boolean(token) && given.length === expected.length && timingSafeEqual(given, expected);
  };
  const send = (res, status, value) => {
    res.writeHead(status, { "content-type": "application/json", "cache-control": "no-store" });
    res.end(JSON.stringify(value));
  };

  const routes = {
    "/rpc/forget": ({ device }) => keyServer.forget(device),
    "/rpc/challenge": () => keyServer.handoffChallenge(),
    "/rpc/attest": ({ nonce }) => keyServer.attestation(nonce),
    "/rpc/handoff": ({ successor, approvals }) => keyServer.handoff(successor, approvals),
    "/rpc/receive": ({ sealed }) => keyServer.receive(sealed),
  };

  const server = http.createServer(async (req, res) => {
    const { pathname } = new URL(req.url, "http://key-server");
    try {
      if (req.method === "GET" && pathname === "/health") return send(res, 200, { version, ...keyServer.status });
      const route = req.method === "POST" && routes[pathname];
      if (!route) return send(res, 404, { error: "not found" });
      if (!authorized(req.headers.authorization?.replace(/^Bearer /, ""))) return send(res, 401, { error: "unauthorized" });
      const chunks = [];
      for await (const chunk of req) chunks.push(chunk);
      send(res, 200, { result: (await route(chunks.length ? JSON.parse(Buffer.concat(chunks)) : {})) ?? null });
    } catch (error) {
      send(res, 400, { error: error.message });
    }
  });

  const sockets = new WebSocketServer({
    noServer: true,
    maxPayload: 4 * 1024 * 1024,
    handleProtocols: (protocols) => (protocols.has("ks") ? "ks" : false),
  });

  server.on("upgrade", (req, socket, head) => {
    const url = new URL(req.url, "http://key-server");
    const offered = String(req.headers["sec-websocket-protocol"] ?? "").split(",").map((p) => p.trim());
    if (!["/rpc/pair", "/rpc/install", "/rpc/check"].includes(url.pathname) || offered[0] !== "ks" || !authorized(offered[1])) {
      socket.end("HTTP/1.1 401 Unauthorized\r\n\r\n");
      return;
    }
    sockets.handleUpgrade(req, socket, head, (ws) => operate(ws, url));
  });

  async function operate(ws, url) {
    const toOperator = (message) => ws.readyState === ws.OPEN && ws.send(JSON.stringify({ to: "operator", ...message }));
    const phone = makeChannel((data) => ws.readyState === ws.OPEN && ws.send(JSON.stringify({ to: "phone", data })));
    const ipaChunks = makeChannel(() => {});
    ws.on("message", (raw) => {
      let message;
      try { message = JSON.parse(raw); } catch { return; }
      if (message.from === "phone") phone.deliver(message.data);
      else if (message.from === "operator" && message.chunk) ipaChunks.deliver(Buffer.from(message.chunk, "base64"));
      else if (message.from === "operator" && message.end) ipaChunks.deliver(null);
    });
    ws.on("close", () => { phone.close(); ipaChunks.close(); });

    const device = url.searchParams.get("device");
    try {
      let result;
      if (url.pathname === "/rpc/pair") {
        result = await keyServer.pair(device, phone, (code) => toOperator({ code }));
      } else if (url.pathname === "/rpc/check") {
        result = await keyServer.check(device, phone);
      } else {
        const chunks = (async function* () {
          for (;;) {
            const chunk = await ipaChunks.recv(600_000);
            if (chunk === null) return;
            yield chunk;
          }
        })();
        toOperator({ ready: true });
        result = await keyServer.install(device, {
          name: url.searchParams.get("name"),
          version: url.searchParams.get("version"),
          hash: url.searchParams.get("hash"),
          size: Number(url.searchParams.get("size")),
          chunks,
        }, phone);
      }
      toOperator({ result });
    } catch (error) {
      toOperator({ error: error.message });
    } finally {
      setTimeout(() => ws.close(), 200);
    }
  }

  return server;
}
