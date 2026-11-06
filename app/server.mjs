// Key server node, step 1: prove which build this is and which keys it holds.
// GET /attestation?challenge=<64 hex> asks the hardware for a fresh attestation
// whose nonce is SHA-256 of this node's public keys and the caller's challenge,
// so the attestation vouches for exactly these keys, right now.
import http from "node:http";
import { canonical, sha256, signingKey, boxKey } from "./crypto.mjs";

const identity = signingKey();
const box = boxKey();
const SOCKET = "/tinfoil/attestation.sock";

function fromSocket(path) {
  return new Promise((resolve, reject) => {
    const request = http.get({ socketPath: SOCKET, path, timeout: 15000 }, (response) => {
      const chunks = [];
      response.on("data", (chunk) => chunks.push(chunk));
      response.on("end", () => resolve({ status: response.statusCode, body: Buffer.concat(chunks).toString() }));
    });
    request.on("timeout", () => request.destroy(new Error("attestation socket timed out")));
    request.on("error", reject);
  });
}

const send = (res, status, value) => {
  res.writeHead(status, { "content-type": "application/json", "cache-control": "no-store" });
  res.end(JSON.stringify(value));
};

http.createServer(async (req, res) => {
  const url = new URL(req.url, "http://node");
  try {
    if (req.method === "GET" && url.pathname === "/health") {
      return send(res, 200, { ok: true, identity: identity.publicKey, boxKey: box.publicKey });
    }
    if (req.method === "GET" && url.pathname === "/attestation") {
      const challenge = url.searchParams.get("challenge") ?? "";
      if (!/^[0-9a-f]{64}$/.test(challenge)) return send(res, 400, { error: "challenge must be 64 hex characters" });
      const userData = { identity: identity.publicKey, boxKey: box.publicKey, challenge };
      const nonce = sha256(canonical(userData)).toString("hex");
      const { status, body } = await fromSocket(`/.well-known/tinfoil-attestation?nonce=${nonce}`);
      let attestation = body;
      try { attestation = JSON.parse(body); } catch {}
      return send(res, status === 200 ? 200 : 502, { userData, nonce, socketStatus: status, attestation });
    }
    send(res, 404, { error: "not found" });
  } catch (error) {
    send(res, 500, { error: error.message });
  }
}).listen(Number(process.env.PORT || 8080), "0.0.0.0");
