// A stand-in for iOS pairing, shaped like the real thing:
//  - pairing: both sides exchange long-term Ed25519 keys and ephemeral X25519
//    keys, and prove they hold the same short code the user typed in;
//  - sessions: both sides prove their long-term keys over fresh ephemeral keys,
//    derive session keys, and everything after is encrypted (AES-256-GCM).
// Messages are JSON objects over a `channel` ({ send(obj), recv() }).
//
// Not iOS's real protocol. In particular, pairing uses an HMAC over the code,
// which a man in the middle could brute-force offline; iOS uses SRP, which it can't.
import { createCipheriv, createDecipheriv, createHmac, diffieHellman, generateKeyPairSync, hkdfSync, timingSafeEqual } from "node:crypto";
import { canonical, importPublic, verifySignature } from "./crypto.mjs";

/** A channel over any transport: `deliver` inbound messages, `recv` them in order. */
export function makeChannel(send) {
  const queue = [];
  const waiting = [];
  let closed = null;
  return {
    send,
    deliver(message) {
      if (waiting.length) waiting.shift().resolve(message);
      else queue.push(message);
    },
    /** Put a message back, to be received next. */
    unshift(message) {
      queue.unshift(message);
    },
    close(error = new Error("the connection closed")) {
      closed = error;
      while (waiting.length) waiting.shift().reject(error);
    },
    recv(timeoutMs = 120_000) {
      if (queue.length) return Promise.resolve(queue.shift());
      if (closed) return Promise.reject(closed);
      return new Promise((resolve, reject) => {
        const entry = { resolve: (m) => { clearTimeout(timer); resolve(m); }, reject: (e) => { clearTimeout(timer); reject(e); } };
        const timer = setTimeout(() => { waiting.splice(waiting.indexOf(entry), 1); reject(new Error("timed out waiting for the phone")); }, timeoutMs);
        waiting.push(entry);
      });
    },
  };
}

async function expect(channel, type) {
  const message = await channel.recv();
  if (message?.t === "error") throw new Error(message.reason);
  if (message?.t !== type) throw new Error(`expected ${type}, got ${message?.t}`);
  return message;
}

function ephemeral() {
  const { publicKey, privateKey } = generateKeyPairSync("x25519");
  return {
    publicKey: publicKey.export({ type: "spki", format: "der" }).toString("base64"),
    shared: (peer) => diffieHellman({ privateKey, publicKey: importPublic(peer) }),
  };
}

const hkdf = (secret, salt, info, length = 32) => Buffer.from(hkdfSync("sha256", secret, salt, info, length));
const mac = (key, label) => createHmac("sha256", key).update(label).digest("base64");
const sameMac = (a, b) => typeof a === "string" && a.length === b.length && timingSafeEqual(Buffer.from(a), Buffer.from(b));

// ---------- Pairing ----------

/** Host side. Returns the phone's long-term public key. */
export async function hostPair(channel, hostKey, code) {
  const eph = ephemeral();
  channel.send({ t: "pair-start", host: hostKey.publicKey, eph: eph.publicKey });
  const reply = await expect(channel, "pair-reply");
  const transcript = canonical({ host: hostKey.publicKey, hostEph: eph.publicKey, phone: reply.phone, phoneEph: reply.eph });
  const key = hkdf(eph.shared(reply.eph), code, `pair|${transcript}`);
  channel.send({ t: "pair-confirm", mac: mac(key, "host"), sig: hostKey.sign(`pair-host|${transcript}`) });
  const done = await expect(channel, "pair-done");
  if (!sameMac(done.mac, mac(key, "phone"))) throw new Error("the phone used a different code");
  if (!verifySignature(reply.phone, `pair-phone|${transcript}`, done.sig)) throw new Error("the phone's signature is invalid");
  return reply.phone;
}

/** Phone side. `askCode` asks the user for the code. Returns the host's long-term public key. */
export async function phonePair(channel, phoneKey, askCode) {
  const start = await expect(channel, "pair-start");
  const eph = ephemeral();
  channel.send({ t: "pair-reply", phone: phoneKey.publicKey, eph: eph.publicKey });
  const confirm = await expect(channel, "pair-confirm");
  const code = await askCode();
  const transcript = canonical({ host: start.host, hostEph: start.eph, phone: phoneKey.publicKey, phoneEph: eph.publicKey });
  const key = hkdf(eph.shared(start.eph), code, `pair|${transcript}`);
  if (!sameMac(confirm.mac, mac(key, "host"))) {
    channel.send({ t: "error", reason: "the code didn't match" });
    throw new Error("the code didn't match");
  }
  if (!verifySignature(start.host, `pair-host|${transcript}`, confirm.sig)) throw new Error("the computer's signature is invalid");
  channel.send({ t: "pair-done", mac: mac(key, "phone"), sig: phoneKey.sign(`pair-phone|${transcript}`) });
  return start.host;
}

// ---------- Sessions ----------

function encrypted(channel, sendKey, receiveKey) {
  let sent = 0;
  let received = 0;
  const nonce = (n) => { const iv = Buffer.alloc(12); iv.writeUInt32BE(n, 8); return iv; };
  return {
    send(message) {
      const cipher = createCipheriv("aes-256-gcm", sendKey, nonce(sent));
      const c = Buffer.concat([cipher.update(JSON.stringify(message)), cipher.final(), cipher.getAuthTag()]);
      channel.send({ t: "enc", n: sent++, c: c.toString("base64") });
    },
    async recv() {
      const frame = await expect(channel, "enc");
      if (frame.n !== received) throw new Error("out-of-order message");
      const bytes = Buffer.from(frame.c, "base64");
      const decipher = createDecipheriv("aes-256-gcm", receiveKey, nonce(received++));
      decipher.setAuthTag(bytes.subarray(-16));
      return JSON.parse(Buffer.concat([decipher.update(bytes.subarray(0, -16)), decipher.final()]));
    },
  };
}

/** Host side: prove `hostKey`, check the phone is `phoneIdentity`, return an encrypted session. */
export async function hostSession(channel, hostKey, phoneIdentity) {
  const eph = ephemeral();
  channel.send({ t: "session-start", host: hostKey.publicKey, eph: eph.publicKey });
  const reply = await expect(channel, "session-reply");
  if (reply.phone !== phoneIdentity) throw new Error("this isn't the phone that was paired");
  const transcript = canonical({ host: hostKey.publicKey, hostEph: eph.publicKey, phone: reply.phone, phoneEph: reply.eph });
  if (!verifySignature(reply.phone, `session-phone|${transcript}`, reply.sig)) throw new Error("the phone's signature is invalid");
  channel.send({ t: "session-confirm", sig: hostKey.sign(`session-host|${transcript}`) });
  const secret = eph.shared(reply.eph);
  return encrypted(channel, hkdf(secret, "", `host->phone|${transcript}`), hkdf(secret, "", `phone->host|${transcript}`));
}

/** Phone side: accept only a trusted host key, prove `phoneKey`, return an encrypted session. */
export async function phoneSession(channel, phoneKey, trusted) {
  const start = await expect(channel, "session-start");
  if (!trusted.includes(start.host)) {
    channel.send({ t: "error", reason: "this phone isn't paired with that key" });
    throw new Error("a computer this phone isn't paired with tried to connect");
  }
  const eph = ephemeral();
  const transcript = canonical({ host: start.host, hostEph: start.eph, phone: phoneKey.publicKey, phoneEph: eph.publicKey });
  channel.send({ t: "session-reply", phone: phoneKey.publicKey, eph: eph.publicKey, sig: phoneKey.sign(`session-phone|${transcript}`) });
  const confirm = await expect(channel, "session-confirm");
  if (!verifySignature(start.host, `session-host|${transcript}`, confirm.sig)) throw new Error("the computer's signature is invalid");
  const secret = eph.shared(start.eph);
  return { host: start.host, ...encrypted(channel, hkdf(secret, "", `phone->host|${transcript}`), hkdf(secret, "", `host->phone|${transcript}`)) };
}
