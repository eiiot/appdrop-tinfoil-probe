// Small wrappers over node:crypto. Keys travel as base64 SPKI; signatures as base64.
import {
  createCipheriv, createDecipheriv, createHash, createPrivateKey, createPublicKey, diffieHellman,
  generateKeyPairSync, hkdfSync, randomBytes, sign, verify,
} from "node:crypto";

export const b64 = (bytes) => Buffer.from(bytes).toString("base64");
export const unb64 = (text) => Buffer.from(text, "base64");
export const b64url = (bytes) => Buffer.from(bytes).toString("base64url");

/** JSON with sorted keys, so the same value always hashes the same. */
export function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value).filter((k) => value[k] !== undefined).sort()
      .map((k) => `${JSON.stringify(k)}:${canonical(value[k])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

export function sha256(...parts) {
  const hash = createHash("sha256");
  for (const part of parts) hash.update(typeof part === "string" ? part : Buffer.from(part));
  return hash.digest();
}

export const digest = (value) => sha256(canonical(value)).toString("hex");

const exportPublic = (key) => b64(key.export({ type: "spki", format: "der" }));
export const importPublic = (text) => createPublicKey({ key: unb64(text), format: "der", type: "spki" });

/** An Ed25519 signing key. The private half stays in this closure. */
export function signingKey() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return {
    publicKey: exportPublic(publicKey),
    sign: (data) => b64(sign(null, Buffer.from(data), privateKey)),
    // Only for moving a key between key servers, sealed; never logged or sent in the clear.
    exportPrivate: () => b64(privateKey.export({ type: "pkcs8", format: "der" })),
  };
}

export function signingKeyFrom(pkcs8) {
  const privateKey = createPrivateKey({ key: unb64(pkcs8), format: "der", type: "pkcs8" });
  return {
    publicKey: exportPublic(createPublicKey(privateKey)),
    sign: (data) => b64(sign(null, Buffer.from(data), privateKey)),
    exportPrivate: () => pkcs8,
  };
}

export function verifySignature(publicKey, data, signature) {
  try {
    return verify(null, Buffer.from(data), importPublic(publicKey), unb64(signature));
  } catch {
    return false;
  }
}

/** An X25519 key that can open boxes sealed to its public half. */
export function boxKey() {
  const { publicKey, privateKey } = generateKeyPairSync("x25519");
  const recipient = exportPublic(publicKey);
  return { publicKey: recipient, open: (box) => openBox(box, privateKey, recipient) };
}

const boxSecret = (shared, ephemeral, recipient) =>
  Buffer.from(hkdfSync("sha256", shared, Buffer.alloc(0), `sealed-box|${ephemeral}|${recipient}`, 32));

/** Encrypt to a recipient's X25519 public key; only its holder can open it. */
export function sealBox(recipient, plaintext) {
  const ephemeral = generateKeyPairSync("x25519");
  const ephemeralPublic = exportPublic(ephemeral.publicKey);
  const shared = diffieHellman({ privateKey: ephemeral.privateKey, publicKey: importPublic(recipient) });
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", boxSecret(shared, ephemeralPublic, recipient), iv);
  const ciphertext = Buffer.concat([cipher.update(Buffer.from(plaintext)), cipher.final()]);
  return { ephemeral: ephemeralPublic, iv: b64(iv), ciphertext: b64(ciphertext), tag: b64(cipher.getAuthTag()) };
}

function openBox(box, privateKey, recipient) {
  const shared = diffieHellman({ privateKey, publicKey: importPublic(box.ephemeral) });
  const decipher = createDecipheriv("aes-256-gcm", boxSecret(shared, box.ephemeral, recipient), unb64(box.iv));
  decipher.setAuthTag(unb64(box.tag));
  return Buffer.concat([decipher.update(unb64(box.ciphertext)), decipher.final()]);
}

export function encryptWith(secret, plaintext) {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", secret, iv);
  const ciphertext = Buffer.concat([cipher.update(Buffer.from(plaintext)), cipher.final()]);
  return { iv: b64(iv), ciphertext: b64(ciphertext), tag: b64(cipher.getAuthTag()) };
}

export function decryptWith(secret, box) {
  const decipher = createDecipheriv("aes-256-gcm", secret, unb64(box.iv));
  decipher.setAuthTag(unb64(box.tag));
  return Buffer.concat([decipher.update(unb64(box.ciphertext)), decipher.final()]);
}

export { randomBytes };
