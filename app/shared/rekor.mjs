// A small Rekor client: write a hashedrekord entry, verify Rekor's signed entry
// timestamp (SET) with a pinned key, and search by public key.
import { createHash, createPublicKey, createSign, createVerify, generateKeyPairSync } from "node:crypto";

export const STAGING = {
  url: "https://rekor.sigstage.dev",
  publicKey: `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEDODRU688UYGuy54mNUlaEBiQdTE9
nYLr0lg6RXowI/QV/RE1azBn4Eg5/2uTOMbhB1/gfcHzijzFi9Tk+g1Prg==
-----END PUBLIC KEY-----
`,
};

const sha256 = (data) => createHash("sha256").update(data).digest();

/** The same public key as PEM, whether given as PEM or base64 SPKI DER. */
export function toPem(key) {
  const object = key.includes("BEGIN") ? createPublicKey(key) : createPublicKey({ key: Buffer.from(key, "base64"), format: "der", type: "spki" });
  return object.export({ type: "spki", format: "pem" });
}

const samePublicKey = (a, b) =>
  createPublicKey(a).export({ type: "spki", format: "der" }).equals(createPublicKey(b).export({ type: "spki", format: "der" }));

/** An ECDSA P-256 key for writing to Rekor: signs `message`, returns what Rekor needs. */
export function rekorKey() {
  const { publicKey, privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  return {
    publicKeyPem: publicKey.export({ type: "spki", format: "pem" }),
    sign(message) {
      const bytes = Buffer.from(message);
      return { digest: sha256(bytes), signature: createSign("SHA256").update(bytes).sign(privateKey) };
    },
  };
}

/** Write an entry: a signature over a SHA-256 digest by a public key. Returns the verified entry. */
export async function rekorWrite({ digest, signature, publicKeyPem }, rekor = STAGING) {
  const body = {
    apiVersion: "0.0.1",
    kind: "hashedrekord",
    spec: {
      signature: { content: Buffer.from(signature).toString("base64"), publicKey: { content: Buffer.from(publicKeyPem).toString("base64") } },
      data: { hash: { algorithm: "sha256", value: Buffer.from(digest).toString("hex") } },
    },
  };
  const response = await fetch(`${rekor.url}/api/v1/log/entries`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  if (response.status !== 201) throw new Error(`Rekor refused the entry (${response.status}): ${(await response.text()).slice(0, 200)}`);
  const [uuid, entry] = Object.entries(await response.json())[0];
  return verifyEntry({ uuid, ...entry }, rekor);
}

/**
 * Check Rekor's signed entry timestamp with its pinned key, and decode the
 * entry. Returns { uuid, time (ms), publicKeyPem, digest } or throws.
 */
export function verifyEntry(entry, rekor = STAGING) {
  const payload = JSON.stringify({ body: entry.body, integratedTime: entry.integratedTime, logID: entry.logID, logIndex: entry.logIndex });
  const set = entry.verification?.signedEntryTimestamp;
  if (!set || !createVerify("SHA256").update(payload).verify(rekor.publicKey, Buffer.from(set, "base64"))) {
    throw new Error("Rekor's signed timestamp doesn't verify");
  }
  const body = JSON.parse(Buffer.from(entry.body, "base64").toString());
  return {
    uuid: entry.uuid,
    time: entry.integratedTime * 1000,
    publicKeyPem: Buffer.from(body.spec.signature.publicKey.content, "base64").toString(),
    digest: body.spec.data.hash.value,
  };
}

/** Every entry signed by `publicKey`, each verified. Throws if Rekor can't be asked. */
export async function entriesBy(publicKey, rekor = STAGING) {
  const pem = toPem(publicKey);
  const response = await fetch(`${rekor.url}/api/v1/index/retrieve`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ publicKey: { format: "x509", content: Buffer.from(pem).toString("base64") } }),
  });
  if (!response.ok) throw new Error(`Rekor search failed (${response.status})`);
  const uuids = await response.json();
  const entries = [];
  for (const uuid of uuids ?? []) {
    const got = await fetch(`${rekor.url}/api/v1/log/entries/${uuid}`);
    if (!got.ok) throw new Error(`Rekor didn't return entry ${uuid} (${got.status})`);
    const [id, entry] = Object.entries(await got.json())[0];
    const verified = verifyEntry({ uuid: id, ...entry }, rekor);
    if (!samePublicKey(verified.publicKeyPem, pem)) throw new Error(`Rekor returned an entry by a different key`);
    entries.push(verified);
  }
  return entries;
}

export const digestOf = (message) => sha256(Buffer.from(message)).toString("hex");
