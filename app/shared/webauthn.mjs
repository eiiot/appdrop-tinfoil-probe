// Checking passkey signatures (WebAuthn assertions), and turning one into a
// Rekor entry: a passkey signs authenticatorData || SHA-256(clientDataJSON)
// with ECDSA P-256, which Rekor accepts as a signature over that digest.
import { createHash, createVerify } from "node:crypto";
import { toPem } from "./rekor.mjs";

export const RP_ID = "localhost";
export const ORIGIN = "http://localhost:7777";

const sha256 = (data) => createHash("sha256").update(data).digest();
const UP = 0x01;
const UV = 0x04;
const BE = 0x08;

export const signedBytes = (assertion) =>
  Buffer.concat([Buffer.from(assertion.authenticatorData, "base64"), sha256(Buffer.from(assertion.clientDataJSON, "base64"))]);

/** For Rekor: the digest, signature and key of a passkey assertion. */
export function rekorFields(assertion, publicKey) {
  return { digest: sha256(signedBytes(assertion)), signature: Buffer.from(assertion.signature, "base64"), publicKeyPem: toPem(publicKey) };
}

/**
 * Check an assertion from one of `admins` ({ name, credentialId, publicKey })
 * over `challenge` (bytes). Returns the admin's name, or throws.
 */
export function verifyApproval(assertion, challenge, admins, { allowSynced = false } = {}) {
  const admin = admins.find((a) => a.credentialId === assertion?.credentialId);
  if (!admin) throw new Error("approval from an unknown passkey");
  const authenticatorData = Buffer.from(assertion.authenticatorData, "base64");
  const client = JSON.parse(Buffer.from(assertion.clientDataJSON, "base64").toString());
  if (client.type !== "webauthn.get") throw new Error("not a passkey signature");
  if (client.challenge !== Buffer.from(challenge).toString("base64url")) throw new Error("the passkey signed something else");
  if (client.origin !== ORIGIN) throw new Error(`signed on ${client.origin}, not ${ORIGIN}`);
  if (!authenticatorData.subarray(0, 32).equals(sha256(RP_ID))) throw new Error("passkey for a different site");
  const flags = authenticatorData[32];
  if (!(flags & UP) || !(flags & UV)) throw new Error(`${admin.name} didn't confirm with a password or biometric`);
  if (flags & BE && !allowSynced) throw new Error(`${admin.name}'s passkey is synced; only hardware keys may approve`);
  const valid = createVerify("SHA256").update(signedBytes(assertion)).verify(toPem(admin.publicKey), Buffer.from(assertion.signature, "base64"));
  if (!valid) throw new Error(`${admin.name}'s signature is invalid`);
  return admin.name;
}
