// Admin approvals in WebAuthn's shape, so a real passkey or security key can
// replace SecurityKey later without touching verifyApproval.
//
// An assertion is what navigator.credentials.get() returns: authenticatorData,
// clientDataJSON, and an ECDSA P-256 signature over
// authenticatorData || SHA-256(clientDataJSON).
import { createPrivateKey, createPublicKey, createSign, createVerify, generateKeyPairSync, randomBytes } from "node:crypto";
import { b64, b64url, importPublic, sha256, unb64 } from "./crypto.mjs";

const UP = 0x01; // user present
const UV = 0x04; // user verified (PIN or biometric)
const BE = 0x08; // backup eligible: a synced passkey
const BS = 0x10; // backed up

export const RP_ID = "keyserver.example";
export const ORIGIN = `https://${RP_ID}`;

/** A hardware security key, or (with synced: true) a passkey that syncs to the cloud. */
export class SecurityKey {
  #privateKey;
  #count = 0;

  constructor(owner, { synced = false, saved = null } = {}) {
    const privateKey = saved ? createPrivateKey({ key: unb64(saved.privateKey), format: "der", type: "pkcs8" })
      : generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey;
    this.#privateKey = privateKey;
    this.owner = owner;
    this.synced = synced;
    this.credentialId = saved?.credentialId ?? b64url(randomBytes(16));
    this.publicKey = b64(createPublicKey(privateKey).export({ type: "spki", format: "der" }));
  }

  /** For the demo only: a real security key never reveals its private key. */
  save() {
    return { owner: this.owner, credentialId: this.credentialId, privateKey: b64(this.#privateKey.export({ type: "pkcs8", format: "der" })) };
  }

  /** What an admin registers: shown once, baked into the key server's image. */
  get registration() {
    return { owner: this.owner, credentialId: this.credentialId, publicKey: this.publicKey };
  }

  /** The admin touches the key to sign `challenge` (bytes). */
  approve(challenge, { origin = ORIGIN, rpId = RP_ID } = {}) {
    const flags = UP | UV | (this.synced ? BE | BS : 0);
    const count = Buffer.alloc(4);
    count.writeUInt32BE(++this.#count);
    const authenticatorData = Buffer.concat([sha256(rpId), Buffer.from([flags]), count]);
    const clientDataJSON = Buffer.from(JSON.stringify({ type: "webauthn.get", challenge: b64url(challenge), origin }));
    const signer = createSign("SHA256");
    signer.update(Buffer.concat([authenticatorData, sha256(clientDataJSON)]));
    return {
      credentialId: this.credentialId,
      authenticatorData: b64(authenticatorData),
      clientDataJSON: b64(clientDataJSON),
      signature: b64(signer.sign(this.#privateKey)),
    };
  }
}

/**
 * Check an assertion from one of `admins` over `challenge`. Returns the admin's
 * owner name, or throws with the reason.
 */
export function verifyApproval(assertion, challenge, admins) {
  const admin = admins.find((a) => a.credentialId === assertion?.credentialId);
  if (!admin) throw new Error("approval from an unknown key");
  const authenticatorData = unb64(assertion.authenticatorData);
  const clientDataJSON = unb64(assertion.clientDataJSON);
  const client = JSON.parse(clientDataJSON.toString());
  if (client.type !== "webauthn.get") throw new Error("not an assertion");
  if (client.challenge !== b64url(challenge)) throw new Error("approval is for something else");
  if (client.origin !== ORIGIN) throw new Error("approval from the wrong site");
  if (!authenticatorData.subarray(0, 32).equals(sha256(RP_ID))) throw new Error("approval for the wrong site");
  const flags = authenticatorData[32];
  if (!(flags & UP) || !(flags & UV)) throw new Error("the admin didn't confirm with a PIN or biometric");
  if (flags & BE) throw new Error(`${admin.owner}'s key is a synced passkey; only hardware keys may approve`);
  const verifier = createVerify("SHA256");
  verifier.update(Buffer.concat([authenticatorData, sha256(clientDataJSON)]));
  if (!verifier.verify(importPublic(admin.publicKey), unb64(assertion.signature))) {
    throw new Error("approval signature is invalid");
  }
  return admin.owner;
}
