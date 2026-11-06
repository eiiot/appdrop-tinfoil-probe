// The platform interface on Tinfoil: attest through the enclave's attestation
// socket, verify with AMD's pinned roots (src/sev.mjs). The nonce is SHA-256 of
// the userData, so an attestation vouches for exactly the keys in it.
import http from "node:http";
import { canonical, sha256 } from "./crypto.mjs";
import { verifyTinfoilAttestation } from "./sev.mjs";

const SOCKET = "/tinfoil/attestation.sock";

function fromSocket(path) {
  return new Promise((resolve, reject) => {
    const request = http.get({ socketPath: SOCKET, path, timeout: 20000 }, (response) => {
      const chunks = [];
      response.on("data", (chunk) => chunks.push(chunk));
      response.on("end", () => resolve({ status: response.statusCode, body: Buffer.concat(chunks).toString() }));
    });
    request.on("timeout", () => request.destroy(new Error("attestation socket timed out")));
    request.on("error", reject);
  });
}

const nonceFor = (userData) => sha256(canonical(userData)).toString("hex");

/** Check a Tinfoil attestation { userData, document }; returns { measurement, userData }. */
export function verifyTinfoil(attestation) {
  const { measurement } = verifyTinfoilAttestation(attestation?.document, nonceFor(attestation?.userData ?? {}));
  return { measurement, userData: attestation.userData };
}

export async function attestTinfoil(userData) {
  for (let attempt = 0; ; attempt++) {
    const { status, body } = await fromSocket(`/.well-known/tinfoil-attestation?nonce=${nonceFor(userData)}`);
    if (status === 200) return { userData, document: JSON.parse(body) };
    if (status !== 503 || attempt > 30) throw new Error(`attestation socket answered ${status}`);
    await new Promise((r) => setTimeout(r, 2000)); // not ready yet
  }
}

/** The platform for a key server running in this enclave; learns its own measurement first. */
export async function tinfoilPlatform() {
  const self = verifyTinfoil(await attestTinfoil({ purpose: "self", at: Date.now() }));
  return { measurement: self.measurement, attest: attestTinfoil, verify: verifyTinfoil };
}
