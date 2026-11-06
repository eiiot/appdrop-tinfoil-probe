// What the key server needs from its surroundings: attestation (Tinfoil),
// Rekor, and Roughtime.
import http from "node:http";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { canonical, sha256 } from "../shared/crypto.mjs";
import { entriesBy, rekorWrite, STAGING } from "../shared/rekor.mjs";
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

export function verifyTinfoil(attestation) {
  const { measurement } = verifyTinfoilAttestation(attestation?.document, nonceFor(attestation?.userData ?? {}));
  return { measurement, userData: attestation.userData };
}

async function attestTinfoil(userData) {
  for (let attempt = 0; ; attempt++) {
    const { status, body } = await fromSocket(`/.well-known/tinfoil-attestation?nonce=${nonceFor(userData)}`);
    if (status === 200) return { userData, document: JSON.parse(body) };
    if (status !== 503 || attempt > 30) throw new Error(`attestation socket answered ${status}`);
    await new Promise((r) => setTimeout(r, 2000));
  }
}

export async function tinfoilPlatform() {
  const self = verifyTinfoil(await attestTinfoil({ purpose: "self", at: Date.now() }));
  return { measurement: self.measurement, attest: attestTinfoil, verify: verifyTinfoil };
}

export const stagingRekor = {
  write: (fields) => rekorWrite(fields, STAGING),
  entriesBy: (publicKey) => entriesBy(publicKey, STAGING),
};

/** The time, from Roughtime: at least two servers must agree within 10 seconds. */
export async function roughtime() {
  const { stdout } = await promisify(execFile)("roughtime", [], { timeout: 30000 });
  const times = stdout.trim().split("\n").map((line) => JSON.parse(line)).filter((r) => r.midpoint_ms).map((r) => r.midpoint_ms).sort((a, b) => a - b);
  const median = times[Math.floor(times.length / 2)];
  const agreeing = times.filter((t) => Math.abs(t - median) < 10_000);
  if (agreeing.length < 2) throw new Error("couldn't get a trusted time from Roughtime");
  return agreeing[Math.floor(agreeing.length / 2)];
}
