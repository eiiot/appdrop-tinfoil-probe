// Verifying a Tinfoil v3 attestation on AMD SEV-SNP, with nothing but Node's
// crypto and AMD's pinned roots: no network, so a key server can check its
// successor from inside its own enclave.
//
// What it proves: an AMD Genoa CPU, not in debug mode, signed a report saying
// "this VM has measurement M, and REPORT_DATA R", where R binds the caller's
// nonce and the enclave's endorsed keys (Tinfoil's report-data/v1).
import { X509Certificate, createHash, verify } from "node:crypto";
import { AMD_GENOA } from "./amd-genoa.mjs";

const [ARK, ASK] = AMD_GENOA.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g).map((p) => new X509Certificate(p));
if (!ARK.verify(ARK.publicKey) || !ASK.verify(ARK.publicKey)) throw new Error("pinned AMD certificates don't chain");

const REPORT_DATA_V1 = "https://tinfoil.sh/report-data/v1";
const sha256 = (...parts) => { const h = createHash("sha256"); for (const p of parts) h.update(p); return h.digest(); };

/** Check the report's AMD signature and policy; returns its fields. */
export function verifySnpReport(report, vcekDer) {
  const vcek = new X509Certificate(vcekDer);
  if (!vcek.verify(ASK.publicKey)) throw new Error("the VCEK isn't signed by AMD's Genoa key");
  if (report.length < 0x4a0) throw new Error("report is too short");
  const version = report.readUInt32LE(0x00);
  const policy = report.readBigUInt64LE(0x08);
  if (version < 2) throw new Error(`report version ${version} is too old`);
  if (report.readUInt32LE(0x34) !== 1) throw new Error("report isn't signed with ECDSA P-384");
  if (!(policy & (1n << 17n))) throw new Error("report policy has an invalid reserved bit");
  if (policy & (1n << 19n)) throw new Error("the enclave allows debugging, so its memory isn't private");
  // AMD stores r and s little-endian in 72-byte fields; P-384 needs 48 big-endian bytes each.
  const component = (offset) => Buffer.from(report.subarray(offset, offset + 48)).reverse();
  const signature = Buffer.concat([component(0x2a0), component(0x2a0 + 72)]);
  const valid = verify("sha384", report.subarray(0, 0x2a0), { key: vcek.publicKey, dsaEncoding: "ieee-p1363" }, signature);
  if (!valid) throw new Error("the report's AMD signature is invalid");
  return { reportData: report.subarray(0x50, 0x90), measurement: report.subarray(0x90, 0xc0).toString("hex") };
}

/**
 * Verify a Tinfoil v3 attestation document against the nonce the caller
 * expects. Returns the measurement and the endorsed crypto material.
 */
export function verifyTinfoilAttestation(document, expectedNonce) {
  if (document?.format !== "https://tinfoil.sh/predicate/attestation/v3") throw new Error("not a v3 attestation");
  const { challenge } = document;
  if (challenge.nonce !== expectedNonce) throw new Error("the attestation is for a different challenge");
  if (challenge.report_data_algorithm !== REPORT_DATA_V1) throw new Error("unknown report-data algorithm");
  const cryptoMaterial = Buffer.from(document.crypto_material, "base64");
  const deviceEvidence = Buffer.from(document.device_evidence, "base64");
  const expected = Buffer.concat([
    sha256(REPORT_DATA_V1, Buffer.from(expectedNonce, "hex"), sha256(cryptoMaterial), sha256(deviceEvidence)),
    Buffer.alloc(32),
  ]);
  const vcek = document.collateral?.find((c) => c.format === "https://tinfoil.sh/collateral/amd-vcek/v1");
  if (!vcek) throw new Error("no VCEK in the attestation");
  const { reportData, measurement } = verifySnpReport(
    Buffer.from(document.cpu_evidence.report_base64, "base64"),
    Buffer.from(vcek.data.vcek_der_base64, "base64"),
  );
  if (!reportData.equals(expected)) throw new Error("the report doesn't bind this nonce and these keys");
  return { measurement, cryptoMaterial: JSON.parse(cryptoMaterial) };
}
