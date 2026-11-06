// A simulated phone. It trusts the host keys it was paired with, and installs
// a build only over a session opened with one of them. This stands in for iOS
// pairing: possession of a trusted key is all it checks.
import { randomBytes } from "node:crypto";
import { b64, canonical, sha256, verifySignature } from "./crypto.mjs";

export const buildHash = (build) => sha256(build.bytes).toString("hex");

export class Phone {
  #trusted = new Set();
  #nonce = null;
  installed = new Map();

  constructor(name, { confirm = () => true } = {}) {
    this.name = name;
    this.confirm = confirm; // the user entering the pairing code
  }

  pair(hostPublicKey) {
    if (!this.confirm(hostPublicKey)) throw new Error(`${this.name}: the user didn't confirm pairing`);
    this.#trusted.add(hostPublicKey);
  }

  openSession() {
    this.#nonce = b64(randomBytes(16));
    return this.#nonce;
  }

  install(build, { publicKey, signature }) {
    const nonce = this.#nonce;
    this.#nonce = null;
    if (!nonce) throw new Error(`${this.name}: no session`);
    if (!this.#trusted.has(publicKey)) throw new Error(`${this.name}: not paired with that key`);
    const hash = buildHash(build);
    if (!verifySignature(publicKey, canonical({ nonce, hash }), signature)) throw new Error(`${this.name}: session signature is invalid`);
    this.installed.set(build.name, build.version);
  }
}
