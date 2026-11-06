// The watcher: run by someone other than the operator, on separate
// infrastructure. It reads the log, refuses to countersign a rewritten
// history, raises alerts, and is the only clock the key server trusts.
import { canonical, signingKey, signingKeyFrom, verifySignature } from "./crypto.mjs";
import { GENESIS, cancelChallenge, entryHash, extend } from "./log.mjs";
import { merkleRoot } from "./merkle.mjs";
import { verifyApproval } from "./securityKey.mjs";

// "sealed" entries are customer actions, blinded: only a salted hash is public.
const SIGNED = new Set(["server-started", "sealed", "handoff"]);

export class Watcher {
  #key;
  #size = 0;
  #head = GENESIS;
  #cancelled = new Set();
  #servers = new Set();
  #hashes = [];

  /** verify: checks a key server's attestation for the platform in use; returns { measurement, userData }. */
  constructor({ log, clock, alert, admins, verify, savedKey = null }) {
    Object.assign(this, { log, clock, alert, admins, verify });
    this.#key = savedKey ? signingKeyFrom(savedKey) : signingKey();
  }

  get publicKey() {
    return this.#key.publicKey;
  }

  /** For the demo only: the watcher's key, to keep it across runs. */
  saveKey() {
    return this.#key.exportPrivate();
  }

  /** Read new entries and countersign the log as it now stands. */
  cosign({ nonce } = {}) {
    const entries = this.log.since(this.#size);
    const heads = extend(this.#size, this.#head, entries); // throws on a rewritten history
    for (const entry of entries) this.#inspect(entry);
    this.#hashes.push(...entries.map(entryHash));
    this.#size += entries.length;
    if (heads.length) this.#head = heads.at(-1);
    const checkpoint = { size: this.#size, head: this.#head, root: merkleRoot(this.#hashes), time: this.clock(), cancelled: [...this.#cancelled].sort(), nonce };
    return { ...checkpoint, signature: this.#key.sign(canonical(checkpoint)) };
  }

  /** An admin cancels a pending upgrade directly, in case the operator won't log it. */
  cancel(to, assertion) {
    const owner = verifyApproval(assertion, cancelChallenge(to), this.admins);
    this.#cancelled.add(to);
    this.alert(`Upgrade to ${to.slice(0, 12)} cancelled by ${owner}.`);
  }

  #inspect(entry) {
    if (SIGNED.has(entry.type)) {
      if (entry.type === "server-started") {
        try {
          const { measurement, userData } = this.verify(entry.body.attestation);
          if (measurement === entry.body.measurement && userData.identity === entry.signer) this.#servers.add(entry.signer);
        } catch {}
      }
      const genuine = this.#servers.has(entry.signer)
        && verifySignature(entry.signer, canonical({ type: entry.type, body: entry.body }), entry.signature);
      if (!genuine) this.alert(`Log entry ${entry.seq} (${entry.type}) wasn't written by an attested key server.`);
    }
    if (entry.type === "server-started") {
      this.alert(`Key server ${entry.body.measurement.slice(0, 12)} started.`);
    } else if (entry.type === "upgrade-proposed") {
      const { from, to, approvals = [] } = entry.body;
      this.alert(`UPGRADE PROPOSED: keys move from ${from.slice(0, 12)} to ${to.slice(0, 12)} in 12 hours, `
        + `approved by ${approvals.length} key(s). If you didn't expect this, cancel it now.`);
    } else if (entry.type === "upgrade-cancelled") {
      try {
        const owner = verifyApproval(entry.body.assertion, cancelChallenge(entry.body.to), this.admins);
        this.#cancelled.add(entry.body.to);
        this.alert(`Upgrade to ${entry.body.to.slice(0, 12)} cancelled by ${owner}.`);
      } catch (error) {
        this.alert(`Log entry ${entry.seq} tries to cancel an upgrade but isn't valid: ${error.message}.`);
      }
    } else if (entry.type === "handoff") {
      this.alert(`Keys moved from ${entry.body.from.slice(0, 12)} to ${entry.body.to.slice(0, 12)}.`);
    }
  }
}

/** The checkpoint without its signature, or an error. */
export function verifyCheckpoint(watcherPublicKey, checkpoint) {
  const { signature, ...rest } = checkpoint ?? {};
  if (!verifySignature(watcherPublicKey, canonical(rest), signature)) throw new Error("checkpoint isn't signed by the watcher");
  return rest;
}
