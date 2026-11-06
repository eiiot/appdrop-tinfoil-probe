// The public, append-only log. Each entry names the hash of the one before it,
// so rewriting history changes every later hash. The log is run by the
// untrusted operator; the watcher's countersignatures are what make it
// trustworthy.
import { digest, sha256, canonical } from "./crypto.mjs";

export const GENESIS = "0".repeat(64);
export const entryHash = (entry) => digest(entry);

/** What admins sign to approve moving the keys from one build to another. */
export const upgradeChallenge = (from, to) => sha256(canonical({ action: "approve-upgrade", from, to }));
/** What an admin signs to stop a pending upgrade. */
export const cancelChallenge = (to) => sha256(canonical({ action: "cancel-upgrade", to }));

export class Log {
  entries = [];

  append({ type, body, signer, signature }) {
    const prev = this.entries.length ? entryHash(this.entries.at(-1)) : GENESIS;
    const entry = { seq: this.entries.length, prev, type, body, signer, signature };
    this.entries.push(entry);
    return entry;
  }

  since(size) {
    return this.entries.slice(size);
  }
}

/**
 * Check that `entries` continue a log of `size` entries ending in `head`.
 * Returns the hash after each entry; throws if any link is broken.
 */
export function extend(size, head, entries) {
  const heads = [];
  entries.forEach((entry, i) => {
    if (entry.seq !== size + i || entry.prev !== head) throw new Error(`log entry ${size + i} doesn't follow the one before it`);
    head = entryHash(entry);
    heads.push(head);
  });
  return heads;
}
