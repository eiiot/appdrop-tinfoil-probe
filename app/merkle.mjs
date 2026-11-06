// A Merkle tree over the log's entries, as in Certificate Transparency
// (RFC 9162), so one entry can be proved to be in a countersigned log without
// revealing any other entry.
import { sha256 } from "./crypto.mjs";

const leaf = (hex) => sha256(Buffer.from([0]), Buffer.from(hex, "hex"));
const node = (left, right) => sha256(Buffer.from([1]), left, right);
const split = (n) => { let k = 1; while (k * 2 < n) k *= 2; return k; };

function root(nodes) {
  if (nodes.length === 1) return nodes[0];
  const k = split(nodes.length);
  return node(root(nodes.slice(0, k)), root(nodes.slice(k)));
}

/** The tree's root over entry hashes (hex). */
export function merkleRoot(hashes) {
  return (hashes.length ? root(hashes.map(leaf)) : sha256("")).toString("hex");
}

/** The sibling hashes that prove entry `index` is in the tree over `hashes`. */
export function inclusionProof(hashes, index) {
  const path = (nodes, m) => {
    if (nodes.length <= 1) return [];
    const k = split(nodes.length);
    return m < k
      ? [...path(nodes.slice(0, k), m), root(nodes.slice(k))]
      : [...path(nodes.slice(k), m - k), root(nodes.slice(0, k))];
  };
  return path(hashes.map(leaf), index).map((h) => h.toString("hex"));
}

/** RFC 9162, section 2.1.3.2. */
export function verifyInclusion(hash, index, size, proof, expectedRoot) {
  if (index >= size) return false;
  let fn = index;
  let sn = size - 1;
  let r = leaf(hash);
  for (const hex of proof) {
    const p = Buffer.from(hex, "hex");
    if (sn === 0) return false;
    if (fn & 1 || fn === sn) {
      r = node(p, r);
      while (!(fn & 1) && fn !== 0) { fn >>= 1; sn >>= 1; }
    } else {
      r = node(r, p);
    }
    fn >>= 1;
    sn >>= 1;
  }
  return sn === 0 && r.toString("hex") === expectedRoot;
}
