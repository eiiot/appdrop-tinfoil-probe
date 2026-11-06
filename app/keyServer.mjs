// The key server: the code that runs inside the enclave. It is the only place
// device keys exist in the clear. It can pair a device, install a build on one,
// and hand all its keys to an approved successor; there is no other way out.
//
// It trusts nothing it is handed by the host (the untrusted machine around the
// enclave) except what is signed by the hardware, the watcher, or the admins
// named in its own image. Every host call is awaited, so the host can be
// in-process (tests) or across the network (an enclave talking to its operator).
import { randomBytes } from "node:crypto";
import { b64, boxKey, canonical, decryptWith, digest, encryptWith, sealBox, signingKey, signingKeyFrom } from "./crypto.mjs";
import { GENESIS, cancelChallenge, extend, upgradeChallenge } from "./log.mjs";
import { buildHash } from "./phone.mjs";
import { verifyApproval } from "./securityKey.mjs";
import { verifyCheckpoint } from "./watcher.mjs";

export class KeyServer {
  #identity = signingKey(); // signs this server's log entries
  #box = boxKey(); // receives sealed keys
  #devices = new Map(); // device id -> signing key
  #seen = []; // the log as the watcher has countersigned it
  #heads = [GENESIS]; // #heads[n]: the log's hash after n entries
  #challenges = new Set(); // handoff challenges this server issued
  #dataKey = null;
  #wrapped = null;
  #keyId = null;
  #retired = false;

  /**
   * config, from the image (so part of the measurement):
   *   admins: [{ owner, credentialId, publicKey }], threshold, delayMs, watcherPublicKey
   * platform: the hardware, as { measurement, attest(userData), verify(attestation) }
   * host: the untrusted operator: log, watcher, privateLog, phone(id), and
   *   optionally keyRelease and storage. Without keyRelease, keys live only in memory.
   */
  constructor({ config, platform, host }) {
    Object.assign(this, { config, platform, host, measurement: platform.measurement });
  }

  /** Prove this build holds these keys, for `nonce` (a challenge from whoever asks). */
  attestation(nonce = b64(randomBytes(16))) {
    return this.platform.attest({ identity: this.#identity.publicKey, boxKey: this.#box.publicKey, nonce });
  }

  get devices() {
    return [...this.#devices.keys()];
  }

  /** Boot: reopen this build's sealed keys if there are any, then announce itself. */
  async start() {
    const stored = this.host.keyRelease && (await this.host.storage.get(this.measurement));
    if (stored) {
      this.#keyId = stored.keyId;
      await this.#checkKeyPolicy();
      const sealed = await this.host.keyRelease.unwrap(stored.keyId, stored.wrapped, await this.attestation());
      this.#dataKey = this.#box.open(sealed);
      this.#wrapped = stored.wrapped;
      this.#load(decryptWith(this.#dataKey, stored.state));
    }
    await this.#record("server-started", { measurement: this.measurement, attestation: await this.attestation() });
    return this;
  }

  /** Pair a phone. Logged before the key exists. */
  async pair(deviceId) {
    this.#live();
    if (this.#devices.has(deviceId)) throw new Error(`${deviceId} is already paired`);
    await this.#record("pair", { device: deviceId }, { private: true });
    const key = signingKey();
    await this.host.phone(deviceId).pair(key.publicKey);
    this.#devices.set(deviceId, key);
    await this.#seal();
  }

  /** Install a build on a paired phone. Logged before the session opens. */
  async install(deviceId, build) {
    this.#live();
    const key = this.#devices.get(deviceId);
    if (!key) throw new Error(`${deviceId} isn't paired with this key server`);
    const hash = buildHash(build);
    await this.#record("install", { device: deviceId, app: build.name, version: build.version, hash }, { private: true });
    const phone = this.host.phone(deviceId);
    const nonce = await phone.openSession();
    await phone.install(build, { publicKey: key.publicKey, signature: key.sign(canonical({ nonce, hash })) });
  }

  /** Step 1 of a handoff: a fresh challenge the successor must attest to. */
  handoffChallenge() {
    this.#live();
    const challenge = b64(randomBytes(32));
    this.#challenges.add(challenge);
    return challenge;
  }

  /**
   * Step 2: hand every key to a successor, if the upgrade to it was approved,
   * public for the delay, and not cancelled.
   *   successor: the new server's attestation, for a challenge from step 1
   *   proposal: the log index of its "upgrade-proposed" entry
   *   firstSeen: a watcher checkpoint that already included the proposal
   */
  async handoff({ successor, proposal, firstSeen }) {
    this.#live();
    const { measurement, userData } = await this.platform.verify(successor);
    if (!this.#challenges.delete(userData.nonce)) throw new Error("the successor's attestation isn't for a challenge this server issued");
    const now = await this.#sync(); // fresh, countersigned view of the log

    const entry = this.#seen[proposal];
    if (entry?.type !== "upgrade-proposed") throw new Error("no such upgrade proposal in the log");
    const { from, to, approvals = [] } = entry.body;
    if (from !== this.measurement) throw new Error("the proposal is for a different key server");
    if (to !== measurement) throw new Error("the successor isn't running the approved build");

    const owners = new Set();
    for (const approval of approvals) owners.add(verifyApproval(approval, upgradeChallenge(from, to), this.config.admins));
    if (owners.size < this.config.threshold) {
      throw new Error(`needs ${this.config.threshold} admins' approval; has ${owners.size}`);
    }

    const seen = verifyCheckpoint(this.config.watcherPublicKey, firstSeen);
    if (seen.size <= proposal || this.#heads[seen.size] !== seen.head) throw new Error("that checkpoint doesn't include the proposal");
    const waited = now.time - seen.time;
    if (waited < this.config.delayMs) {
      throw new Error(`the upgrade has been public for ${duration(waited)}; it must be for ${duration(this.config.delayMs)}`);
    }
    if (now.cancelled.includes(to) || this.#seen.slice(proposal).some((e) => e.type === "upgrade-cancelled" && this.#isCancel(e, to))) {
      throw new Error("an admin cancelled this upgrade");
    }

    await this.#record("handoff", { from, to });
    this.#retired = true;
    return sealBox(userData.boxKey, this.#export());
  }

  /** On a successor: take the keys a predecessor sealed to it. */
  async receive(sealed) {
    this.#live();
    if (this.#devices.size) throw new Error("this key server already holds keys");
    this.#load(this.#box.open(sealed));
    await this.#seal();
  }

  #isCancel(entry, to) {
    if (entry.body.to !== to) return false;
    try {
      verifyApproval(entry.body.assertion, cancelChallenge(to), this.config.admins);
      return true;
    } catch {
      return false;
    }
  }

  #live() {
    if (this.#retired) throw new Error("this key server has handed off its keys and is retired");
  }

  // Log, then act: append, then wait for the watcher to countersign a log that includes it.
  // A private action (anything naming a customer) goes into the public log as a
  // salted hash; its details go to the operator's private store, to be proved
  // to that customer later.
  async #record(type, body, { private: hidden = false } = {}) {
    const salt = hidden ? b64(randomBytes(16)) : null;
    const entry = hidden ? { type: "sealed", body: { commitment: digest({ type, body, salt }) } } : { type, body };
    const signature = this.#identity.sign(canonical(entry));
    await this.host.log.append({ ...entry, signer: this.#identity.publicKey, signature });
    await this.#sync();
    const recorded = this.#seen.find((e) => e.signature === signature);
    if (!recorded) throw new Error("the log didn't record this action");
    if (hidden) await this.host.privateLog.set(recorded.seq, { type, body, salt });
  }

  /** Read the log up to a fresh watcher checkpoint, checking it matches what the watcher saw. */
  async #sync() {
    const nonce = b64(randomBytes(16));
    const checkpoint = verifyCheckpoint(this.config.watcherPublicKey, await this.host.watcher.cosign({ nonce }));
    if (checkpoint.nonce !== nonce) throw new Error("stale checkpoint");
    const entries = (await this.host.log.since(this.#seen.length)).slice(0, checkpoint.size - this.#seen.length);
    const heads = extend(this.#seen.length, this.#heads.at(-1), entries);
    if ((heads.at(-1) ?? this.#heads.at(-1)) !== checkpoint.head) throw new Error("the log we were shown isn't the one the watcher signed");
    this.#seen.push(...entries);
    this.#heads.push(...heads);
    return checkpoint;
  }

  async #checkKeyPolicy() {
    const policy = await this.host.keyRelease.describe(this.#keyId);
    if (policy.measurement !== this.measurement) throw new Error("the storage key would also open for other code");
  }

  // Seal the device keys with this build's own release key, for restarts.
  // Without a key-release service, keys stay in memory only.
  async #seal() {
    if (!this.host.keyRelease) return;
    if (!this.#dataKey) {
      this.#keyId = await this.host.keyRelease.createKey({ measurement: this.measurement });
      await this.#checkKeyPolicy();
      const { wrapped, sealed } = await this.host.keyRelease.generateDataKey(this.#keyId, await this.attestation());
      this.#dataKey = this.#box.open(sealed);
      this.#wrapped = wrapped;
    }
    await this.host.storage.set(this.measurement, {
      keyId: this.#keyId,
      wrapped: this.#wrapped,
      state: encryptWith(this.#dataKey, this.#export()),
    });
  }

  #export() {
    return canonical(Object.fromEntries([...this.#devices].map(([id, key]) => [id, key.exportPrivate()])));
  }

  #load(bytes) {
    for (const [id, pkcs8] of Object.entries(JSON.parse(bytes.toString()))) this.#devices.set(id, signingKeyFrom(pkcs8));
  }
}

const duration = (ms) => (ms >= 3_600_000
  ? `${Math.floor(ms / 3_600_000)}h${String(Math.floor((ms % 3_600_000) / 60_000)).padStart(2, "0")}m`
  : `${Math.floor(ms / 60_000)}m${String(Math.floor((ms % 60_000) / 1000)).padStart(2, "0")}s`);
