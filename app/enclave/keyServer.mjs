import { createHash, randomBytes, randomInt } from "node:crypto";
import { boxKey, canonical, sealBox, signingKey, signingKeyFrom } from "../shared/crypto.mjs";
import { hostPair, hostSession } from "../shared/phoneProtocol.mjs";
import { digestOf, rekorKey } from "../shared/rekor.mjs";
import { signedBytes, verifyApproval } from "../shared/webauthn.mjs";
import { challengeFor, upgradeMessage } from "../shared/messages.mjs";

export class KeyServer {
  #rekorKey = rekorKey();
  #box = boxKey();
  #devices = new Map();
  #challenges = new Set();
  #retired = false;

  constructor({ config, platform, rekor, roughtime }) {
    Object.assign(this, { config, platform, rekor, roughtime, measurement: platform.measurement });
  }

  get status() {
    return {
      measurement: this.measurement,
      rekorKey: this.#rekorKey.publicKeyPem,
      devices: this.#devices.size,
      retired: this.#retired,
      rules: { threshold: this.config.threshold, delayMs: this.config.delayMs, windowMs: this.config.windowMs, admins: this.config.admins.map((a) => a.name) },
    };
  }

  attestation(nonce) {
    return this.platform.attest({ rekorKey: this.#rekorKey.publicKeyPem, boxKey: this.#box.publicKey, nonce });
  }

  async pair(deviceId, channel, showCode) {
    this.#live();
    if (this.#devices.has(deviceId)) throw new Error("already paired");
    const hostKey = signingKey();
    const code = String(randomInt(0, 1_000_000)).padStart(6, "0");
    await showCode(code);
    const phoneIdentity = await hostPair(channel, hostKey, code);
    this.#devices.set(deviceId, { hostKey, phoneIdentity });
    return { host_key: hostKey.publicKey, phone_identity: phoneIdentity };
  }

  async install(deviceId, ipa, channel) {
    this.#live();
    const device = this.#devices.get(deviceId);
    if (!device) throw new Error("not paired");
    const session = await hostSession(channel, device.hostKey, device.phoneIdentity);
    session.send({ op: "copy-begin", name: ipa.name, size: ipa.size });
    const hash = createHash("sha256");
    for await (const chunk of ipa.chunks) {
      hash.update(chunk);
      session.send({ op: "copy-chunk", data: chunk.toString("base64") });
    }
    session.send({ op: "copy-end" });
    const copied = await session.recv();
    if (hash.digest("hex") !== ipa.hash || copied.hash !== ipa.hash) throw new Error("the IPA doesn't match its hash");
    session.send({ op: "install", name: ipa.name, version: ipa.version });
    const result = await session.recv();
    if (result.op !== "installed") throw new Error(result.error ?? "the phone didn't install it");
    return { installed: result.name, version: result.version };
  }

  async check(deviceId, channel) {
    this.#live();
    const device = this.#devices.get(deviceId);
    if (!device) throw new Error("not paired");
    try {
      const session = await hostSession(channel, device.hostKey, device.phoneIdentity);
      session.send({ op: "ping" });
      await session.recv();
      return { trusted: true };
    } catch (error) {
      return { trusted: false, reason: error.message };
    }
  }

  forget(deviceId) {
    this.#live();
    return { forgotten: this.#devices.delete(deviceId) };
  }

  /** A fresh challenge the successor must put in its attestation. */
  handoffChallenge() {
    this.#live();
    const challenge = randomBytes(32).toString("hex");
    this.#challenges.add(challenge);
    return challenge;
  }

  /**
   * Hand every key to `successor`, if admins approved exactly this move in
   * Rekor, the delay has passed since the last needed approval, and no admin
   * has written anything else to Rekor since the first.
   * approvals: [{ uuid, assertion }]: the admins' Rekor entries, and the
   * passkey data behind each (Rekor keeps only its hash).
   */
  async handoff(successor, approvals = []) {
    this.#live();
    const { measurement, userData } = this.platform.verify(successor);
    if (!this.#challenges.delete(userData.nonce)) throw new Error("the successor's attestation isn't for our challenge");

    const challenge = challengeFor(upgradeMessage(this.measurement, measurement));
    const shown = new Map(approvals.map((a) => [a.uuid, a.assertion]));
    const approves = (admin, entry) => {
      const assertion = shown.get(entry.uuid);
      if (!assertion || createHash("sha256").update(signedBytes(assertion)).digest("hex") !== entry.digest) return false;
      try {
        return verifyApproval(assertion, challenge, [admin], { allowSynced: this.config.allowSyncedPasskeys }) === admin.name;
      } catch {
        return false;
      }
    };

    const now = await this.roughtime();
    const { threshold, delayMs, windowMs } = this.config;
    const entries = [];
    for (const admin of this.config.admins) {
      for (const entry of await this.rekor.entriesBy(admin.publicKey)) entries.push({ admin, entry, approval: approves(admin, entry) });
    }

    const latest = new Map();
    for (const { admin, entry, approval } of entries) {
      if (approval && now - entry.time <= delayMs + windowMs) latest.set(admin.name, Math.max(latest.get(admin.name) ?? 0, entry.time));
    }
    const times = [...latest.values()].sort((a, b) => a - b);
    if (times.length < threshold) throw new Error(`needs ${threshold} admins' approvals in Rekor; found ${times.length}`);
    const [first, started] = [times[0], times[threshold - 1]];

    const waited = now - started;
    if (waited < delayMs) throw new Error(`too early: ${minutes(waited)} of ${minutes(delayMs)} have passed`);
    if (waited > delayMs + windowMs) throw new Error("the approvals expired; approve again");

    const block = entries.find(({ entry, approval }) => entry.time >= first && !approval);
    if (block) throw new Error(`blocked by ${block.admin.name}`);

    await this.#write({ action: "handoff", from: this.measurement, to: measurement });
    this.#retired = true;
    return sealBox(userData.boxKey, canonical(Object.fromEntries(
      [...this.#devices].map(([id, d]) => [id, { hostKey: d.hostKey.exportPrivate(), phoneIdentity: d.phoneIdentity }]),
    )));
  }

  receive(sealed) {
    this.#live();
    if (this.#devices.size) throw new Error("already holds keys");
    for (const [id, d] of Object.entries(JSON.parse(this.#box.open(sealed).toString()))) {
      this.#devices.set(id, { hostKey: signingKeyFrom(d.hostKey), phoneIdentity: d.phoneIdentity });
    }
    return { devices: this.#devices.size };
  }

  async #write(statement) {
    const { digest, signature } = this.#rekorKey.sign(canonical(statement));
    return this.rekor.write({ digest, signature, publicKeyPem: this.#rekorKey.publicKeyPem });
  }

  #live() {
    if (this.#retired) throw new Error("retired: this key server handed off its keys");
  }
}

export const statementDigest = (statement) => digestOf(canonical(statement));
const minutes = (ms) => `${Math.floor(ms / 60_000)}m${String(Math.floor((ms % 60_000) / 1000)).padStart(2, "0")}s`;
