// What gets signed, written the same way everywhere.
import { createHash } from "node:crypto";
import { canonical } from "./crypto.mjs";

export const upgradeMessage = (from, to) => canonical({ action: "upgrade", from, to });
export const blockMessage = (from, to) => canonical({ action: "block", from, to });
export const challengeFor = (message) => createHash("sha256").update(message).digest();
