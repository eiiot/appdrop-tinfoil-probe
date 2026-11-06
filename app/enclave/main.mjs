// The key server as it runs in a Tinfoil enclave.
import { readFileSync } from "node:fs";
import { KeyServer } from "./keyServer.mjs";
import { roughtime, stagingRekor, tinfoilPlatform } from "./platform.mjs";
import { createServer } from "./server.mjs";

const VERSION = "v0.3.1";
const config = JSON.parse(readFileSync(new URL("./config.json", import.meta.url), "utf8"));
const keyServer = new KeyServer({ config, platform: await tinfoilPlatform(), rekor: stagingRekor, roughtime });
createServer({ keyServer, token: process.env.OPERATOR_TOKEN, version: VERSION }).listen(Number(process.env.PORT || 8080), "0.0.0.0");
console.log(`key server ${VERSION} listening; measurement ${keyServer.measurement}`);
