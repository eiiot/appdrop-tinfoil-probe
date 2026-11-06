// The host as the enclave sees it when the operator is across the network:
// the same interface as the in-process host, over HTTPS. Everything the host
// returns is checked by the key server (watcher signatures, hash chains), so
// this connection needs no trust beyond the shared token that keeps strangers out.
import { b64 } from "./crypto.mjs";

export function remoteHost(base, token) {
  const call = async (path, body = {}) => {
    const response = await fetch(new URL(path, base), {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${token}` },
      body: JSON.stringify(body),
    });
    const reply = await response.json().catch(() => ({ error: `host answered ${response.status}` }));
    if (!response.ok) throw new Error(reply.error ?? `host answered ${response.status}`);
    return reply.result;
  };
  return {
    log: {
      append: (entry) => call("/log/append", entry),
      since: (size) => call("/log/since", { size }),
    },
    watcher: { cosign: (options) => call("/watcher/cosign", options) },
    privateLog: { set: (seq, details) => call("/private/set", { seq, details }) },
    phone: (id) => ({
      pair: (publicKey) => call("/phone/pair", { id, publicKey }),
      openSession: () => call("/phone/session", { id }),
      install: (build, session) => call("/phone/install", { id, build: { ...build, bytes: b64(build.bytes) }, session }),
    }),
  };
}
