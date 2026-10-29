# Tinfoil transport trial

An isolated probe for AppDrop's proposed attested worker. It contains no phone
pairing records, Apple credentials, or production integration.

**The cloud trial passed and the instance is stopped.** Read the
[trial report](REPORT.md) for checks, evidence, limitations, and shutdown
confirmation. The successful measured release is
[v0.0.2](https://github.com/eiiot/appdrop-tinfoil-probe/releases/tag/v0.0.2).

## Probe

`app/` contains a Node server with a health check, binary WebSocket echo, and a
fixed outbound HTTPS check to `tuft-rendezvous.fly.dev`. The Docker context uses
an explicit file allowlist. `check-transport.mjs` tests a localhost proxy that
must verify the remote enclave before forwarding traffic.

The trial used Tinfoil CLI 0.19.12, CVM runtime 0.14.17, and measurement action
0.14.1. The release workflows originate from Tinfoil's public template, with
the image build context restricted to `app/` and the measurement action updated
to the current compatible version. CI pins each published image by SHA-256.

Only the transport foundation has been exercised. This repository does not
implement passkey ownership, encrypted phone-state recovery, the production
release-approval policy, or the phone install protocol.
