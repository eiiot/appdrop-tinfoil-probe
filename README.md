# Key server node on Tinfoil

Disposable experiments for a key server that holds device keys inside a Tinfoil
enclave and hands them only to an approved, attested successor. The design and
its rules are prototyped separately; this repository runs the hardware part on
real AMD SEV-SNP machines.

Step 1 (`app/server.mjs`): `GET /attestation?challenge=<64 hex>` returns a fresh
attestation whose nonce is SHA-256 of the node's public keys and the challenge,
so the attestation vouches for exactly those keys.

The earlier transport trial is described in `REPORT.md`.
