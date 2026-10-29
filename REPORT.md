# Tinfoil trial report

2026-10-28. Release: [v0.0.2](https://github.com/eiiot/appdrop-tinfoil-probe/releases/tag/v0.0.2).

**Result:** the attested networking foundation works for this disposable probe.
This is enough to justify a phone-protocol prototype; it does not validate the
complete AppDrop security architecture.

| Check | Result |
| --- | --- |
| Deploy a non-debug confidential VM | Passed; AMD SEV-SNP, 2 CPUs, 8 GB RAM |
| Match hardware measurements to the signed release | Passed |
| Bind the TLS connection to the attested public key | Passed; key fingerprints match |
| Reject an incorrect release digest | Passed; signature verification rejected the mismatched artifact digest |
| HTTP through the attestation-pinned proxy | Passed |
| Binary WebSocket traffic and heartbeat | Passed for 60 seconds; 12 random 1,500-byte echoes and ping/pong exchanges |
| Outbound HTTPS to the Tuft relay hostname | Passed; no enrollment code or real phone was used |
| Replace the trial with an updated measured release | Passed; v0.0.1 replaced by v0.0.2 |

Verification used Tinfoil CLI 0.19.12 with an explicit repository, version, and
release digest pin. The successful release digest was
`a4a22be48931044adf2015825a2df1ef6adaa0a623318a89a57c1b2d5fe404ec`.
The [verification record](evidence/attestation-v0.0.2.json) preserves the
hardware measurements and matching public TLS key fingerprints. No verification
checks were disabled to obtain the passing result.

## Friction encountered

- Deployment required adding at least $20 in credits.
- The official public template's older measurement action produced provenance
  that the current verifier rejected because `vm_shape` was absent. The passing
  release uses CVM image 0.14.17 and measurement action 0.14.1. The initial
  release failed verification and is not a successful trial result.
- Certificate provisioning is part of startup. A request before readiness saw
  a temporary self-signed certificate and failed. Verification succeeded after
  startup completed; certificate verification was not bypassed.
- The host list initially returned empty, but automatic placement worked.

## What remains untested

The full Tuft VPN transport, physical iPhone pairing and installation, iOS-native
attestation integration, cross-user isolation attacks, encrypted persistence,
passkey ownership, unattended key recovery, and the two-step release policy.
The relay check was an HTTPS reachability test, not a real Tuft session.
The minute-long WebSocket check does not establish hours-long reliability or
production capacity.

The runtime update had no user state to preserve. It does not establish safe
restoration of phone keys across worker replacement. That remains the main
architecture decision before automatic updates can work securely.

## Shutdown

Tinfoil confirmed **Stopped** at `2026-10-29T02:09:58Z` (October 28 locally).
There is no pending update or production/review connection. The local verified
proxy is closed. No persistent volumes were created. The stopped instance's
configuration and the public trial repository remain available for review.
