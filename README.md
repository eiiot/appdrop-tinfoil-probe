# Tinfoil transport trial

Disposable transport probe for the proposed AppDrop attested worker. No phone
pairing records, Apple credentials, or production changes.

The probe source in `app/` is the previously locally verified Node server:
health check, binary WebSocket echo, heartbeat, and fixed outbound HTTPS to the
Tuft relay. The Docker build context is explicitly allowlisted.

CLI v0.19.12 is installed at `/private/tmp/appdrop-tinfoil-cli/tinfoil`; its
archive was checked against the official GitHub release's SHA-256 digest.
`run-tinfoil.py` reads the organization admin key from the submitted Ocho secret
file into the CLI environment and uses a task-local configuration path.

## Next steps

1. Wait for the submitted organization admin key. Use `whoami` and read-only
   container/host listing to confirm organization access and available capacity.
2. Prepare a separate public configuration repository and measured release.
   Configuration and disposable probe source may be public; credentials must
   remain outside the repository and Docker context.
3. Deploy one non-debug CPU instance for the trial and stop it after checks.
4. Verify exact release attestation, reject an incorrect release, and test the
   long-lived binary connection plus outbound HTTPS under attested TLS.

The organization admin key works. Read-only API checks report Tier 1 with a
five-container quota and no existing containers. The host list is empty; that
has not yet established whether automatic placement works. Local transport
checks passed in the Evervault preparation, but Tinfoil attestation and routing
have not been tested.

The measured-release workflows come from Tinfoil's public-container template
at commit `1d4369c1a284173fded52607099592ebff558211`. The image build context is
restricted to `app/`. CI replaces the draft image reference in the configuration
with the published SHA-256 digest before creating the measured release.

Tinfoil's volume/private-secret/automatic-unlock features are documented as beta.
This transport trial does not implement key recovery, release approval, passkey
authorization, or the full phone protocol.
