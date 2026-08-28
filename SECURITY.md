# Security model

This project is experimental authentication software. Keep password login and
an already-authenticated recovery terminal available while changing PAM.

## Trust boundaries

- The T2 SEP owns fingerprint templates and makes the biometric decision.
- The root `fprintd` facade trusts its locally installed Python environment,
  the kernel transport, bridgeOS, and the configured macOS user scope.
- A successful result is accepted only when SEP reports both a match and an
  identity present in the selected user's current identity list.
- Missing, malformed, timed-out, rejected, or differently scoped replies fail
  closed. Linux cannot enroll, delete, or export fingerprint templates.

## Password and keybag material

The macOS keybag and login password are authentication secrets. The PAM helper
receives a password over stdin and does not put it in argv, the environment, or
logs. The optional systemd credential is encrypted at rest, but on a machine
without a TPM its host-key protection does not defend against a root attacker
or an attacker who can decrypt the Linux filesystem. Reusing the same password
for Linux and macOS increases the impact of either environment being breached.

Private files must be root-owned and inaccessible to group/other. Never publish
keybags, catacombs, credentials, captures, device identifiers, UUIDs, raw
BridgeXPC replies, or biometric payloads.

## PAM safety

Fingerprint authentication is `sufficient`, not the sole authentication path.
The supplied installer keeps the password fallback and stores original PAM
files in `/var/lib/t2-touchid/pam-backups`. Validate both the intended finger
and a wrong finger before closing the recovery terminal. Use
`sudo tools/rollback-pam.sh` to restore the originals.

## Reporting vulnerabilities

Open a GitHub security advisory rather than a public issue when a report might
contain secrets, stable identifiers, authentication bypass details, or raw
protocol data. Redact identifiers and attach only the output of the supplied
diagnostic tools.
