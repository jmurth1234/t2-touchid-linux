# Security model

This project is experimental authentication software. Keep password login and
an already-authenticated recovery terminal available while changing PAM.

It has been proven on exactly one machine; see the README's
[proven configuration](README.md#proven-configuration) and
[status table](README.md#status) for what is exposed and what has actually been
tested on hardware.

## Trust boundaries

- The T2 SEP owns fingerprint templates and makes the biometric decision.
- The root `fprintd` facade trusts its locally installed Python environment,
  the kernel transport, bridgeOS, and the configured macOS user scope.
- A successful result is accepted only when SEP reports both a match and an
  identity present in the selected user's current identity list.
- Missing, malformed, timed-out, rejected, or differently scoped replies fail
  closed.
- Linux can never export or read fingerprint templates; SEP does not release
  them and no code path requests them.
- The installed `fprintd` service is verification-only. It exposes no
  enrollment or deletion method: native enrollment is default-off and native
  deletion is disabled.
- Enrollment and single-identity deletion exist only as separate root-only,
  journaled brokers (`t2-touchid-enroll`, `t2-touchid-manage`) behind explicit
  `--acknowledge-*` flags. They are experimental; deletion is irreversible in
  SEP and has not been tested on hardware.

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

## Scope

Because the mutation brokers are root-only, a report that requires root to
exploit is generally a hardening issue rather than a privilege boundary
failure. The boundaries that matter most are: the fprintd D-Bus surface
reachable by an unprivileged local caller, the PAM helpers, anything that could
cause a match to be reported without SEP returning a matching identity, and any
path that leaks keybag material, identity UUIDs, or biometric payloads.

## Reporting vulnerabilities

Open a GitHub security advisory rather than a public issue when a report might
contain secrets, stable identifiers, authentication bypass details, or raw
protocol data. Redact identifiers and attach only the output of the supplied
diagnostic tools.
