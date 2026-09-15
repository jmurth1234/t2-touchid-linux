# PAM authentication (sudo, pkexec, lock)

How this tree talks to `pam_fprintd` 1.94.5 on a machine that already has
keybags unlocked and `fprintd.service` running. It is the operator guide for
the verification boundary in [FPRINT_INTEGRATION.md](FPRINT_INTEGRATION.md).

Do **not** use Omarchy **Setup → Security → Fingerprint**. That wizard is a
USB reader + `fprintd-enroll` path. Enrollment stays in **macOS**.

Do **not** unload `t2_sep_transport` or start a second transport on a boot
that already negotiated SEP.

## What PAM actually does

`pam_fprintd.so` is sequential. It cannot wait for a busy sensor and cannot
show fingerprint and password at the same time. Default `timeout=` (30 s)
starts only **after** `VerifyStart` returns. `ListEnrolledFingers` and `Claim`
are synchronous D-Bus calls with systemd’s ~25 s method timeout.

The module always:

1. `ListEnrolledFingers` — if this errors, it treats the user as having **zero**
   prints and returns `PAM_AUTHINFO_UNAVAIL` (password fallback on
   `sufficient`).
2. `Claim`
3. `VerifyStart("any")` — never a named finger.
4. Wait for `VerifyStatus`.
5. On success, **disconnect without `Release`**. fprintd drops the claim on
   `NameOwnerChanged` (and a 0.5 s completed-claim timer in this facade).

`sudo` reuses a timestamp for later commands in the same ticket. `pkexec`
does **not**. Each `pkexec` is a new PAM session on `/etc/pam.d/polkit-1`.

## Stacks this installer writes

`tools/install-pam.sh` writes:

| File | Who uses it | Lid closed |
| --- | --- | --- |
| `/etc/pam.d/sudo` | `sudo` | skip sensor → password |
| `/etc/pam.d/polkit-1` | `pkexec` / Omarchy polkit dialog | skip sensor → password |
| `/etc/pam.d/omarchy-lock-fingerprint` | lock screen | **still fingerprint** (no clamshell skip) |

After creating `polkit-1`, restart the shell (`omarchy restart shell`) so the
agent rereads PAM.

Typical sudo / polkit auth lines:

```text
auth      [success=3 default=ignore] pam_exec.so quiet /usr/bin/omarchy-hw-laptop-closed
auth      [success=ignore default=2] pam_exec.so quiet seteuid /usr/local/sbin/t2-pam-fingerprint-ready
auth      optional   pam_exec.so quiet stdout /usr/local/sbin/t2-pam-fingerprint-prompt
auth      sufficient pam_fprintd.so
auth      include      system-auth
```

### Lid-open `exit 1` is not a failed login

`omarchy-hw-laptop-closed` exits **0** if the lid is closed (skip three modules
→ password) and **1** if the lid is open (continue to Touch ID). PAM
`default=ignore` means that 1 is the fingerprint path. `pam_exec` still
syslogs `failed: exit code 1`; `quiet` only hides it from the dialog.

### Keybags

`t2-pam-fingerprint-ready` must succeed or PAM skips the sensor. Before the
first unlock of the boot, sudo asks for the Linux password, then a hidden
macOS password, then records readiness. With the host-encrypted credstore,
unlock is unattended. After readiness, the same helper waits out another
short-lived fingerprint PAM client so a second sudo does not see
`AlreadyInUse` and drop to password.

## pkexec caller pin

polkit 126+ runs `polkit-agent-helper-1 --socket-activated` as an **all-root**
systemd service, not sudo’s setuid shape. This facade accepts that helper
only when stdin is `/run/polkit/agent-helper.socket` and `SO_PEERCRED` names
one non-root desktop agent. That peer UID is pinned the same way as sudo’s
real UID (`pidfd_getfd`). The unit allows `pidfd_getfd` in
`SystemCallFilter`. An all-root D-Bus client that is not that helper still
cannot borrow a session.

## Why list and `any` verify must not open Bridge

A live `t2-touchid-fprint-status` from `ListEnrolledFingers` takes
`/run/t2-touchid/operation.lock` with **`LOCK_NB`**. The match probe holds
that lock with `flock --timeout 10`. Back-to-back `pkexec` (or sudo then
pkexec) hits teardown: list fails with `fingerprint inventory unavailable`,
pam_fprintd sees zero prints, password field appears.

This facade therefore:

- **`ListEnrolledFingers`** — return the stored compatibility alias. No
  subprocess. Empty list is still `NoEnrolledPrints`.
- **`VerifyStart("any")` and `VerifyStart(alias)`** — do not take
  `operation_lock`, do not call `runtime_projection()`. Return, then run the
  probe.
- **`verify_fprint` for those names** — `target_finger=None`,
  `resolve_any_finger=False` (all enrolled identities). The probe waits on
  `flock --timeout 10` **after** `VerifyStart` returns, inside pam_fprintd’s
  30 s finger timeout.
- **Other finger names** — `NoEnrolledPrints` on this path.
- **Enroll / delete** — still a fresh live projection.

`Claim` stays exclusive and immediate. Do not queue claims: pam_fprintd will
time out the D-Bus method (~25 s) and fall through to password anyway.
Overlapping **sudo / pkexec** wait in `t2-pam-fingerprint-ready` instead
(before the touch prompt), up to 32 s, while
`/run/t2-touchid/workers/fprint-claim` names `sudo` / `pkexec` /
`polkit-agent-helper-1`. Start the second command after the first has
claimed (about a second). Two Claims in the same instant can still race.
The lock screen is `other` and does not delay TTY sudo. After the wait,
`Claim` is a normal exclusive take.

Hardware-tested 14 Sep 2026 on MacBookPro16,1: two `pkexec bash -c 'id -u'`
one second apart both returned `0` with `pam_fprintd`, no inventory error.

## Checks

Lid open, keybags unlocked:

```sh
fprintd-verify -f any "$USER"          # PAM-shaped; expect verify-match
pkexec bash -c 'id -u'                 # 0; Omarchy fingerprint square
pkexec bash -c 'id -u'                 # immediate second; still fingerprint
```

Do **not** use bare `fprintd-verify` as the PAM control. Upstream picks
`fingers[0]` by name. Named `fprintd-verify -f right-thumb` is
`NoEnrolledPrints` on this PAM path unless that name is the configured alias.

`t2-touchid-fprint-status` remains the live inventory CLI (root, operation
lock). Do not run it during an on-screen fingerprint prompt.

## Journal noise that is OK

| Line | Meaning |
| --- | --- |
| `omarchy-hw-laptop-closed failed: exit code 1` | Lid open → try the sensor |
| `Unexpected VerifyFingerSelected any signal` | T2 / pam_fprintd 1.94.5 quirk; auth can still succeed |
| `fingerprint inventory unavailable` | **Not OK** on the PAM path after this change; live list leaked onto Bridge |

## Rollback

Keep a root TTY before changing PAM:

```sh
sudo tools/rollback-pam.sh
```

Live facade only (this machine): restore
`/opt/t2-touchid/src/t2-fprintd.py.bak-before-pam-list-storage` and
`systemctl restart fprintd.service`. Do not unload transport.
