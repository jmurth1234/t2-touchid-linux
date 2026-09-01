# Intel T2 Touch ID for Linux

Experimental, fail-closed Touch ID authentication for Intel Macs with an Apple
T2 chip. It talks to bridgeOS BiometricKit over BridgeXPC and exposes a minimal
`fprintd`-compatible D-Bus service for PAM clients.

This is research software, not an upstream `libfprint` driver. It has been
proven on exactly one machine, and macOS remains the recovery environment.
Read [Before you start](#before-you-start) before installing anything.

## Contents

- [Status](#status)
- [Proven configuration](#proven-configuration)
- [Prerequisites](#prerequisites)
- [Before you start](#before-you-start)
- [Concepts](#concepts)
- [Installation](#installation)
- [Verification](#verification)
- [Recovery and uninstall](#recovery-and-uninstall)
- [Diagnostics](#diagnostics)
- [Enrollment (experimental)](#enrollment-experimental)
- [Identity management (experimental)](#identity-management-experimental)
- [Single-identity deletion (experimental)](#single-identity-deletion-experimental)
- [Cross-OS reconciliation](#cross-os-reconciliation)
- [Security properties](#security-properties)
- [Limitations](#limitations)
- [Reporting compatibility](#reporting-compatibility)
- [Repository layout](#repository-layout)
- [Development status](#development-status)
- [Background and provenance](#background-and-provenance)
- [Tests](#tests)
- [License](#license)

## Status

"Exposed" means a user can invoke it on an installed system. "Hardware-tested"
means it has been proven on the [proven configuration](#proven-configuration)
below, and nowhere else.

| Feature | Exposed? | Hardware-tested? |
| --- | --- | --- |
| Fingerprint verification through `fprintd` and PAM | Yes, installed and enabled | Yes, including negative controls and password fallback |
| Keybag unlock (manual, PAM hook, or encrypted credential) | Yes, installed | Yes, including cold boot |
| Diagnostics and identity inventory | Yes, installed | Yes |
| Enrollment from Linux (`t2-touchid-enroll`) | Yes, separate root-only CLI | Yes, one identity enrolled and re-proven after Linux reboot; a later macOS boot removed it |
| Label rename (`t2-touchid-manage rename-fprint`) | Yes, separate root-only CLI | Yes |
| Adaptive Catacomb persistence | Yes, opt-in (`T2_TOUCHID_AUTO_SYNC_ADAPTIVE=1`) | Partly; the journaled path is installed but has no dedicated live control |
| Single-identity deletion (`t2-touchid-manage delete`) | Yes, behind explicit acknowledgements | No; the first live hardware test has not been performed |
| Native `fprintd-enroll` / `fprintd-delete` | No; default-off flags and an uninstalled drop-in | No |
| Multi-user / mapped Linux accounts | No; `t2-touchid-user-map` only writes forced-disabled records | Read-only AKS gates only; no live multi-user operation |
| Endpoint-10 / ACM transport | Opt-in research only (`T2_TOUCHID_ENABLE_ACM_RESEARCH=1`) | Preflight and one transient-context lifecycle test only |
| Suspend/resume | n/a | No; known broken, treat as unsupported |

The `fprintd` service never exposes enrollment or deletion. The experimental
mutation commands are separate root-only, journaled brokers.

## Proven configuration

Developed and verified on an Intel `MacBookPro16,2`, bridgeOS build `23P1072`,
BridgeXPC 39, and Omarchy/Arch Linux.

A positive right-index control and a negative unenrolled-finger control were
both verified at the raw bridge, `fprintd`, and sudo/PAM layers. After the
first Linux enrollment and a reboot, the macOS-enrolled right index and the
Linux-enrolled right thumb were reconciled and assigned the canonical
`right-index-finger` and `right-thumb` labels. Both independently return
`verify-match` through an explicit `fprintd-verify -f any "$USER"` request,
while an unenrolled finger returns `verify-no-match`; named requests also
select only their corresponding identity.

That Linux-only thumb did not appear in macOS Touch ID settings. After macOS
booted, the next Linux boot found one stable SEP identity but two records in
the Linux-local Catacomb. fprintd correctly failed closed. This cross-OS
boundary and its host-only recovery are documented below.

## Prerequisites

**Hardware and firmware**

- An Intel Mac with an Apple T2 chip. Only `MacBookPro16,2` on bridgeOS
  `23P1072` has been tested.
- macOS still installed on the same machine, with at least one enrolled
  finger. macOS is both the source of the exported keybags and the recovery
  environment.

**Kernel and T2 support**

- A Linux kernel with the T2 support stack (`t2bce` / `apple-bce`), providing
  the T2 USB-network (`cdc_ncm`) interface used to reach BridgeXPC. Development
  used the t2linux patched kernels.
- Kernel build headers for the running kernel
  (`/lib/modules/$(uname -r)/build`), a C compiler, and `make`. The installer
  builds `t2_sep_transport` and two small helper binaries.
- `dkms` is optional but strongly recommended; without it, the installer must
  be rerun by hand after every kernel upgrade.

**Userspace**

- `systemd`, including `systemd-creds` and libsystemd, plus D-Bus and `polkit`.
- `fprintd` 1.94.5 and its PAM module `pam_fprintd.so`. The documented client
  behaviour, including the `PAM_SILENT` workaround described under
  [Installation](#installation), is specific to that version.
- Python 3.12 or newer, with `venv` and `pip`, plus `git`. CI covers Python
  3.12 and 3.14. The installer creates
  `/opt/t2-touchid/.venv` and installs `dbus-next` plus `pymobiledevice3` from
  a pinned git revision, so it needs network access on first run.
- `sudo`, and root access to the machine.

**Optional desktop feedback**

- `libnotify` (`notify-send`) and `libcanberra` (`canberra-gtk-play`) for the
  audible and visual cues described under
  [Desktop feedback](#desktop-feedback). Everything works without them.

## Before you start

Two things are far more likely to ruin your day than anything else in this
document. Read these first:

- **Keep macOS available, and keep password authentication working.** macOS is
  the only recovery environment for the fingerprint state in SEP. Never remove
  password authentication from PAM.
- **PAM changes can lock you out.** Install the PAM templates only after both
  the positive and negative fingerprint controls pass, keep a root shell open
  while you test, and remember that `sudo tools/rollback-pam.sh` restores the
  originals from `/var/lib/t2-touchid/pam-backups`.
- **Suspend is unsupported.** After a deep-S3 suspend, Touch ID fails closed
  until the machine is rebooted and the keybags are unlocked again. See
  [Suspend/resume](#suspendresume).
- **The kernel module is pinned after DMA registration.** Never unload it;
  reboot before replacing it.
- **Deletion is irreversible in SEP** and has never been tested on hardware.

The full recovery and removal commands are collected under
[Recovery and uninstall](#recovery-and-uninstall).

## Concepts

These terms recur throughout the document and the commands.

**Operation lock.** A single machine-wide lock serialising every biometric
operation. Inventory, enrollment, rename, deletion, and the adaptive Catacomb
sync all take it, so two of them can never touch SEP at once.

**Mutation journal.** Every mutating broker writes durable intent before it
dispatches a command to SEP, and records the reconciled outcome afterwards. An
interrupted or ambiguous operation therefore leaves a journal that must be
reconciled with a `recover*` subcommand. Never blindly replay a mutation:
inspect `status` first and follow only the recovery path it identifies.

**Post-reboot proof.** A completed enrollment, rename, or deletion stays
*blocking* — it is the only mutation allowed — until the resulting
identity and Catacomb state have been proved again from a different Linux
boot and a different Bridge connection. `t2-touchid-post-reboot.service`
performs that read-only proof automatically before `fprintd` starts; the
manual `verify-post-reboot` commands remain diagnostic fallbacks.

**Compatibility alias.** While any reconciled label is not a unique canonical
fprint finger name, `fprintd-list` and `fprintd-verify` deliberately expose one
configured logical finger slot (for example `right-index-finger`). That slot
means "authenticate against any built-in identity owned by the configured Apple
user". **It is not an enrollment count.** Use `sep_identity_count` from
`t2-touchid-inventory`, or `t2-touchid-enroll list`, for the truthful hardware
identity count. Once every label is uniquely canonical, the service
automatically lists every finger, restricts a named verification to only that
identity, and reports the exact canonical identity selected by a successful
`any` match.

**Management slot.** `t2-touchid-identities` prints numbered slots for the
reconciled identities. A slot number is valid only for that one reconciled
invocation and is the selector used by the identity-management commands.

**Acknowledgement flags.** `--acknowledge-*` options are statements that you
have already performed a control or accepted a consequence. They never run a
control and never, by themselves, authorize anything else.

**Generation pinning.** Live operations pin one Bridge connection generation,
one Linux boot, and one Linux account generation. If any of them changes
mid-operation, the operation fails closed rather than continuing against
different state.

## Installation

1. Keep macOS available and enroll exactly the finger you intend to use.
2. Run the export helpers in `tools/macos/` from macOS and transfer the outputs
   privately. Never commit or publish them.
3. On Linux, identify the T2 USB-network interface and its link-local IPv6
   address, then run `sudo ./install.sh`. Edit `/etc/t2-touchid.conf` when
   prompted, including the numeric macOS user ID and its corresponding special
   bag.
4. Start `t2-sep-transport.service`. The installer builds the module for the
   running kernel and configures PCI autoload with `register_ool=1`. The loader
   accepts an already operational module and can safely replace an early
   observation-only instance; it never unloads an instance that registered SEP
   DMA. After `/dev/t2-aks` exists, do not unload the module: reboot before
   rebuilding or replacing it. Re-run the installer after a kernel upgrade.
5. Place the extracted keybag at `/var/lib/t2-touchid/user.kb`, owned by root
   and mode `0600`, then start `t2-keybag-load.service`.
6. Unlock the loaded normal handle and the special user bag with the macOS
   password.

   `t2-keybag-load.service` records the boot-specific values in
   `/run/t2-touchid/keybag.env` (mode `0700` directory, root-only):

   ```sh
   sudo cat /run/t2-touchid/keybag.env
   ```

   `T2_KEYBAG_HANDLE` is the handle SEP returned for the loaded keybag; it
   changes on every boot. `T2_KEYBAG_SPECIAL` is the special bag from
   `T2_TOUCHID_SPECIAL_BAG` in `/etc/t2-touchid.conf` (`-501` for macOS user
   `501`). Unlock both, reading the values straight from that file:

   ```sh
   sudo sh -c '. /run/t2-touchid/keybag.env
     /usr/local/sbin/t2-aks-tool unlock-keybag "$T2_KEYBAG_SESSION" "$T2_KEYBAG_HANDLE"
     /usr/local/sbin/t2-aks-tool unlock-keybag "$T2_KEYBAG_SESSION" "$T2_KEYBAG_SPECIAL"'
   ```

   To avoid unlocking by hand after every boot, see
   [Unlocking keybags from password authentication](#unlocking-keybags-from-password-authentication)
   or [Unattended boot unlock](#unattended-boot-unlock).

7. Start `fprintd.service` and run the controls under
   [Verification](#verification).
8. **Only after those controls pass**, install the relevant files from `pam/`
   into `/etc/pam.d/` with `sudo tools/install-pam.sh`. Keep password
   authentication as a fallback and keep a root shell open while you test;
   `sudo tools/rollback-pam.sh` restores the originals.

   The sudo template displays a generic pre-capture sensor message through a
   fixed-text helper that writes to the controlling terminal or sudo's
   terminal-output channel. This is intentional: sudo sets `PAM_SILENT`, which
   hides conversation-based `pam_echo` messages, while fprintd 1.94.5's PAM
   client suppresses the ABI-valid `VerifyFingerSelected("any")` prompt when
   multiple identities are available. The message never names one finger
   because either enrolled identity is valid, and the clamshell guard skips
   both the message and the fingerprint module when the laptop is closed.

The installer is safe to rerun and replaces only project-managed files. When
DKMS is available it registers the transport for kernel upgrades; otherwise it
warns that the installer must be rerun after an upgrade.

If the desktop user's systemd user manager is already running, installation
reloads it through that user's `/run/user/<uid>/bus`. If no user bus exists,
the reload is skipped quietly and the units are discovered at the next login;
the root environment is never mistaken for a desktop user session. Uninstall
uses the same bounded user-bus rule after removing the feedback units.

### Unlocking keybags from password authentication

If the macOS and Linux login passwords are identical, PAM can pass the password
already entered by the user to the keybag unlock helper. The password is kept
only in process memory and is not placed in argv, the environment, logs, or
persistent storage. The helper reads the boot-specific handle recorded under
`/run` by `t2-keybag-load.service` and always exits successfully, so a T2
failure cannot block password authentication.

After making a root-owned backup, add this at the end of the `auth` section in
`/etc/pam.d/system-auth`, after the successful `pam_faillock.so authsucc` line:

```text
auth optional pam_exec.so quiet expose_authtok seteuid /usr/local/sbin/t2-pam-unlock
```

Omarchy uses SDDM autologin followed by a separate lock-screen PAM service, so
the initial desktop password does not traverse `system-auth`. On Omarchy, also
install `pam/omarchy-lock-password` as `/etc/pam.d/omarchy-lock-password` after
backing up the existing file. That template contains the same optional hook
after its successful `pam_faillock.so authsucc` line.

This unlocks the bags on the first successful password authentication through
an instrumented PAM service after boot. It cannot unlock them before a password
has been entered. The helper restricts itself to `T2_TOUCHID_USER` from
`/etc/t2-touchid.conf`.

### Unattended boot unlock

For unattended keybag availability after SDDM autologin, provision an encrypted
systemd credential:

```sh
sudo tools/provision-credential.sh
sudo systemctl enable t2-credential-unlock.service
```

The provisioning prompt is local and hidden. The plaintext password is piped
directly into `systemd-creds`; it is not placed in argv, the environment, or a
persistent plaintext file. At boot, systemd decrypts it into a protected,
service-scoped runtime credential, the one-shot helper unlocks both keybags,
and fprintd starts only after that attempt.

The proven machine has no usable TPM, so the credential is encrypted with
systemd's host key. That protects against casual or offline disclosure without
the decrypted Linux filesystem, but root can decrypt it. Since the credential
is also the Linux and macOS login password on the proven configuration,
understand this tradeoff before provisioning it.

With an unattended credential present, `t2-biometric-ready.service` also waits
for the T2 network path, discovers the dynamic RemoteXPC port, and performs a
non-matching initialization, calibration, and identity-list warm-up before
fprintd starts. This avoids exposing the first Omarchy lock-screen scan to the
cold BiometricKit startup race observed on the proven configuration. Its
verified dynamic port is cached root-only under `/var/lib/t2-touchid`; fprintd
consumes that cache and does not request a finger until discovery has
completed.

Cold boot authentication has been verified with sudo. Touch ID unlock through
an explicit `omarchy system lock` has also been verified, including
wrong-finger rejection and password fallback; other shell and login
configurations may use a different PAM path.

### Desktop feedback

`systemd/user/` installs three oneshot units that the root fprint daemon starts
through the configured user's live, owned bus socket:

| Unit | When | What you get |
| --- | --- | --- |
| `t2-touchid-alert.service` | A finger is requested | A short `message-new-instant` sound |
| `t2-touchid-success.service` | Match accepted | A "Fingerprint accepted" desktop notification and a quiet `complete` sound |
| `t2-touchid-failure.service` | Match rejected | A "Fingerprint not recognized" desktop notification and a `dialog-error` sound |

The cues use `notify-send` and `canberra-gtk-play`. To silence them, mask the
units as the desktop user:

```sh
systemctl --user mask t2-touchid-alert.service \
  t2-touchid-success.service t2-touchid-failure.service
```

Unmask them to restore the cues. If `notify-send` or `canberra-gtk-play` is not
installed, the units simply fail without affecting authentication.

## Verification

Run these controls after step 7 of the installation, before touching PAM, and
again after any reboot that follows a mutation.

```sh
fprintd-verify -f any "$USER"
```

Require `verify-match` with an enrolled finger and `verify-no-match` with an
unenrolled one. Once canonical labels are assigned, also test each identity
explicitly:

```sh
fprintd-verify -f right-index-finger "$USER"
fprintd-verify -f right-thumb "$USER"
```

The first command accepts any reconciled enrolled identity. The named commands
deliberately restrict SEP matching to only that identity. PAM uses fprintd's
`any` verification path.

With more than one listed finger, **do not use bare `fprintd-verify` as an
all-finger control**. The upstream utility's "automatic" default selects the
first name returned by `ListEnrolledFingers`; it does not request
`VerifyStart("any")`, so it does not represent what PAM does.

The fail-closed named-match boundary double-checks both SEP identity views on
the same Bridge connection, reconciles them with the validated local Catacomb,
sends only the selected opaque identity to the matcher, and proves all identity
state is unchanged afterwards. It is reached automatically only for a complete
canonical projection; with legacy labels, the
[compatibility alias](#concepts) continues to select all enrolled identities.

The transition policy is explicit: incomplete inventories expose only the
compatibility alias, complete inventories expose the canonical per-finger list,
named verification is restricted to that exact identity, and `any` always
remains an all-identities request. The named backend verdict requires both the
pre-match reconciliation proof and the post-match unchanged-state proof; a
selected-identity match alone is insufficient. For a complete projection, a
successful `any` match is also reduced to exactly one canonical finger name.
fprintd emits `VerifyFingerSelected("any")` before capture, as the upstream ABI
specifies, then reports the resolved canonical identity through
`VerifyFingerMatched` on success. Ambiguous events fail closed and UUIDs remain
private.

## Recovery and uninstall

**Undo PAM changes.** This is the command to reach for if fingerprint
authentication misbehaves or you are at risk of being locked out. It restores
the originals saved in `/var/lib/t2-touchid/pam-backups`:

```sh
sudo tools/rollback-pam.sh
```

If you added the `pam_exec.so` line to `/etc/pam.d/system-auth` by hand, remove
it by hand from your own backup; `rollback-pam.sh` only restores the templates
installed by `tools/install-pam.sh`.

**Recover after a failed suspend.** Reboot, unlock the keybags again, restart
`fprintd.service` if needed, and repeat both controls. See
[Suspend/resume](#suspendresume).

**Recover an interrupted mutation.** Do not replay it. Inspect the relevant
status first, then use only the recovery path it identifies:
`t2-touchid-enroll status` and its `recover-*` subcommands for enrollment,
`t2-touchid-manage status` and its `recover*` subcommands for rename, deletion,
and adaptive sync.

**Remove the software.** This removes code and services but preserves
configuration, credentials, keybags, and PAM backups:

```sh
sudo ./uninstall.sh
```

Add `--purge-private-data` only when those secrets should be permanently
removed; it deletes `/var/lib/t2-touchid`, `/etc/t2-touchid.conf`, and the
encrypted credential:

```sh
sudo ./uninstall.sh --purge-private-data
```

PAM restoration remains a separate explicit operation in both cases, and the
pinned kernel module stays loaded until you reboot.

## Diagnostics

Run the privacy-safe health report as root, so it can inspect root-only runtime
state and the encrypted credential metadata:

```sh
sudo t2-touchid-doctor
sudo t2-touchid-doctor --json
```

The doctor compares the loaded transport module's GNU build ID with the module
installed for the running kernel. A `module-build` warning means an update is
on disk but the old pinned SEP transport is still live; reboot before testing
the updated protocol path.

The report never prints configured addresses, usernames, ports, keybag handles,
credential contents, identity UUIDs, or biometric payloads.

### Identity inventory

Query the live SEP identity count and owner/layout consistency without exposing
template UUIDs:

```sh
sudo t2-touchid-inventory
```

This read-only command performs two exact back-to-back collections and fails if
the private global or per-user identity records, capacity replies, Catacomb
UUID/hash/state, or secure-key-store lock state change between them. It also
requires protocol-v2 global identities to reconcile with the configured user's
detail records. It exposes only counts, presence, query status, and
equality — not identity or Catacomb UUIDs or hashes. Maximum capacity and
configured-user free capacity remain separate because their arithmetic scope is
not yet proven. It is the read-only inventory gate used by the enrollment and
deletion research, and it mutates no biometric state.

Use `sep_identity_count` from this command for the truthful hardware identity
count; fprintd's [compatibility alias](#concepts) is an authentication
selector, not a template count.

### Reconciled labels

List the reconciled local labels as numbered management slots:

```sh
sudo t2-touchid-identities
```

This command holds the same exclusive operation lock used by enrollment,
strictly decodes the committed local Catacomb, performs a fresh stable SEP
double-read, and requires exact equality between the local, configured-user,
and global built-in identity sets. It prints only current-list slot numbers and
labels; UUIDs, entities, Catacomb identifiers, and biometric data remain
redacted.

### fprint projection status

Check whether every reconciled identity currently has one unique canonical
fprint finger name, without changing labels or exposing identifiers:

```sh
sudo t2-touchid-fprint-status
```

`complete: false` keeps the compatibility alias in place. It means one or more
labels need an explicit anatomical assignment before truthful per-finger fprint
listing can replace that alias; the command never guesses or mutates a label.

## Enrollment (experimental)

The stable command frontend exposes the proven journaled enrollment broker
without enabling enrollment in the installed fprintd service. Check the
redacted state first, then run the non-mutating preflight after confirming
password fallback works:

```sh
sudo t2-touchid-enroll status
sudo t2-touchid-enroll list
sudo t2-touchid-enroll preflight \
  --acknowledge-password-fallback-tested
```

To enroll one fingerprint, keep macOS available as the recovery environment and
explicitly acknowledge both the live SEP mutation and the local Catacomb
persistence:

```sh
sudo t2-touchid-enroll start \
  --name "Linux enrolled finger" \
  --acknowledge-password-fallback-tested \
  --acknowledge-live-fingerprint-enrollment \
  --acknowledge-local-catacomb-mutation
```

Follow the lift/place prompts until completion. The result then requires a
[post-reboot proof](#concepts) before any further mutation is allowed:

```sh
sudo t2-touchid-enroll verify-post-reboot
```

On bridgeOS 23P1072, a completed enrollment may carry an embedded owner field
that disagrees with the configured Apple user, even though the authoritative
SEP inventories add the identity to that user. Such a result is treated only as
a terminal completion witness: its UUID is discarded, and enrollment can
complete only when a stable double-read proves exactly one new built-in
identity in both the configured-user and global inventories, with unchanged
account, keybag, mapping, and local Catacomb state. This is the path validated
by the first Linux enrollment, which persisted and matched independently
alongside the original macOS-enrolled finger after reboot.

### Enrollment recovery

Do not simply repeat `start` after an interruption or an ambiguous result.
Inspect `status`, then use only the recovery path it identifies:

```sh
sudo t2-touchid-enroll recover-outcome
sudo t2-touchid-enroll recover-local
sudo t2-touchid-enroll recover-observed \
  --name "Recovered Linux finger" \
  --acknowledge-observed-identity-recovery \
  --acknowledge-local-catacomb-mutation
```

`recover-observed` persists a newly observed SEP identity and is therefore a
mutation; it is not a generic repair command. The backend remains experimental
and is proven only on the configuration documented here. The `list` subcommand
is the authoritative human-readable view of the real enrolled identities.

## Identity management (experimental)

### Identifying a physical finger

Legacy macOS labels such as `Finger 1`, and early Linux research labels, cannot
be converted to anatomical names by guessing. The installed read-only helper
matches one presented finger against all freshly reconciled identities and
returns only its current ephemeral management slot:

```sh
sudo t2-touchid-identities
sudo t2-touchid-identify-finger
```

No UUID, fingerprint payload, or guessed name is emitted, and the helper sends
no enrollment, rename, persistence, or deletion command. A positive result is
valid only for the current reconciled list. Note which physical finger you
presented, list again, and then rename that exact slot. Never infer the
anatomical name from the old compatibility alias.

### Persisting adaptive template updates

Successful matching can update a template adaptively and set the SEP user
Catacomb's save bit. Before enrollment, rename, deletion, or first mapping
enablement, persist that existing update with the exact Apple user-then-master
save order. The command changes no identity UUID, label, or count, requires an
explicit protected `verify` capability (an enabled mapping is not required for
initial bootstrap), and journals the host commit before the final SEP
confirmation:

```sh
sudo t2-touchid-manage sync-user-catacomb \
  --acknowledge-adaptive-template-persistence \
  --acknowledge-local-catacomb-persistence
```

An already-clean result is a read-only no-op. Any ambiguous dispatch or host
commit remains blocking and must not be retried blindly. Inspect status, then
recover one exact ambiguous adaptive save through a fresh Bridge generation:

```sh
sudo t2-touchid-manage status
sudo t2-touchid-manage recover-catacomb-sync \
  --acknowledge-interrupted-adaptive-sync-recovery \
  --acknowledge-adaptive-template-persistence \
  --acknowledge-local-catacomb-persistence
```

Recovery proves the committed host snapshot, identity set, mapping, Catacomb,
and fresh connection before either closing an already-clean operation or
performing one forward save. Another ambiguous result remains blocking.

Automatic post-match persistence is installed but defaults off. To opt in, set
this exact root-owned configuration value and restart fprintd:

```sh
sudoedit /etc/t2-touchid.conf   # T2_TOUCHID_AUTO_SYNC_ADAPTIVE=1
sudo systemctl restart fprintd.service
```

This opt-in acknowledges that every successful match may update authenticated
template state and the committed local Catacomb. fprintd emits the terminal
authentication verdict first, then asks the static
`t2-touchid-adaptive-sync.service` to run the same journaled user-then-master
operation. Scheduling or persistence failure cannot replace a successful
authentication verdict; the unit and the mutation journal retain diagnostic or
blocking state instead. Negative and unknown matches never schedule a write.
The oneshot waits two seconds before collection so late match/cancel callbacks
can settle; multiple requests during that interval coalesce into the same save.
Set the value back to `0` and restart fprintd to disable automatic persistence.

### Renaming a label

Renaming changes a label only; it does not alter the fingerprint template. For
fprint migration, preview and commit only a canonical anatomical name
(`left-thumb`, `right-index-finger`, and so on):

```sh
sudo t2-touchid-manage status
sudo t2-touchid-identities
sudo t2-touchid-manage plan-fprint-rename \
  --slot 2 \
  --name right-index-finger
sudo t2-touchid-manage rename-fprint \
  --slot 2 \
  --name right-index-finger \
  --acknowledge-identity-label-mutation \
  --acknowledge-local-catacomb-persistence
```

Rename refuses a label already assigned to another identity. Its result reports
whether every label now forms a unique canonical fprint projection; until that
becomes true, fprintd deliberately keeps exposing the single compatibility
alias.

The broker resolves the slot only against a fresh reconciled list, holds the
global operation lock and a verified sleep inhibitor, writes durable intent
before dispatch, persists exactly the selected user's Catacomb, and performs a
same-connection independent read-back. Rename is credential-free, so its
generic mutation baseline truthfully records that password fallback was not
verified; that field is not used as rename authority.

A successful rename requires the [post-reboot proof](#concepts) before any
further mutation is allowed:

```sh
sudo t2-touchid-manage verify-post-reboot
```

If the process or the machine stops during persistence, do not replay the
rename. The recovery command follows only the already-journaled direction:
discard a validated pre-commit `prepare/`, roll a complete post-boundary
`commit/` forward, or inspect the clean committed root. It then uses a fresh
stable SEP inventory to close the operation only as provably unchanged or
provably committed:

```sh
sudo t2-touchid-manage recover \
  --acknowledge-interrupted-rename-recovery
```

Any third or ambiguous state remains blocked.

## Single-identity deletion (experimental)

Single deletion is irreversible in SEP and **its first Linux hardware test has
not yet been performed.** Back up the private Catacomb, confirm password
fallback works, and list the current reconciled slots immediately before
selecting one.

First run the read-only preflight. It opens a fresh stable Bridge inventory and
resolves the slot, but creates no mutation journal and sends no delete command:

```sh
sudo t2-touchid-identities
sudo t2-touchid-manage plan-delete --slot 2
```

Review its label and before/after counts. The mutating command separately
requires both acknowledgements and refuses to delete the last identity:

```sh
sudo t2-touchid-manage delete \
  --slot 2 \
  --acknowledge-fingerprint-deletion \
  --acknowledge-local-catacomb-persistence
```

The broker journals the exact internal UID and UUID target before command
`0x0d`, then trusts only a stable SEP inventory — not the command
status — to decide whether deletion occurred. If SEP removed the identity,
the broker persists only the selected user's survivor archive and
independently reads it back. A deletion baseline likewise records password
fallback as unverified, because the credential-free path does not use it as
authority.

A reconciled deletion requires the [post-reboot proof](#concepts) of the exact
survivor set and clean Catacomb state:

```sh
sudo t2-touchid-manage verify-delete-post-reboot
```

An interruption must be reconciled, never blindly replayed:

```sh
sudo t2-touchid-manage recover-delete \
  --acknowledge-interrupted-delete-recovery
```

Recovery first journals and resolves any exact local `prepare/` or `commit/`
transaction. Fresh stable host and SEP state must then prove exactly one of
three outcomes: unchanged, already committed, or SEP-deleted and still
requiring user-component confirmation. The last case may have either the exact
old host file or the exact journaled survivor file; both run a fresh
forward-only user-Catacomb persistence transaction. Any other state remains
blocked.

Delete-all, last-identity deletion, whole-user removal, and cross-user
administration remain disabled.

## Cross-OS reconciliation

macOS and this project currently use separate host Catacombs. On the proven
dual-boot machine, macOS did not import a fingerprint enrolled only from Linux;
instead, its next boot reconciled SEP back to the identity present in macOS's
host Catacomb. Linux then retained one stale local-only record and refused to
expose an inventory.

Do not run adaptive Catacomb sync while the identity sets disagree. Repair only
the exact one-record external-deletion shape with:

```sh
sudo t2-touchid-manage reconcile-external-deletion \
  --acknowledge-external-fingerprint-removal \
  --acknowledge-local-catacomb-reconciliation
sudo systemctl restart fprintd.service
```

The command requires clean, stable, equal per-user/global SEP views; SEP must
be an exact one-identity subset of the Linux archive. It creates a root-only
backup of every local component, atomically removes only the unique local-only
record, repeats the live inventory, and proves the survivor set. It sends no
SEP enrollment, deletion, or Catacomb command.

This exact recovery was live-proven after the dual-boot divergence described
above. It created the backup, removed one stale local-only identity, reported
one reconciled survivor and no SEP mutation, and restored truthful fprintd
listing. The surviving right-index identity then passed both direct fprintd
verification and sudo/PAM authentication; the removed identity no longer
appeared, an unenrolled finger failed, and password fallback remained usable.

If interrupted, inspect and recover its journal rather than replaying it:

```sh
sudo t2-touchid-manage status
sudo t2-touchid-manage recover-external-deletion \
  --acknowledge-interrupted-external-reconciliation
```

Backups remain under
`/var/lib/t2-touchid/external-reconciliation-backups/`. This restores Linux
consistency only. Making Linux enrollment visible to and durable across macOS
requires a separate macOS host-Catacomb synchronization design.

## Security properties

- Matching is scoped to the configured macOS user ID and the identity records
  returned by SEP.
- Success requires the enrolled 16-byte identity UUID to occur in SEP's
  protocol-v2 match-result event.
- Missing, malformed, rejected, or timeout results fail closed.
- The service never emits UUIDs, fingerprint images, or biometric payloads.
- The installed fprintd service keeps native enrollment default-off and
  deletion disabled; the experimental mutation workers remain separately gated
  and fail closed.
- PAM templates are supplied but are not installed automatically.

See [`SECURITY.md`](SECURITY.md) for reporting and threat-model notes.

## Limitations

- This has only been tested on the machine and build described under
  [Proven configuration](#proven-configuration).
- The SEP kernel module is pinned after DMA registration and must not be
  unloaded; reboot before replacing it.
- The macOS-derived keybag must remain private and must be unlocked with the
  macOS login password after every reboot. The password is never stored.
- Linux-only enrollments currently do not survive a macOS boot because macOS's
  separate host Catacomb does not contain them.
- Suspend/resume is not reliable; see below.
- Multi-user operation is not supported. Only the single configured Apple user
  can authenticate.
- Never publish `*.kb`, `*.cat`, exported archives, captures, Apple binaries,
  device identifiers, or match-result payloads.

### Suspend/resume

Treat suspend as unsupported until the underlying T2 BCE resume path is fixed,
or until an alternative sleep mode has been validated on your specific Mac
model.

The failure was reproduced with the `t2bce` stack on the proven configuration.
The kernel reported repeated `NETDEV WATCHDOG` transmit timeouts for the T2's
`cdc_ncm` interface after resuming from `deep` sleep. The T2 CDC-NCM interface
may remain present while BridgeXPC is unreachable, so the systemd transport,
keybag, and fprintd services can still appear active: their existing process
state does not reflect the loss of communication with bridgeOS. Touch ID then
fails closed until the machine is rebooted.

Rebinding the `cdc_ncm` interface, and deauthorizing then reauthorizing its
virtual USB device, both recreated the interface but did not restore RemoteXPC.
**Do not unload `t2_sep_transport` as a recovery attempt**: its SEP-registered
DMA memory is deliberately pinned until reboot. The known recovery is:

1. Reboot Linux.
2. Unlock the normal and special user keybags again.
3. Restart `fprintd.service` if it is not already running.
4. Repeat both the enrolled- and unenrolled-finger controls before relying on
   PAM authentication.

`tools/collect-suspend-diagnostics.sh` collects a privacy-safe bundle; see
[`docs/SUSPEND_REPORT.md`](docs/SUSPEND_REPORT.md).

## Reporting compatibility

This has been proven on exactly one machine, so reports from other models are
the most useful contribution available. If you try this on different hardware,
a bridgeOS build, or another distribution, please open an issue with:

- the Mac model identifier, the bridgeOS build, and the BridgeXPC version;
- the Linux distribution, kernel version, T2 stack (`t2bce`/`apple-bce`), and
  `fprintd` version;
- how far you got: module load, `/dev/t2-aks` creation, keybag load, keybag
  unlock, RemoteXPC discovery, `fprintd-verify`, PAM;
- the output of `sudo t2-touchid-doctor --json`, which is designed to be safe
  to share;
- for a suspend failure, the bundle from
  `tools/collect-suspend-diagnostics.sh`.

**Redact before posting.** Never attach `*.kb` or `*.cat` files, exported
archives, packet captures, Apple binaries, device identifiers, identity UUIDs,
or match-result payloads. Run `tools/privacy-check.sh` over anything you intend
to attach.

## Repository layout

- `src/t2_sep_transport.c`: SEP endpoint-7 DMA/keybag transport.
- `src/t2-aks-tool.c`: narrowly allow-listed AppleKeyStore operations.
- `src/discover-biometric-port.py`: privacy-preserving RemoteXPC discovery.
- `src/bridge-xpc-probe.py`: BridgeXPC command and match implementation.
- `src/t2-fprintd.py`: the verification facade exposed on D-Bus.
- `src/t2-touchid-enroll.py`, `src/t2-touchid-manage.py`: the experimental
  root-only mutation brokers.
- `src/t2-touchid-doctor.py`, `src/t2-touchid-inventory.py`,
  `src/t2-touchid-identities.py`: read-only diagnostics.
- `systemd/system/`, `systemd/user/`: system units and desktop feedback units.
- `systemd/research/`: uninstalled candidate units; see
  [Development status](#development-status).
- `pam/`: clamshell-safe Omarchy PAM templates.
- `polkit/`: distinct non-transitive action definitions for future brokers.
- `tools/macos/`: private export helpers; outputs must never be committed.
- `enrollment_research/`: sanitized enrollment, multi-user, Catacomb, and
  rollback findings, plus non-mutating and deferred collection helpers.
- `tests/`: hardware-free fail-closed lifecycle tests.

Exact keybag extraction and hardware bring-up remain machine-sensitive. Read
[`src/README.md`](src/README.md) before loading the module.

## Development status

Roughly half of this repository is internal work that is deliberately not
reachable from an installed system: the multi-user mapping validator and its
administration boundary, the policy resolver, the caller/session/account
evidence collectors, the broker transaction and its seqpacket IPC, the
socket-activation adapter and client core, the keybag activation core, the
staged native fprintd enrollment and deletion path, and the endpoint-10 ACM
research transport.

- [`docs/DEVELOPMENT_STATUS.md`](docs/DEVELOPMENT_STATUS.md) describes those
  components and what still gates each of them.
- [`ROADMAP.md`](ROADMAP.md) is the evidence-based reliability checklist and
  the order in which parked work resumes.
- [`docs/FPRINT_INTEGRATION.md`](docs/FPRINT_INTEGRATION.md) records the
  caller, authorization, cancellation, recovery, and standard D-Bus lifecycle
  required before native enrollment or deletion can be exposed.
- [`enrollment_research/README.md`](enrollment_research/README.md) publishes
  the current protocol findings and evidence-collection helpers.

## Background and provenance

This project was reverse-engineered from scratch against one machine. The
redacted conversation that produced it is published here:
<https://gist.github.com/jmurth1234/4a138019fd832dfabbed26475613db3a>

## Tests

```sh
python -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python -m unittest discover -s tests -v
.venv/bin/python -m py_compile src/*.py
tools/privacy-check.sh
```

## License

This project is licensed under the GNU General Public License version 2 only
(`GPL-2.0-only`). See [`LICENSE`](LICENSE). The userspace-facing transport
header retains the standard Linux syscall-note exception.
