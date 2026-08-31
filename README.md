# Intel T2 Touch ID for Linux

Experimental, fail-closed Touch ID authentication for Intel Macs with an Apple
T2 chip. It talks to bridgeOS BiometricKit over BridgeXPC and exposes a minimal
`fprintd`-compatible D-Bus service for PAM clients.

This is research software, not an upstream `libfprint` driver. Verification and
two live identities, including one enrolled entirely from Linux, have been
proven on the configuration below. Label rename
is exposed through a separately gated management broker. Single-identity
deletion is implemented behind explicit acknowledgements but has not yet had
its first live hardware test; macOS remains the recovery environment.

See [`ROADMAP.md`](ROADMAP.md) for the evidence-based reliability checklist.
The separate [enrollment research](enrollment_research/README.md) publishes the
current protocol findings and evidence-collection helpers. The fprintd service
does not expose enrollment or deletion; experimental mutation commands use
separate root-only, journaled brokers.

The in-development endpoint-10 transport is separately opt-in. Setting
`T2_TOUCHID_ENABLE_ACM_RESEARCH=1` in the private root-owned configuration
registers dedicated ACM DMA buffers on the next boot and creates a root-only
`/dev/t2-acm`. This still does not enable enrollment or expose a generic raw
command CLI. `sudo t2-acm-preflight` only verifies registration metadata and
performs no SEP mutation. The separately installed
`t2-acm-lifecycle-test --acknowledge-transient-context-mutation` performs one
root-only, UID-bound tracking-context create followed by mandatory deletion; it
does not enroll or delete a fingerprint. Use it only on an already backed-up
research machine. The kernel grants one endpoint-10 owner and one context lease
at a time, attempts context deletion when that owner exits, and disables the
endpoint until reboot after a timeout or ambiguous create response so a late
reply cannot be reused. Because SEP retains the DMA addresses, changing this
setting requires a reboot; never unload the active module.

See the redacted conversation that produced this here: https://gist.github.com/jmurth1234/4a138019fd832dfabbed26475613db3a

## Proven configuration

Developed and verified on an Intel `MacBookPro16,2`, bridgeOS build `23P1072`,
BridgeXPC 39, and Omarchy/Arch Linux. A positive right-index control and a
negative unenrolled-finger control were both verified at the raw bridge,
`fprintd`, and sudo/PAM layers.

## Security properties

- Matching is scoped to the configured macOS user ID and the identity records
  returned by SEP.
- Success requires the enrolled 16-byte identity UUID to occur in SEP's
  protocol-v2 match-result event.
- Missing, malformed, rejected, or timeout results fail closed.
- The service never emits UUIDs, fingerprint images, or biometric payloads.
- fprintd enrollment and deletion are deliberately unsupported; experimental
  root-only brokers are separate and fail closed.
- PAM templates are supplied but are not installed automatically.

## Important limitations

- This has only been tested on the machine/build above.
- The SEP kernel module is pinned after DMA registration and must not be
  unloaded; reboot before replacing it.
- The macOS-derived keybag must remain private and must be unlocked with the
  macOS login password after every reboot. The password is never stored.
- Suspend/resume is not currently reliable on the proven configuration. After
  a deep-S3 suspend, the T2 CDC-NCM interface may remain present while
  BridgeXPC is unreachable. Touch ID then fails closed until the machine is
  rebooted and the keybags are unlocked again.
- Never publish `*.kb`, `*.cat`, exported archives, captures, Apple binaries,
  device identifiers, or match-result payloads.

### Suspend/resume failure

This was reproduced with the `t2bce` stack on the proven configuration. The
kernel reported repeated `NETDEV WATCHDOG` transmit timeouts for the T2's
`cdc_ncm` interface after resuming from `deep` sleep. The systemd transport,
keybag, and fprintd services could still appear active because their existing
process state did not reflect loss of communication with bridgeOS.

Rebinding the `cdc_ncm` interface and deauthorizing/reauthorizing its virtual
USB device both recreated the interface but did not restore RemoteXPC. Do not
unload `t2_sep_transport` as a recovery attempt: its SEP-registered DMA memory
is deliberately pinned until reboot. The known recovery is:

1. Reboot Linux.
2. Unlock the normal and special user keybags again as described below.
3. Restart `fprintd.service` if it is not already running.
4. Repeat both the enrolled- and unenrolled-finger controls before relying on
   PAM authentication.

Treat suspend as unsupported until the underlying T2 BCE resume path is fixed
or an alternative sleep mode has been validated on the specific Mac model.

## Layout

- `src/t2_sep_transport.c`: SEP endpoint-7 DMA/keybag transport.
- `src/t2-aks-tool.c`: narrowly allow-listed AppleKeyStore operations.
- `src/discover-biometric-port.py`: privacy-preserving RemoteXPC discovery.
- `src/bridge-xpc-probe.py`: BridgeXPC command and match implementation.
- `src/t2_bridge_connection.py`: exclusive generation-pinned Bridge owner used
  by the no-CLI enrollment research coordinator.
- `src/t2-fprintd.py`: verification-only fprintd facade.
- `src/t2_user_mapping.py`: non-exposed, fail-closed schema for mapping Linux
  accounts to already-provisioned Apple users and explicit capabilities.
- `src/t2_user_readiness.py`: pure classifier for per-user binding, alias, and
  lock-state evidence; it emits no AKS operation.
- `src/t2_user_activation_{journal,operation,recovery}.py`: transport-free
  durable activation, execution, and read-only recovery core; no CLI exists.
- `systemd/`: system and audible-feedback units.
- `pam/`: clamshell-safe Omarchy PAM templates.
- `tools/macos/`: private export helpers; outputs must never be committed.
- `enrollment_research/`: sanitized enrollment, multi-user, Catacomb, and
  rollback findings plus non-mutating/deferred collection helpers.
- `tests/`: hardware-free fail-closed lifecycle tests.

## Installation outline

1. Keep macOS available and enroll exactly the finger you intend to use.
2. Run the export helpers from macOS and transfer outputs privately.
3. On Linux, identify the T2 USB-network interface and link-local IPv6 address,
   then run `sudo ./install.sh`. Edit `/etc/t2-touchid.conf` when prompted,
   including the numeric macOS user ID and its corresponding special bag.
4. Start `t2-sep-transport.service`. The installer builds the module for the
   running kernel and configures PCI autoload with `register_ool=1`. The loader
   accepts an already operational module and can safely replace an early
   observation-only instance; it never unloads an instance that registered SEP
   DMA. After `/dev/t2-aks` exists, do not unload the module: reboot before
   rebuilding or replacing it. Re-run the installer after a kernel upgrade.
5. Place the extracted keybag at `/var/lib/t2-touchid/user.kb`, owned by root
   and mode `0600`, then start `t2-keybag-load.service`.
6. Unlock the loaded normal handle and special user bag with the macOS password:

   ```sh
   sudo /usr/local/sbin/t2-aks-tool unlock-keybag 1 HANDLE
   sudo /usr/local/sbin/t2-aks-tool unlock-keybag 1 SPECIAL_BAG
   ```

7. Start `fprintd.service`. Run `fprintd-verify` once with the enrolled finger
   and once with an unenrolled finger. Require `verify-match` and
   `verify-no-match`, respectively.
8. Only after those controls pass, install the relevant files from `pam/` into
   `/etc/pam.d/` with `sudo tools/install-pam.sh`. Keep password authentication
   as fallback; `sudo tools/rollback-pam.sh` restores the originals.

The installer is safe to rerun and replaces only project-managed files. When
DKMS is available it registers the transport for kernel upgrades; otherwise it
warns that the installer must be rerun after an upgrade. `sudo ./uninstall.sh`
removes code and services but preserves configuration, credentials, keybags,
and PAM backups. Add `--purge-private-data` only when those secrets should be
permanently removed; PAM restoration remains an explicit operation.

### Unlocking keybags from password authentication

If the macOS and Linux login passwords are identical, PAM can pass the password
already entered by the user to the keybag unlock helper. The password is kept
only in process memory and is not placed in argv, the environment, logs, or
persistent storage. The helper reads the boot-specific handle recorded under
`/run` by `t2-keybag-load.service` and always exits successfully so a T2 failure
cannot block password authentication.

After making a root-owned backup, add this at the end of the `auth` section in
`/etc/pam.d/system-auth`, after the successful `pam_faillock.so authsucc` line:

```text
auth optional pam_exec.so quiet expose_authtok seteuid /usr/local/sbin/t2-pam-unlock
```

Omarchy uses SDDM autologin followed by a separate lock-screen PAM service, so
the initial desktop password does not traverse `system-auth`. On Omarchy, also
install `pam/omarchy-lock-password` as `/etc/pam.d/omarchy-lock-password`
after backing up the existing file. That template contains the same optional
hook after its successful `pam_faillock.so authsucc` line.

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

With an unattended credential present, `t2-biometric-ready.service` also waits
for the T2 network path, discovers the dynamic RemoteXPC port, and performs a
non-matching initialization/calibration/identity-list warm-up before fprintd
starts. This avoids exposing the first Omarchy lock-screen scan to the cold
BiometricKit startup race observed on the proven configuration. Its verified
dynamic port is cached root-only under `/var/lib/t2-touchid`; fprintd consumes
that cache and does not request a finger until discovery has completed. Cold
boot authentication has been verified with sudo, including after installing
the current configurable-identity and endpoint-recovery changes. Touch ID
unlock through an explicit `omarchy system lock` has also been verified on the proven
configuration, including wrong-finger rejection and password fallback; other
shell/login configurations may use a different PAM path.

## Diagnostics

Run the privacy-safe health report as root so it can inspect root-only runtime
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

Query the live SEP identity count and owner/layout consistency without exposing
template UUIDs:

```sh
sudo t2-touchid-inventory
```

`fprintd-list` and `fprintd-verify` deliberately expose one configured logical
finger slot (for example `right-index-finger`). That slot means “authenticate
against any built-in identity owned by the configured Apple user”; it is not an
enrollment count. Use `sep_identity_count` from `t2-touchid-inventory` for the
truthful hardware identity count. Multiple enrolled fingers can therefore all
match while fprintd continues to list one logical slot.

List the reconciled local labels as numbered management slots:

```sh
sudo t2-touchid-identities
```

This command holds the same exclusive operation lock used by enrollment,
strictly decodes the committed local Catacomb, performs a fresh stable SEP
double-read, and requires exact equality between the local, configured-user,
and global built-in identity sets. It prints only current-list slot numbers and
labels; UUIDs, entities, Catacomb identifiers, and biometric data remain
redacted. A slot number is valid only for that reconciled invocation and is the
selector used by identity management commands.

### Experimental Linux enrollment

The stable command frontend exposes the proven journaled enrollment broker
without adding enrollment to fprintd. Check the redacted state first, then run
the non-mutating preflight after confirming password fallback works:

```sh
sudo t2-touchid-enroll status
sudo t2-touchid-enroll list
sudo t2-touchid-enroll preflight \
  --acknowledge-password-fallback-tested
```

To enroll one fingerprint, keep macOS available as the recovery environment
and explicitly acknowledge both the live SEP mutation and local Catacomb
persistence:

```sh
sudo t2-touchid-enroll start \
  --name "Linux enrolled finger" \
  --acknowledge-password-fallback-tested \
  --acknowledge-live-fingerprint-enrollment \
  --acknowledge-local-catacomb-mutation
```

Follow the lift/place prompts until completion. A completed enrollment remains
the only blocking mutation until the exact identity and Catacomb state are
proved after a different Linux boot and Bridge connection:

```sh
sudo t2-touchid-enroll verify-post-reboot
```

Do not simply repeat `start` after an interruption or ambiguous result. Inspect
`status`, then use only the recovery path it identifies:

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
is the authoritative human-readable view of the real enrolled identities;
fprintd's one compatibility slot remains an authentication selector, not a
template count.

Multi-user live operation is not enabled. The repository now contains a pure
mapping validator as a prerequisite: it binds each numeric Linux UID and
account generation to one already-provisioned Apple UID, account UUID, AKS bag
UUID, canonical private keybag path/digest, unlock mode, and explicit
`verify`/`enroll`/`identity-management` capabilities. It rejects duplicate
Apple authority across Linux accounts and derives the special alias as
`-AppleUID`; callers cannot supply an alias. No command consumes this mapping
yet, because per-user bag activation, relocking, and runtime reconciliation
must be implemented and proven first.

The accompanying pure readiness classifier already defines the fail-closed
outcomes for that future runtime: absent aliases require activation and fresh
read-back; alias/bag collisions, Catacomb corruption, binding drift, and unknown
lock-state bits quarantine the mapping; lockout and first-unlock states require
the appropriate password recovery/bootstrap path. Only a fully reconciled
alias with the expected bag and known-safe lock state is match-ready. This is a
tested policy model, not a command that loads or unlocks another user's bag.

The activation core is implemented behind injected interfaces only. It
durably records load intent before obtaining a temporary handle, verifies that
handle's independently observed bag UUID, records bind intent before selecting
the derived alias, re-reads the alias regardless of the command return, and
records unlock intent before using a wipeable password buffer. It trusts only
the final readiness observation: a lost bind/unlock reply can succeed when
read-back proves the exact ready state, while a lost load handle, missing
read-back, or post-mutation journal failure becomes outcome-unknown without a
retry. Its recovery core requires a fresh runtime generation and the exact
protected mapping, performs one read-only alias observation, and never retries
or cleans up an unknown handle. It closes only as observed ready, observed
not-ready, blocked, or quarantined. There is still no concrete transport,
public command, or automatic recovery path.

Rename one current identity label (this does not alter its fingerprint
template or fprintd's compatibility-slot name):

```sh
sudo t2-touchid-manage status
sudo t2-touchid-identities
sudo t2-touchid-manage rename \
  --slot 2 \
  --name "New label" \
  --acknowledge-identity-label-mutation \
  --acknowledge-local-catacomb-persistence
```

The broker resolves the slot only against a fresh reconciled list, holds the
global operation lock and a verified sleep inhibitor, writes durable intent
before dispatch, persists exactly the selected user's Catacomb, and performs
same-connection independent read-back. A successful rename remains the only
blocking mutation until it survives a different Linux boot and Bridge
connection:

```sh
sudo t2-touchid-manage verify-post-reboot
```

If the process or machine stops during persistence, do not replay the rename.
The recovery command follows only the already-journaled direction: discard a
validated pre-commit `prepare/`, roll a complete post-boundary `commit/`
forward, or inspect the clean committed root. It then uses a fresh stable SEP
inventory to close the operation only as provably unchanged or provably
committed:

```sh
sudo t2-touchid-manage recover \
  --acknowledge-interrupted-rename-recovery
```

Any third or ambiguous state remains blocked.

### Experimental single-identity deletion

Single deletion is irreversible in SEP and its first Linux hardware test has
not yet been performed. Back up the private Catacomb, confirm password fallback
works, and list the current reconciled slots immediately before selecting one.
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

The broker journals the exact internal UID+UUID target before command `0x0d`,
then trusts only a stable SEP inventory—not the command status—to decide
whether deletion occurred. If SEP removed the identity, the broker persists
only the selected user's survivor archive and independently reads it back. A
reconciled deletion remains blocking until a different Linux boot and Bridge
connection prove the exact survivor set and clean Catacomb state:

```sh
sudo t2-touchid-manage verify-delete-post-reboot
```

An interruption must be reconciled, never blindly replayed:

```sh
sudo t2-touchid-manage recover-delete \
  --acknowledge-interrupted-delete-recovery
```

Recovery first journals and resolves any exact local `prepare/` or `commit/`
transaction. Fresh stable host/SEP state must then prove exactly one of three
outcomes: unchanged, already committed, or SEP-deleted and still requiring
user-component confirmation. The last case may have either the exact old host
file or the exact journaled survivor file; both run a fresh forward-only
user-Catacomb persistence transaction. Any other state remains blocked.
Delete-all, last-identity
deletion, whole-user removal, and cross-user administration remain disabled.

This read-only command performs two exact back-to-back collections and fails if
the private global/per-user identity records, capacity replies, Catacomb
UUID/hash/state, or secure-key-store lock state change between them. It also
requires protocol-v2 global identities to reconcile with the configured user's
detail records. It exposes only counts, presence, query status, and equality—not
identity or Catacomb UUIDs/hashes. Maximum capacity and configured-user free
capacity remain separate because their arithmetic scope is not yet proven. The
command is the read-only inventory gate used by enrollment and deletion
research; it does not mutate biometric state.

On bridgeOS 23P1072, a completed enrollment may carry an embedded owner field
that disagrees with the configured Apple user even though the authoritative
SEP inventories add the identity to that user. Such a result is treated only
as a terminal completion witness: its UUID is discarded, and enrollment can
complete only when a stable double-read proves exactly one new built-in
identity in both the configured-user and global inventories, with unchanged
account, keybag, mapping, and local Catacomb state. This is the path validated
by the first Linux enrollment, which persisted and matched independently
alongside the original macOS-enrolled finger after reboot.

This machine has no usable TPM, so the credential is encrypted with systemd's
host key. It protects against casual/offline disclosure without the decrypted
Linux filesystem, but root can decrypt it. Since the credential is also the
Linux and macOS login password on the proven configuration, understand this
tradeoff before provisioning it.

Exact keybag extraction and hardware bring-up remain machine-sensitive. Read
`src/README.md` before loading the module.

## Tests

```sh
python -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python -m unittest discover -s tests -v
python -m py_compile src/*.py
tools/privacy-check.sh
```

## License

This project is licensed under the GNU General Public License version 2 only
(`GPL-2.0-only`). See [`LICENSE`](LICENSE). The userspace-facing transport
header retains the standard Linux syscall-note exception.
