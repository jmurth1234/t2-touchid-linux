# Intel T2 Touch ID for Linux

Experimental, fail-closed Touch ID authentication for Intel Macs with an Apple
T2 chip. It talks to bridgeOS BiometricKit over BridgeXPC and exposes a minimal
`fprintd`-compatible D-Bus service for PAM clients.

This is research software, not an upstream `libfprint` driver. Enrollment and
deletion remain in macOS. The Linux side only verifies an identity already
enrolled for the configured macOS user ID.

See [`ROADMAP.md`](ROADMAP.md) for the evidence-based reliability checklist.
The separate [enrollment research](enrollment_research/README.md) publishes the
current protocol findings and deferred evidence-collection helpers. It does not
enable enrollment or deletion in the shipped service.

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
- Enrollment and deletion are deliberately unsupported on Linux.
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
- `src/t2-fprintd.py`: verification-only fprintd facade.
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

This read-only command performs two exact back-to-back collections and fails if
the private global/per-user identity records, capacity replies, Catacomb
UUID/hash/state, or secure-key-store lock state change between them. It also
requires protocol-v2 global identities to reconcile with the configured user's
detail records. It exposes only counts, presence, query status, and equality—not
identity or Catacomb UUIDs/hashes. Maximum capacity and configured-user free
capacity remain separate because their arithmetic scope is not yet proven. This
is the inventory gate for future enrollment and deletion operations; it does
not mutate biometric state.

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
