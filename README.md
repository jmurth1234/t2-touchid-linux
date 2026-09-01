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
The [proper fprint integration design](docs/FPRINT_INTEGRATION.md) records the
caller, authorization, cancellation, recovery, and standard D-Bus lifecycle
required before native enrollment or deletion can be exposed.
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
`fprintd`, and sudo/PAM layers. After the first Linux enrollment and a reboot,
the macOS-enrolled right index and Linux-enrolled right thumb were reconciled
and assigned the canonical `right-index-finger` and `right-thumb` labels. Both
independently return `verify-match` through an explicit
`fprintd-verify -f any` request, while an unenrolled finger returns
`verify-no-match`; named requests also select only their corresponding
identity.

## Security properties

- Matching is scoped to the configured macOS user ID and the identity records
  returned by SEP.
- Success requires the enrolled 16-byte identity UUID to occur in SEP's
  protocol-v2 match-result event.
- Missing, malformed, rejected, or timeout results fail closed.
- The service never emits UUIDs, fingerprint images, or biometric payloads.
- The installed fprintd service keeps native enrollment default-off and
  deletion disabled; experimental mutation workers remain separately gated
  and fail closed.
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
- `src/t2-fprintd.py`: verification facade with a default-off native enrollment
  activation boundary and an unattached single-name deletion adapter.
- `src/t2_fprint_deletion_runtime.py`: exact reconciled-completion contract for
  the journaled deletion client.
- `src/t2_fprint_delete_worker.py`: credential-free, caller-pidfd-bound
  transient worker for exact-name `delete-one`; installed but not attached to
  the default daemon.
- `src/t2_user_mapping.py`: non-exposed, fail-closed schema for mapping Linux
  accounts to already-provisioned Apple users and explicit capabilities.
- `src/t2_user_readiness.py`: pure classifier for per-user binding, alias, and
  lock-state evidence; it emits no AKS operation.
- `src/t2_user_policy.py`: non-exposed self-service caller/target/policy
  resolver with exact operation, boot, mapping, and authorization bindings.
- `src/t2_polkit_grant.py`: race-resistant `PID,start-time,UID` PolicyKit
  adapter that creates bounded in-process grants for the policy resolver.
- `src/t2_ipc_session.py`: `SO_PEERCRED`/`SO_PEERPIDFD` and libsystemd session
  collector that joins one live local session to the PolicyKit decision.
- `src/t2_linux_account.py`: strict local-files account-generation collector
  that detects UID/account/password/database replacement without accepting a
  caller-supplied username or generation.
- `src/t2_user_mapping_admin.py` and `t2-touchid-user-map`: crash-safe,
  root-only creation, explicit account rebinding, and separately reconciled
  enablement of protected mappings.
- `src/t2_user_reconciliation{,_live}.py`: atomic mapping-enable transaction
  over a read-only, generation-pinned Bridge/Catacomb/AKS session.
- `src/t2_user_activation_{journal,operation,recovery}.py`: transport-free
  durable activation, execution, and read-only recovery core; no CLI exists.
- `src/t2_aks_{state,observer,transport}.py`: strict operation-`0x19` state
  decoding plus an exact, non-exposed AKS observation/command adapter.
- `t2-aks-observe-test`: redacted read-only hardware validation of the
  configured alias through operations `0x06` and `0x19`.
- `t2-touchid-user-broker-gate`: redacted read-only summary of every prerequisite
  for the first staged negative mapped-user broker test; it never installs or
  starts the candidate socket.
- `systemd/`: system and audible-feedback units.
- `pam/`: clamshell-safe Omarchy PAM templates.
- `polkit/`: distinct non-transitive action definitions for future brokers.
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

7. Start `fprintd.service`. Run `fprintd-verify -f any` once with an enrolled
   finger and once with an unenrolled finger. Require `verify-match` and
   `verify-no-match`, respectively. Once canonical labels are assigned, also
   test each identity explicitly with `fprintd-verify -f FINGER-NAME`.
8. Only after those controls pass, install the relevant files from `pam/` into
   `/etc/pam.d/` with `sudo tools/install-pam.sh`. Keep password authentication
   as fallback; `sudo tools/rollback-pam.sh` restores the originals.

The installer is safe to rerun and replaces only project-managed files. When
DKMS is available it registers the transport for kernel upgrades; otherwise it
warns that the installer must be rerun after an upgrade. `sudo ./uninstall.sh`
removes code and services but preserves configuration, credentials, keybags,
and PAM backups. Add `--purge-private-data` only when those secrets should be
permanently removed; PAM restoration remains an explicit operation.
If the desktop user's systemd user manager is already running, installation
reloads it through that user's `/run/user/<uid>/bus`. If no user bus exists,
the reload is skipped quietly and the units are discovered at the next login;
the root environment is never mistaken for a desktop user session. Uninstall
uses the same bounded user-bus rule after removing the feedback units. The
root fprint daemon applies that rule at runtime as well: audible scan and
result cues are sent only through the configured user's live, owned bus socket.

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

While any reconciled label is not a unique canonical fprint finger name,
`fprintd-list` and `fprintd-verify` deliberately expose one configured logical
finger slot (for example `right-index-finger`). That compatibility slot means
“authenticate against any built-in identity owned by the configured Apple
user”; it is not an enrollment count. Use `sep_identity_count` from
`t2-touchid-inventory` for the truthful hardware identity count. Once every
label is uniquely canonical, the service automatically lists every finger,
targets a named verification to only that identity, and reports the exact
canonical identity selected by a successful `any` match.

With more than one listed finger, do not use bare `fprintd-verify` as an
all-finger control. The upstream command-line utility's "automatic" default
selects the first name returned by `ListEnrolledFingers`; it does not request
`VerifyStart("any")`. Select the intended operation explicitly:

```sh
fprintd-verify -f any "$USER"
fprintd-verify -f right-index-finger "$USER"
fprintd-verify -f right-thumb "$USER"
```

The first command accepts any reconciled enrolled identity. The named commands
deliberately restrict SEP matching to only that identity. PAM uses fprintd's
`any` verification path and is not represented by the bare utility default.

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

Check whether every reconciled identity currently has one unique canonical
fprint finger name, without changing labels or exposing identifiers:

```sh
sudo t2-touchid-fprint-status
```

`complete: false` keeps the compatibility alias in place. It means one or more
labels need an explicit anatomical assignment before truthful per-finger fprint
listing can replace that alias; the command never guesses or mutates a label.
The staged native `EnrollStart` path also refuses to run until this projection
is complete, and refuses a canonical name already present in it. This prevents
standard fprint clients from compounding ambiguous or duplicate labels before
the mutation worker starts. The transient worker independently repeats that
same rule against its fresh reconciled inventory while holding the machine-wide
operation lock, before recovery anchoring, ACM, journaling, or SEP dispatch.

The installed read-only staging gate collects the complete set of prerequisites
for the separate native-enrollment and combined identity-management research
drop-ins. Its acknowledgements are
statements about controls already performed; they do not run those controls or
authorize a mutation:

```sh
sudo t2-touchid-fprint-enrollment-gate \
  --acknowledge-two-distinct-fingers-verified-this-boot \
  --acknowledge-password-fallback-tested \
  --acknowledge-worker-negative-controls-passed
```

Exit status zero means only that an uninstalled drop-in may be staged for the
documented standard-client test. The report does not enable a worker, install a
unit, expose identifiers, or send a mutation command. The normal service has
neither activation flag. The combined research candidate resets `ExecStart`
once and supplies both `--enable-native-enrollment` and
`--enable-native-deletion`; installing either candidate remains a manual,
rollbackable research step.

The fail-closed named-match boundary double-checks both SEP identity views on
the same Bridge connection, reconciles them with the validated local Catacomb,
sends only the selected opaque identity to the matcher, and proves all identity
state is unchanged afterward. It is reached automatically only for a complete
canonical projection. With legacy labels, the compatibility alias continues to
select all enrolled identities.

The transition policy is explicit: incomplete inventories expose only the
compatibility alias, complete inventories expose the canonical per-finger
list, named verification is restricted to that exact identity, and `any`
always remains an all-identities request. The named backend verdict also
requires both the pre-match reconciliation proof and post-match unchanged-state
proof; a selected-identity match alone is insufficient. For a complete
projection, a successful `any` match is also reduced to exactly one canonical
finger name before fprintd emits `VerifyFingerSelected`; ambiguous events fail
closed and UUIDs remain private.

### Experimental Linux enrollment

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

Current development builds also install
`t2-touchid-post-reboot.service`, a credential-free read-only oneshot ordered
before fprintd. It performs the same strict E4 proof automatically, also
closes a completed label rename or single deletion with that transaction's
typed post-reboot proof, and leaves any journal untouched on a mismatch. Manual
commands remain diagnostic fallbacks until the automatic service has passed
the installed hardware controls documented in the roadmap.

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
`-AppleUID`; callers cannot supply an alias.

The internal policy resolver now consumes that mapping together with
authenticated-caller, active-session, fresh policy-grant, and readiness
evidence. It permits only self-service, gives root no implicit bypass, binds a
grant to the exact caller, target, Linux account generation, mapping generation,
operation UUID, Linux boot, live Bridge connection generation, action, and a
bounded monotonic lifetime, and keeps verification, inventory, enrollment, and
identity-management actions non-transitive. A separate `activate-user` grant
is mandatory before a locked or absent alias may enter the keybag activation
core. Immediately before its first AKS operation, that core rejects a changed
Bridge generation or an expired operation/activation grant; the activation
journal then uses the same bound operation UUID.

The non-exposed IPC/session adapter now obtains those inputs directly from a
connected Unix socket using `SO_PEERCRED` and `SO_PEERPIDFD`. It keeps the peer
pidfd open, reads the kernel process start time and all four process UIDs,
resolves the exact process through libsystemd's pidfd API, and requires one
active, local, physical-seat user session. Apps launched through the user
manager may use a same-UID fallback only when exactly one acceptable active
session exists. Session ID/start time and process identity are checked again
after PolicyKit returns. PID reuse, setuid subjects, session switching, remote
or greeter sessions, unknown actions, cross-user targets, timeouts, and
ambiguous exits never create an authorized grant. There is still no public
multi-user socket. The internal request protocol is now canonical Unix
`SOCK_SEQPACKET` framing. It supports a read-only `preflight` for one named
operation and an `identities` command fixed to the inventory policy. It accepts
no UID, UUID, alias, keybag path, raw operation number, or file descriptor; its
bounded responses expose only policy/readiness state, synchronous read-only
handoff proof, and—only for authorized inventory—the reconciled labels. The
internal `t2_user_broker.py` transaction now keeps one pinned peer, mapping
writer lock, biometric operation
lock, Bridge generation, stable live evidence, and both policy grants together
through a synchronous consumer handoff. It derives the target from the kernel
peer UID and never accepts an Apple identifier from the request. Public request
exposure, operation-specific mutating consumers, and per-user relocking remain
incomplete.

The first operation-specific consumer and its dispatcher are also internal and
read-only. The live session retains a canonical identifier-free identity list
only after the exact
local Catacomb, per-user SEP list, global SEP list, clean Catacomb state, alias
binding, and Bridge generation have survived the broker's stable recollection.
The `inventory` policy handoff can return only sequential slots, labels, count,
and reconciliation flags. It cannot collect activation authority, select a
different user, expose UUIDs, or perform a T2 mutation. A one-request dispatcher
selects only `preflight` or the exact `identities/inventory` pair and returns one
canonical response. No public socket invokes it yet.

The non-installed socket-activation adapter is the final process boundary before
that future socket. It delegates activation-environment validation to
libsystemd, requires exactly one `Accept=yes` descriptor named `connection`,
then independently proves it is a connected, non-listening Unix seqpacket
socket. The root process dispatches one request and closes the descriptor on
every outcome. No daemon loop, socket path, unit, PATH command, or enablement is
installed yet.

The matching non-exposed client core sends exactly one canonical request and
receives one bounded seqpacket response with the same truncation/ancillary-data
rejection. It requires a preflight response to repeat the requested operation
and an identities request to receive only the inventory response shape. It has
no socket path, connection constructor, fallback command, or installed CLI.

Candidate systemd units and the fixed read-only entry point now live under
`systemd/research/` and `src/`, respectively. They use `Accept=yes`, bounded
connection/trigger limits, one process per connected seqpacket, and a service
sandbox restricted to the Bridge IPv6 path, local Unix/D-Bus, `/dev/t2-aks`,
and the lock paths required by the broker. They contain no `[Install]` section,
are deliberately omitted from `install.sh`, and must not be copied or started
until the documented module, operation-`0x06`, fingerprint-survivor, mapping,
and negative-caller gates all pass.

The same adapter now derives the caller's account generation itself rather than
accepting an opaque digest from its future client. The deliberately conservative
`local-files-v2` profile resolves the kernel UID to one exact root-owned
`/etc/passwd` row, requires an agreeing NSS result and protected `/etc/shadow`
row, and binds the passwd database epoch plus the UID-owned home-directory's
filesystem ID, inode, and birth-time object. It deliberately excludes the
boot-local statx mount ID. It collects the assertion again after
PolicyKit and requires byte-exact evidence equality. Account recreation,
password/account edits, home replacement,
or any passwd-database rewrite therefore disables the old mapping until an
administrator explicitly rebinds it. This profile intentionally does not claim
support for LDAP, systemd-homed, or other account stores lacking an equivalent
stable assertion.

`t2-touchid-user-map` is the root-only administration boundary for that state.
It writes only `/var/lib/t2-touchid/users.json`, holds a private same-directory
lock, validates the exact old generation before replacement, writes a mode-0600
temporary file, fsyncs it, publishes with atomic rename/no-replace semantics,
fsyncs the directory, and requires exact read-back. It derives the Linux
account generation and canonical per-UID keybag digest itself. New bindings and
all rebindings are forcibly disabled—even if the old record was enabled. A
changed passwd database is never adopted by `status` or normal runtime.

The disabled provisioning shape is:

```sh
sudo install -d -o root -g root -m 0700 \
  /var/lib/t2-touchid/users/<linux-uid>
sudo install -o root -g root -m 0600 <verified-keybag> \
  /var/lib/t2-touchid/users/<linux-uid>/user.kb
sudo t2-touchid-user-map bind-current-disabled \
  --linux-uid <linux-uid> \
  --unlock-mode password-on-demand \
  --capability verify \
  --acknowledge-current-apple-authority-is-already-provisioned
sudo t2-touchid-user-map status --linux-uid <linux-uid>
```

The command takes no Apple UID or UUID arguments. It derives the configured
Apple user and alias from the root-private configuration, holds the biometric
operation lock, and obtains the exact account/bag UUIDs through stable read-only
AKS operations `0x06`/`0x19`. Private authority therefore never enters argv,
shell history, or command output. The new record is still forced disabled. If
the local account generation later changes, the only host-side path is the
explicit `rebind-disabled` acknowledgement. That transition preserves the
Apple/keybag/capability fields, replaces only the account generation, and
forces the result disabled. Neither command is an enable procedure.

Enablement is a separate read-only live reconciliation transaction. It holds
the mapping writer lock, then the machine-wide biometric operation lock and one
Bridge generation; collects the local Catacomb, stable SEP inventory, live AKS
bag UUID, private AKS account UUID, and lock state twice; rechecks the Linux
account and keybag between those collections; and requires exact equality. It
also requires a clean SEP Catacomb, exact local/live identity equality, a ready
known lock state, and successful readiness evaluation for every stored
capability. Only then does it atomically flip that one exact record to enabled.
The session interface has no T2 mutation method. A failure after publication is
outcome-unknown and must be inspected with `status`, never blindly retried.

```sh
sudo t2-touchid-user-map enable-reconciled \
  --linux-uid <linux-uid> \
  --acknowledge-live-apple-aks-catacomb-reconciliation-and-enable
```

The read-only operation-`0x06` hardware gate has passed on the proven machine
with the rebuilt live module. Enablement still does not provision Apple users,
create keybags, activate aliases, unlock a bag, or mutate fingerprints.

Revocation never depends on the T2, Bridge network, Catacomb, account, or
keybag remaining available. An administrator can atomically force an enabled
record disabled at any time:

```sh
sudo t2-touchid-user-map disable \
  --linux-uid <linux-uid> \
  --acknowledge-immediate-mapping-revocation
```

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
not-ready, blocked, or quarantined.

The concrete adapter now uses the matching kext's exact read-only endpoint-7
operation `0x06` to double-read a handle's live bag UUID and strictly decodes
the proven operation-`0x19` DER state dictionary around that read. Any alias,
bag UUID, account UUID, handle, file-mode, schema, or lock-state instability
fails closed. The same adapter composes the existing load/bind/unlock commands
and sends password
bytes through a pipe, never argv or the environment. It remains non-exposed:
there is no public activation command or automatic recovery path. The rebuilt
kernel allowlist and observer have now passed their first read-only hardware
validation. The diagnostic derives the alias from protected configuration,
takes the machine-wide operation lock, and prints no identifiers:

```sh
sudo t2-aks-observe-test
```

Before any mapped-user broker exposure, collect all of its independent gates in
one identifier-free report. The acknowledgement is valid only after two
distinct enrolled fingers have each matched during the current boot:

```sh
sudo t2-touchid-user-broker-gate \
  --acknowledge-two-distinct-fingers-verified-this-boot
```

The report distinguishes the reconciled T2 identity count from fprintd's one
compatibility alias. A successful report means only that an unmapped/inactive
caller negative test may be staged; the candidate socket remains uninstalled.

Legacy/macOS labels such as `Finger 1` and early Linux research labels cannot
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
presented, list again, and then rename that exact slot to one of fprint's
canonical names (`left-thumb`, `right-index-finger`, and so on). Never infer
the anatomical name from the old compatibility alias. Rename refuses a label
already assigned to another identity. Its result reports whether every label
now forms a unique canonical fprint projection; until that becomes true,
fprintd deliberately keeps exposing the single compatibility alias.

Rename one current identity label (this does not alter its fingerprint
template). For fprint migration, preview and commit only a canonical anatomical
name:

Successful matching can update a template adaptively and set the SEP user
Catacomb's save bit. Before enrollment, rename, deletion, or first mapping
enablement, persist that existing update with the exact Apple user-then-master
save order. The command changes no identity UUID, label, or count, requires an
explicit protected `verify` capability (an enabled mapping is not required for
initial bootstrap), and journals host commit before final SEP confirmation:

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

Automatic post-match persistence is installed but defaults off. To opt in,
set the following exact root-owned configuration value, then restart fprintd:

```ini
T2_TOUCHID_AUTO_SYNC_ADAPTIVE=1
```

```sh
sudoedit /etc/t2-touchid.conf
sudo systemctl restart fprintd.service
```

This opt-in acknowledges that every successful match may update authenticated
template state and the committed local Catacomb. fprintd emits the terminal
authentication verdict first, then asks the static
`t2-touchid-adaptive-sync.service` to run the same journaled user-then-master
operation. Scheduling or persistence failure cannot replace a successful
authentication verdict; the unit and mutation journal retain diagnostic or
blocking state instead. Negative and unknown matches never schedule a write.
The oneshot waits two seconds before collection so late match/cancel callbacks
can settle; multiple requests during that interval coalesce into the same save.
Set the value back to `0` and restart fprintd to disable automatic persistence.

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

The broker resolves the slot only against a fresh reconciled list, holds the
global operation lock and a verified sleep inhibitor, writes durable intent
before dispatch, persists exactly the selected user's Catacomb, and performs
same-connection independent read-back. Rename is credential-free, so its
generic mutation baseline truthfully records that password fallback was not
verified; that field is not used as rename authority. A successful rename remains the only
blocking mutation until it survives a different Linux boot and Bridge
connection. The credential-free boot service now performs this read-only proof
automatically before fprintd starts; the manual command remains available for
diagnosis:

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
deletion baseline likewise records password fallback as unverified because
the credential-free path does not use it as authority. A reconciled deletion
remains blocking until a different Linux boot and Bridge
connection prove the exact survivor set and clean Catacomb state. The same
credential-free boot service performs that read-only proof automatically; the
manual command remains available for diagnosis:

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
