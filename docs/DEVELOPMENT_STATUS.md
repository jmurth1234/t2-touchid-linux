# Development status: internal and non-exposed components

This document describes work that exists in the repository but that a user
cannot invoke. Nothing here is reachable from the installed service, and none
of it enables enrollment, deletion, or multi-user operation. It is recorded so
the design can be reviewed before any of it is exposed.

For the evidence-based checklist and the order in which this work resumes, see
[`../ROADMAP.md`](../ROADMAP.md). For the caller, authorization, cancellation,
recovery, and D-Bus lifecycle required before native `fprintd` enrollment or
deletion can be exposed, see
[`FPRINT_INTEGRATION.md`](FPRINT_INTEGRATION.md).

The terms *operation lock*, *mutation journal*, *post-reboot proof*,
*generation pinning*, and *compatibility alias* are defined in the README's
Concepts section.

## Contents

- [Multi-user mapping](#multi-user-mapping)
- [Mapping administration (`t2-touchid-user-map`)](#mapping-administration-t2-touchid-user-map)
- [Policy resolver](#policy-resolver)
- [Caller, session, and account evidence](#caller-session-and-account-evidence)
- [Broker transaction and IPC](#broker-transaction-and-ipc)
- [Socket-activation adapter and client core](#socket-activation-adapter-and-client-core)
- [Candidate systemd units](#candidate-systemd-units)
- [Keybag activation core](#keybag-activation-core)
- [Native fprintd enrollment and deletion staging](#native-fprintd-enrollment-and-deletion-staging)
- [Endpoint-10 / ACM research transport](#endpoint-10--acm-research-transport)
- [Staging gates](#staging-gates)

## Multi-user mapping

Multi-user live operation is not enabled. The repository contains a pure
mapping validator as a prerequisite. It binds each numeric Linux UID and
account generation to one already-provisioned Apple UID, account UUID, AKS bag
UUID, canonical private keybag path and digest, unlock mode, and explicit
`verify` / `enroll` / `identity-management` capabilities. It rejects duplicate
Apple authority across Linux accounts and derives the special alias as
`-AppleUID`; callers cannot supply an alias.

The accompanying pure readiness classifier defines the fail-closed outcomes for
that future runtime:

- an absent alias requires activation and a fresh read-back;
- alias/bag collisions, Catacomb corruption, binding drift, and unknown
  lock-state bits quarantine the mapping;
- lockout and first-unlock states require the appropriate password recovery or
  bootstrap path.

Only a fully reconciled alias with the expected bag and a known-safe lock state
is match-ready. This is a tested policy model, not a command that loads or
unlocks another user's bag.

## Mapping administration (`t2-touchid-user-map`)

`t2-touchid-user-map` is the root-only administration boundary for that state.
It is installed, but every record it can create or change is forced disabled,
so it does not enable multi-user Touch ID.

It writes only `/var/lib/t2-touchid/users.json`, holds a private
same-directory lock, validates the exact old generation before replacement,
writes a mode-0600 temporary file, fsyncs it, publishes with atomic
rename/no-replace semantics, fsyncs the directory, and requires exact
read-back. It derives the Linux account generation and canonical per-UID keybag
digest itself. New bindings and all rebindings are forcibly disabled, even when
the old record was enabled. A changed passwd database is never adopted by
`status` or by normal runtime.

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
operation lock, and obtains the exact account and bag UUIDs through the stable
read-only AKS operations `0x06` and `0x19`. Private authority therefore never
enters argv, shell history, or command output.

If the local account generation later changes, the only host-side path is the
explicit `rebind-disabled` acknowledgement. That transition preserves the
Apple, keybag, and capability fields, replaces only the account generation, and
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

## Policy resolver

The internal policy resolver consumes that mapping together with
authenticated-caller, active-session, fresh policy-grant, and readiness
evidence. It permits only self-service and gives root no implicit bypass. A
grant is bound to all of:

- the exact caller;
- the exact target;
- the Linux account generation;
- the mapping generation;
- the operation UUID;
- the Linux boot;
- the live Bridge connection generation;
- the action;
- a bounded monotonic lifetime.

Verification, inventory, enrollment, and identity-management actions are
non-transitive. A separate `activate-user` grant is mandatory before a locked
or absent alias may enter the keybag activation core. Immediately before its
first AKS operation, that core rejects a changed Bridge generation or an
expired operation/activation grant; the activation journal then uses the same
bound operation UUID.

## Caller, session, and account evidence

The non-exposed IPC/session adapter obtains those inputs directly from a
connected Unix socket using `SO_PEERCRED` and `SO_PEERPIDFD`. It keeps the peer
pidfd open, reads the kernel process start time and all four process UIDs,
resolves the exact process through libsystemd's pidfd API, and requires one
active, local, physical-seat user session. Apps launched through the user
manager may use a same-UID fallback only when exactly one acceptable active
session exists. Session ID, session start time, and process identity are
checked again after PolicyKit returns. PID reuse, setuid subjects, session
switching, remote or greeter sessions, unknown actions, cross-user targets,
timeouts, and ambiguous exits never create an authorized grant.

The same adapter derives the caller's account generation itself rather than
accepting an opaque digest from its future client. The deliberately
conservative `local-files-v2` profile resolves the kernel UID to one exact
root-owned `/etc/passwd` row, requires an agreeing NSS result and a protected
`/etc/shadow` row, and binds the passwd database epoch plus the UID-owned home
directory's filesystem ID, inode, and birth-time object. It deliberately
excludes the boot-local statx mount ID. It collects the assertion again after
PolicyKit and requires byte-exact evidence equality. Account recreation,
password or account edits, home replacement, or any passwd-database rewrite
therefore disables the old mapping until an administrator explicitly rebinds
it. This profile intentionally does not claim support for LDAP,
systemd-homed, or other account stores lacking an equivalent stable assertion.

## Broker transaction and IPC

There is no public multi-user socket. The internal request protocol is
canonical Unix `SOCK_SEQPACKET` framing. It supports a read-only `preflight`
for one named operation and an `identities` command fixed to the inventory
policy. It accepts no UID, UUID, alias, keybag path, raw operation number, or
file descriptor; its bounded responses expose only policy and readiness state,
synchronous read-only handoff proof, and — only for authorized inventory — the
reconciled labels.

The internal `t2_user_broker.py` transaction keeps one pinned peer, the mapping
writer lock, the biometric operation lock, the Bridge generation, stable live
evidence, and both policy grants together through a synchronous consumer
handoff. It derives the target from the kernel peer UID and never accepts an
Apple identifier from the request. Public request exposure,
operation-specific mutating consumers, and per-user relocking remain
incomplete.

The first operation-specific consumer and its dispatcher are also internal and
read-only. The live session retains a canonical identifier-free identity list
only after the exact local Catacomb, per-user SEP list, global SEP list, clean
Catacomb state, alias binding, and Bridge generation have survived the broker's
stable recollection. The `inventory` policy handoff can return only sequential
slots, labels, count, and reconciliation flags. It cannot collect activation
authority, select a different user, expose UUIDs, or perform a T2 mutation. A
one-request dispatcher selects only `preflight` or the exact
`identities`/`inventory` pair and returns one canonical response. No public
socket invokes it.

## Socket-activation adapter and client core

The non-installed socket-activation adapter is the final process boundary
before that future socket. It delegates activation-environment validation to
libsystemd, requires exactly one `Accept=yes` descriptor named `connection`,
then independently proves it is a connected, non-listening Unix seqpacket
socket. The root process dispatches one request and closes the descriptor on
every outcome. No daemon loop, socket path, unit, PATH command, or enablement
is installed.

The matching non-exposed client core sends exactly one canonical request and
receives one bounded seqpacket response with the same truncation and
ancillary-data rejection. It requires a preflight response to repeat the
requested operation, and an identities request to receive only the inventory
response shape. It has no socket path, connection constructor, fallback
command, or installed CLI.

## Candidate systemd units

Candidate systemd units and the fixed read-only entry point live under
`systemd/research/` and `src/`, respectively. They use `Accept=yes`, bounded
connection and trigger limits, one process per connected seqpacket, and a
service sandbox restricted to the Bridge IPv6 path, local Unix and D-Bus,
`/dev/t2-aks`, and the lock paths required by the broker. They contain no
`[Install]` section, are deliberately omitted from `install.sh`, and must not
be copied or started until the documented module, operation-`0x06`,
fingerprint-survivor, mapping, and negative-caller gates all pass.

## Keybag activation core

The activation core is implemented behind injected interfaces only. It durably
records load intent before obtaining a temporary handle, verifies that handle's
independently observed bag UUID, records bind intent before selecting the
derived alias, re-reads the alias regardless of the command return, and records
unlock intent before using a wipeable password buffer. It trusts only the final
readiness observation: a lost bind or unlock reply can succeed when read-back
proves the exact ready state, while a lost load handle, a missing read-back, or
a post-mutation journal failure becomes outcome-unknown without a retry. Its
recovery core requires a fresh runtime generation and the exact protected
mapping, performs one read-only alias observation, and never retries or cleans
up an unknown handle. It closes only as observed ready, observed not-ready,
blocked, or quarantined.

The concrete adapter uses the matching kext's exact read-only endpoint-7
operation `0x06` to double-read a handle's live bag UUID, and strictly decodes
the proven operation-`0x19` DER state dictionary around that read. Any alias,
bag UUID, account UUID, handle, file-mode, schema, or lock-state instability
fails closed. The same adapter composes the existing load, bind, and unlock
commands and sends password bytes through a pipe, never through argv or the
environment. It remains non-exposed: there is no public activation command and
no automatic recovery path.

The rebuilt kernel allowlist and observer have passed their first read-only
hardware validation. The diagnostic derives the alias from protected
configuration, takes the machine-wide operation lock, and prints no
identifiers:

```sh
sudo t2-aks-observe-test
```

## Native fprintd enrollment and deletion staging

The installed `fprintd` service keeps native enrollment default-off and native
deletion disabled. `src/t2_fprint_delete_worker.py` — the credential-free,
caller-pidfd-bound transient worker for exact-name `delete-one` — is installed
but is not attached to the default daemon.

The staged native `EnrollStart` path refuses to run until the canonical fprint
projection is complete, and refuses a canonical name already present in it.
This prevents standard fprint clients from compounding ambiguous or duplicate
labels before the mutation worker starts. The transient worker independently
repeats that same rule against its own fresh reconciled inventory while holding
the machine-wide operation lock, before recovery anchoring, ACM, journaling, or
SEP dispatch.

The combined research candidate resets `ExecStart` once and supplies both
`--enable-native-enrollment` and `--enable-native-deletion`. The normal service
has neither activation flag, and installing either candidate remains a manual,
rollbackable research step.

## Endpoint-10 / ACM research transport

The in-development endpoint-10 transport is separately opt-in. Setting
`T2_TOUCHID_ENABLE_ACM_RESEARCH=1` in the private root-owned configuration
registers dedicated ACM DMA buffers on the next boot and creates a root-only
`/dev/t2-acm`. This does not enable enrollment and does not expose a generic
raw command CLI.

`sudo t2-acm-preflight` only verifies registration metadata and performs no SEP
mutation. The separately installed
`t2-acm-lifecycle-test --acknowledge-transient-context-mutation` performs one
root-only, UID-bound tracking-context create followed by a mandatory deletion;
it does not enroll or delete a fingerprint. Use it only on an already
backed-up research machine.

The kernel grants one endpoint-10 owner and one context lease at a time,
attempts context deletion when that owner exits, and disables the endpoint
until reboot after a timeout or an ambiguous create response, so a late reply
cannot be reused. Because SEP retains the DMA addresses, changing this setting
requires a reboot; never unload the active module.

## Staging gates

Two installed read-only reports collect the prerequisites for the staging steps
above. Their acknowledgements are statements about controls already performed;
they do not run those controls and they authorize no mutation.

The fprint enrollment staging gate collects the complete set of prerequisites
for the separate native-enrollment and combined identity-management research
drop-ins:

```sh
sudo t2-touchid-fprint-enrollment-gate \
  --acknowledge-two-distinct-fingers-verified-this-boot \
  --acknowledge-password-fallback-tested \
  --acknowledge-worker-negative-controls-passed
```

Exit status zero means only that an uninstalled drop-in may be staged for the
documented standard-client test. The report does not enable a worker, install a
unit, expose identifiers, or send a mutation command.

Before any mapped-user broker exposure, collect all of its independent gates in
one identifier-free report. Its acknowledgement is valid only after two
distinct enrolled fingers have each matched during the current boot:

```sh
sudo t2-touchid-user-broker-gate \
  --acknowledge-two-distinct-fingers-verified-this-boot
```

The report distinguishes the reconciled T2 identity count from fprintd's one
compatibility alias, and never installs or starts the candidate socket. A
successful report means only that an unmapped/inactive caller negative test may
be staged.
