# Enrollment research

This directory publishes the current reverse-engineering findings for native
Touch ID enrollment, identity management, multi-user mapping, Catacomb
persistence, and recovery on Intel Macs with an Apple T2.

- [FINDINGS.md](FINDINGS.md) is a sanitized snapshot of the detailed research
  ledger, last updated 2026-08-31.
- [EVIDENCE_COLLECTION.md](EVIDENCE_COLLECTION.md) explains the remaining
  evidence gaps and how to collect data for each one later.
- [`scripts/`](scripts/) contains collection and preflight helpers. They do not
  enroll, delete, load, confirm, or repair biometric state.

## Contents

- [Collecting evidence from macOS](#collecting-evidence-from-macos)
- [Inspecting a Catacomb component on Linux](#inspecting-a-catacomb-component-on-linux)
- [Archive compatibility check](#archive-compatibility-check)
- [Implemented layers](#implemented-layers)
- [Current boundary](#current-boundary)
- [Live run log](#live-run-log)
- [Not yet verified](#not-yet-verified)
- [Privacy and legal notice](#privacy-and-legal-notice)

## Collecting evidence from macOS

The recommended macOS entry point is
[`scripts/collect-all-macos-evidence.sh`](scripts/collect-all-macos-evidence.sh),
which produces one private archive for later offline analysis.

For the narrower selector-42 caller-identity diagnostic, use
[`scripts/collect-aks-caller-identities-macos.sh`](scripts/collect-aks-caller-identities-macos.sh).
It copies only likely Apple system caller executables and their public
code-signing metadata. It does not read a password, keybag, Catacomb, or
fingerprint. Its output is still private research evidence because Apple
binaries must not be committed or redistributed.

The smaller
[`scripts/collect-aks-platform-identities-macos.sh`](scripts/collect-aks-platform-identities-macos.sh)
records the boot-scoped audit-session and process-unique values for currently
running candidate callers. Its output is private and non-replayable; the script
exists to test relationships and field semantics, not to mint credentials.

## Inspecting a Catacomb component on Linux

After transferring an archive privately, inspect a Catacomb component on Linux
without printing its UUIDs:

```sh
enrollment_research/scripts/inspect-catacomb.py path/to/user_000001f5.cat
```

The JSON inventory reports identity labels, counters, creation times, owner
UID, and schema version. UUID output is deliberately opt-in with
`--include-identifiers`; never paste that form into a public issue or log.

## Archive compatibility check

To exercise the strict encoder and an independent semantic reader against the
complete private capture without printing names or UUIDs, run:

```sh
t2-catacomb-fixture-check /path/to/t2-enrollment-evidence.tar.gz \
  --apple-user-id 501
```

The checker is offline and non-mutating. It requires a private mode-0600
archive, reads components directly from the tar stream, and emits only counts
and compatibility booleans.

## Implemented layers

Each layer is hardware-free and separately tested. None of them can start a
live enrollment on its own.

The append-only journal has a typed enrollment layer. It rejects skipped or
reordered start/continue/cancel/terminal milestones, stale concurrent appends,
changed connection generations, boot or mapping reuse, exhausted capacity, and
untyped generic records. A journal produced by the standalone baseline command
is intentionally not mutation-ready because that command closes its inventory
connection. The privileged broker described below instead collects E0 and
executes E1 through final reconciliation under one connection lease.

A synchronous operation core composes the typed journal and pure event machine
through a dependency-injected transport. Tests cover start rejection,
disconnect, progress/continue, duplicate delivery, cancellation, request
erasure, stale E0 generations, provisional identity, and journal failure after
device dispatch. The core itself has no socket or CLI; the privileged broker
supplies its generation-pinned live adapter, keeps it inside the authorized ACM
callback, and continues through E3 reconciliation before reporting completion.

The persistence journal enforces the recovered component order between E2 and
E3. Successful enrollment binds an immutable user/master batch followed by a
mandatory separate bio-lockout batch; terminal failure permits only a single
bio-lockout refresh batch. It requires prepare and complete
intent/observations, records only secure-blob and final-file digests, forces
early confirms before advancing, and forces host batch commit before the final
confirm. It cannot become `persistence-ready` until stable SEP/host generation
equality and independent archive read-back are journaled. No raw secure blob
may enter the journal. The dependency-injected operation core executes this
ordering against fake transport and temporary host-store interfaces, wipes its
secure and encoded buffers, and freezes post-dispatch transport, codec,
host-store, journal, or read-back ambiguity as outcome-unknown. Concrete
generation-pinned Catacomb and bio-lockout adapters are composed only by the
explicitly gated broker. The Linux-local store also rehearses a real process
exit at the durable `prepare/` to `commit/` boundary. It fsyncs that
root-directory rename before any old component is removed, and fsyncs both
directories after each subsequent cross-directory promotion. Reopening the
store after the child exits proves the validated `commit/` transaction rolls
forward to one complete new generation.

The matching daemon disassembly also fixes the reply contract precisely:
prepare `0x3d` returns exactly one 32-bit expected secure-blob length, complete
`0x3e` returns a variable blob that must equal that length, and confirm `0x3f`
returns no payload. `t2_catacomb_protocol.py` enforces those rules as a pure,
non-sending codec for opaque 4-byte v1 and 24-byte v2 component descriptors.
The final SEP component hash is therefore evidence from independent stable
read-back, not a value invented from the confirm reply.

The hardware-free `t2_catacomb_bridge.py` adapter joins that codec to the
already-recovered Bridge command boundary through dependency injection. It
requires one exclusive, generation-pinned lease and exact event-free Bridge
replies, enforces one-way prepare/complete/confirm state, and poisons itself
after any possibly dispatched ambiguity. It intentionally contains no socket,
connection discovery, authorization callback, or user-facing route. Tests show
that its malformed/disconnected path also freezes the outer persistence journal
as outcome-unknown rather than retrying a component.

The pure E3 reconciliation layer is executable too. Given already-collected
host and same-connection SEP snapshots, it rejects mapping or binding drift,
removed or multiple identities, changed existing entity numbers, component
metadata changes, Catacomb UUID changes, and host/SEP disagreement. Identity
success additionally needs the completed typed persistence history and an exact
match to its reconciliation snapshot plus advanced user/master/bio-lockout/SEP
state. A reported failure without persistence can reconcile only against an
unchanged snapshot; the finalizer's bio-lockout-only path permits just that
component to refresh. If failure nevertheless left one new UUID, the journal
records the stable read-back as provisional E2 success before attempting E3.
The classifier itself remains pure; collection, writes, and hardware commands
are owned by the surrounding broker composition.

The privileged experimental broker supplies the collector around this pure
layer. Its recovery-only mode accepts exactly one outcome-unknown enrollment,
opens a fresh Bridge generation, and appends a distinct no-change E3 milestone
only when the stable host/SEP snapshot still equals E0. It refuses automatic
recovery if a new identity or any persistent delta is visible, and the live
path refuses a new operation while an earlier journal is unfinished. For the
narrower case where a terminal enrollment event was rejected locally after SEP
had already created one identity, the separately acknowledged
`--recover-observed-identity` mode can complete persistence. It requires a
terminal-stage outcome-unknown journal and a fresh double collection proving
exactly one new configured-user built-in identity, agreement between per-user
and global SEP inventories, unchanged host files, the same SEP Catacomb UUID
with a terminal secure-state hash advance, unchanged mapping/account/keybag
bindings, and no removal. The journal binds persistence to that fresh recovery
connection before any Catacomb mutation. Every other delta remains manual and
fail-closed. If a Catacomb confirm reply is lost or locally rejected, recovery
does not blindly replay it. For the proven early-confirm case it requires the
staged file to match the journal and a fresh state read to show that component
clean with the next required component still dirty. Only then can persistence
resume at the following component on the fresh connection. The bridge's exact
nil sentinel is valid for zero-capacity confirm replies, but never for prepare
or complete replies that requested output bytes. After a successful mutation,
the Linux-local Catacomb—not the older copied macOS archive—is the current host
baseline for a later enrollment. The archive remains the immutable recovery
reference; opening advanced local state requires strict decoding, unchanged
account/keybag bindings, and equality with a fresh stable SEP identity
inventory. This prevents both accidental rollback to the backup and false
rejection of a legitimate second enrollment.

E4 post-reboot verification is both a typed journal gate and a read-only broker
mode, `--verify-post-reboot`. A successful enrollment can cross it only on a
genuinely new Linux boot and Bridge connection while reproducing the E3
snapshot, mapping, account/bag, identity, protocol, host/SEP equality, and
keybag-ready state. The verifier opens the already-mutated local Catacomb
directly; it never restores the original backup over it. Failed enrollment
transactions cannot manufacture E4, and the repository does not trigger the
required reboot. A successful E3 awaiting E4 blocks another enrollment so its
exact snapshot cannot be displaced before verification.

## Current boundary

Existing, already-provisioned Apple users appear protocol-feasible for
serialized Linux enrollment and identity management. The host authorization
path, event protocol, per-identity deletion, Catacomb schema, and crash windows
are substantially recovered.

Active development includes two non-mutating foundations: a privacy-safe
offline Catacomb decoder and a live, double-collected SEP inventory that joins
protocol-v2 global and per-user identities plus capacity and Catacomb state.
The internal mutation journal implementation durably syncs append-only,
hash-chained intent and observation records, rejects secret-shaped fields and
raw bytes, and fails closed on tampering or insecure storage. It is not yet
connected to any T2 mutation command.

The narrow endpoint-10 research transport has completed the full no-mutation
authorization producer on the proven machine. It creates a tracked context for
the configured macOS UID, observes the type-1 passcode requirement, explicitly
externalizes the live context with command `0x13`, binds the password through
endpoint 7, confirms policy 1007, invokes one no-mutation consumer, and deletes
and reconciles the context. The public result contains typed booleans only; the
context identifier and tracking payload remain redacted. The kernel enforces
one owner and one exact context lease, deletes an active context when its owner
exits, and poisons the endpoint generation after an ambiguous reply. These
fail-closed guarantees and the complete producer path are unit-tested and live
hardware-validated. The diagnostic accepts only a sudo/pkexec caller matching
the Linux account in the private mapping and never accepts a caller-supplied
Apple UID. This proves authorization production, but it neither performs nor
exposes enrollment and is not a general ACM command interface.

The recovered enrollment framing and asynchronous event matrix are encoded in a
pure protocol module and a generation-pinned injected Bridge adapter. They
accept only the broker's 16-byte mode-0 ACM external form, wipe the request
buffer, emit only exact start/continue/cancel commands, validate and sequence
service events within one connection/operation generation, never treat progress
as success, and stop at `SEP-identity-observed`. The adapter permanently
poisons itself after an ambiguous dispatch or receive. The adapter itself owns
no socket and there is no fprintd enrollment route; only the separately gated
experimental broker composes it with Catacomb persistence.

The next same-connection layer is also implemented without exposing a live
mutation command. A single owner initializes and pins one Bridge socket; a
private collector obtains both E0 snapshots without closing it; and a
coordinator creates the journal, runs the ACM-scoped enrollment callback, and
requires a typed finalizer on that same generation. An observed SEP identity is
never reported complete unless the finalizer attests persistence readiness and
reconciliation. Any finalizer error invalidates the Bridge generation while
mandatory ACM deletion still runs.

The same-generation daemon and `CatacombStateCache` implementation also close
the protocol-v2 component-layout gap. A component is exactly 24 bytes:
`userID:u32 + groupType:u32 + groupUUID[16]`. Canonical built-in user and
master components have a zero group record; master uses `userID == UINT32_MAX`.
Command `0x3c` returns 8-byte `userID + state` records, command `0x50` returns
a 24-byte component plus a 4-byte state, and state bit `0x04` selects
components for saving. The Linux parser constructs only a
selected-user-then-master save plan and fails closed on malformed, duplicate,
or unexpected dirty state.

The concrete no-CLI finalizer is implemented. It double-reads the post-E2 save
state, constructs only the exact user/master descriptors, obtains both SEP
secure blobs in user-then-master order, adds the provisional identity to the
strict local archive, increments the master generation/time, and crosses the
crash-safe primary host commit boundary before final confirm. It then exports
the separate bio-lockout record with command `0x4a` into a second committed
batch and performs stable same-generation SEP/host read-back before E3. The
4096-byte output capacity is recovered from the preserved full 14.4 superclass
and confirmed by a read-only 24G830 hardware reply; returned record length is
variable and strictly bounded. End-to-end tests use the real codecs, store,
journal, transport adapters, and classifier. Synthetic bio-lockout reply and
post-commit read-back failures become durable outcome-unknown rather than a
success, retry, or rollback. The module still has no ungated live command.
Terminal failure and cancel paths use the same machinery in a strictly
bio-lockout-only batch; reconciliation then requires user/master/identity/SEP
Catacomb state to remain unchanged while the current lockout record is safely
refreshed.

An experimental root-only broker wraps that composition. Its preflight path has
no route to ACM or enrollment and requires only the already-established
password-fallback acknowledgement. The live path is unreachable unless the
mapped sudo user supplies both separate live-enrollment and local-Catacomb
mutation acknowledgements. Both paths use the global operation lock; the broker
never accepts an Apple UID, keybag handle, connection generation, backup path,
or local-store path from the caller. Ctrl-C requests protocol cancellation
rather than abandoning the operation, and desktop audio cues announce the
finger request, actionable retry conditions, and terminal result. Those cues
and console progress are strictly best-effort; desktop-bus failure or a closed
stdout cannot change an authorized enrollment or persistence outcome. The
broker verifies a block-mode systemd sleep inhibitor before live dispatch,
holds it through the complete authorized enrollment/persistence window, and
releases it through a parent-owned pipe on normal exit or process death.
Failure to acquire that inhibitor stops before ACM or enrollment. The actual
logind registry—not only the helper's process state—is checked again inside the
password-authorized consumer immediately before the first SEP enrollment
dispatch. Guard loss or cancellation during authorization appends a typed
`aborted-before-start` terminal record with `mutation_possible=false`; the
enrollment transport and finalizer are not invoked. SIGINT, SIGTERM, and SIGHUP
all request typed cancellation, including that pre-dispatch gate. Public
summaries omit the internal operation UUID as well as biometric identifiers.
The read-only `--status-only` mode takes the operation lock but skips sensor
warm-up and store provisioning. It emits only unfinished phase counts and a
no-change recovery-candidate boolean, plus the count/eligibility of pending E4
verification and booleans for a pending/recoverable local Catacomb transaction,
never journal paths, operation IDs, or identity UUIDs. Automatic recovery
requires that this be the sole unfinished journal; a mixed unfinished set is
rejected before Bridge is opened.

An additional non-live `--recover-local-transaction` mode closes the host-file
crash window without opening BridgeXPC or asking for a password or fingerprint.
It accepts exactly one persistence journal with exactly one `prepare/` or
`commit/` directory. Before changing files it durably marks the enrollment
outcome unknown and records the one permitted recovery direction. A partial
prepare is discarded only when all present files are valid members of the
journaled batch; a commit is rolled forward only when all planned file digests
and the batch-commit intent are durable. The mode is replay-safe if interrupted
again. After local recovery, ordinary fresh-generation outcome reconciliation
must prove whether the SEP identity set and committed Catacomb changed before
another live enrollment is permitted.

## Live run log

A chronological record of the read-only collections and explicitly approved
live runs on the proven machine, and the adapter changes each one forced. This
is history; the sections above describe the current state.

The complete same-socket E0 collector was exercised read-only on the target T2
on 2026-08-31. Both private snapshots were byte-for-byte equal, protocol 2 was
attested, one existing identity reconciled, and the connection generation was
retained through the second collection. Live replies also established two host
details that the implementation preserves: these inventory commands retain
their version-1 command wrapper under biometric protocol 2, and device maximum
capacity (`0x0f`) cannot be combined arithmetically with configured-user free
capacity (`0x41`). No biometric or Catacomb mutation was performed.

A second read-only hardware run on 2026-08-31 exercised that typed parser over
the owned connection. Two byte-identical reads returned exactly one master and
one selected-user state record; the selected user carried save bit `0x04` and
master did not. The output was redacted to kinds and booleans, and no Catacomb
or biometric mutation was dispatched.

The non-mutating hardware preflight passed on 2026-08-31 and created the
private Linux-local store from the sole hash-named root backup. It verified the
backup, strictly decoded all three components, warmed the sensor, reconciled
one current identity over a single Bridge generation, and confirmed spare
capacity. It did not create an ACM context or dispatch enrollment/persistence.

The explicitly approved first two live runs each reached successful
password/ACM binding and wrote `ENROLL_START_INTENT`, then conservatively
stopped with `ENROLL_OUTCOME_UNKNOWN` at start/transport before scan feedback.
Stable inventory after each still showed one identity, unchanged capacity,
host/SEP equality, and no Catacomb delta; both journals were
recovery-reconciled on fresh Bridge generations before proceeding. The first
run exposed an omitted nil output item. The second exposed a 36-character
string in the same slot. Exact `bkremoted` disassembly proves the latter is one
fixed CFString substituted when the Objective-C output pointer is nil, and a
non-mutating reset command on the target matched that constant without printing
it. The adapter now accepts only `[status]`, `[status, null]`, `[status,
empty-data]`, or that exact fixed nil placeholder. Arbitrary UUID strings and
nonempty data remain fail-closed. Any further live run requires separate
explicit approval.

The third approved run crossed that boundary: command `0x03` returned success
and the journal durably recorded `ENROLL_START_OBSERVED`. It then froze on the
first normal service message, with stable recovery again proving no persistent
delta. A non-mutating timed match/cancel control exposed the parser error. In
the 24-byte common service record, the first qword is zero/reserved, the next
fields are event type and version, and the final qword is a monotonic event
timestamp—not the enrollment status. A generic status message carries its
32-bit ordinal at byte 24, followed by four bytes of padding and a 64-bit
detail length. The corrected parser derives the logical status from that record
and uses the timestamp only as its operation-local ordering key.

The fourth approved run crossed that corrected common-record parser and then
froze on an additional service envelope; stable recovery again proved no
persistent delta. The exact non-mutating control had already shown version-1
statistics (`0xe3ff8004`) interleaved on the same callback stream during a
normal operation. Statistics neither select an identity nor advance enrollment;
the exact daemon requires version 1 and at least 12 payload bytes, so the
reducer deduplicates and ignores only telemetry meeting those boundaries. Every
other unexpected envelope/version remains fail-closed, and its numeric
type/version is included in the controlled diagnostic for the next boundary.

The fifth approved run crossed statistics handling and froze on version-1
`0xe3ff800a`; stable reconciliation again proved no persistent delta. Exact
matching-daemon code identifies this as an SKS lock-state notification, accepts
at least six payload bytes (32-bit Apple user ID plus 16-bit state), and may
synchronize the template list, save the bio-lockout record, cancel a tokenless
unlock match, notify observers, and emit analytics according to its state bits.
Those effects do not advance enrollment itself. A later approved run proved
that this ambient notification's user can differ from the active enrollment
user. That matches the exact daemon, which routes the record using its own user
field rather than requiring equality with the active operation. The reducer now
validates only the exact version and minimum shape, treats it as an auxiliary
event, and never lets it select an identity, emit enrollment feedback, or send
continue. The finalizer still owns persistence for the enrolled user.

The next approved run reached generic enrollment status 90 after a successful
start. Conservative recovery again proved no persistent delta. Exact matching
24G830 `BiometricKit` shows that this status crosses the Touch ID, enrollment,
and generic operation handlers without capture feedback, progress, terminal
delivery, or `enrollContinue`. The reducer now treats this one recovered status
as a validated no-op phase event and continues waiting on the same connection.
At that stage, other unrecovered ordinals remained fail-closed.

The following approved run reached status 63 immediately after the first finger
press; recovery proved no persistent delta. Exact matching `BKOperation` maps
63 and 64 to `operation:presenceStateChanged:` with true and false
respectively, and 64 returns the host operation to its waiting state. Neither
status sends a biometric command or proves a successful capture. The broker now
reports these as quiet contact/lift feedback and continues waiting on the same
connection.

The next approved run emitted status 55 after the first contact notification;
stable recovery again proved no persistent delta. In the exact 24G830 handler
chain, 55 maps to no capture error, enrollment action, delegate callback, state
change, or command, and the generic jump table sends it directly to the common
return path. The reducer therefore accepted 55 as a second silent phase no-op;
at that stage, every other unrecovered ordinal remained fail-closed.

The subsequent approved run emitted status 72 at the same live boundary; stable
recovery again proved no persistent delta. The exact handler chain also sends
72 through the Touch ID and enrollment subclasses without an action and then
directly to the generic common return path. It is now the third explicit silent
phase no-op; other unrecovered ordinals remained fail-closed then.

The next approved run crossed those phase events and stopped on a version-2
generic status envelope after finger contact; stable recovery again proved no
persistent delta. The exact bridge wrapper preserves one common ordinal and
detail-length record across versions, while matching host dispatch explicitly
accepts version 2 for progress ordinals 100 through 355 and forwards its opaque
alignment detail. The reducer now validates that common framing, discards the
detail, and preserves the established percentage/continue cadence for that
recovered range. A subsequent live run proved that version 2 also carries a
lower status after contact. Matching host dispatch removes the envelope version
before the same BiometricKit handler, so version 2 was allowed to reach the
then-recovered ordinal switch while every unknown ordinal remained fail-closed.

The next approved runs reached statuses 95 and 91 after contact. Stable
recovery proved no persistent delta after each stop, and the unfinished-
operation gate correctly prevented an overlapping invocation. Rather than
continue recovering one observed number at a time, the exact 24G830
`BKEnrollTouchIDOperation` -> `BKEnrollOperation` -> `BKOperation` chain was
exhaustively enumerated. Its complete silent no-op domain is `0..50`, `52..57`,
`59`, `69`, `71..73`, `75..77`, `79`, `81..84`, `89..92`, `94..97`, `356..500`,
and `503..UINT32_MAX`. These statuses emit no capture feedback, progress,
terminal result, state change, or command. The reducer now encodes and tests
that whole domain for both supported envelope versions.

Generic statuses `51`, `58`, `60`, `61`, `62`, `65`, `80`, `99`, and `502` do
change `BKOperation` state but their enrollment effects are not yet safely
recovered, so they remain fail-closed. Accessory authorization status `501`
also remains on its separately blocked path. This exhaustive boundary removes
the need for another live attempt merely to classify a harmless phase ordinal.

The following approved attempt reached a genuine 23% progress event and sent
the required `0x0e` continue. It stopped because that command returned a
nonzero integer while service events were delivered before its matching reply;
stable reconciliation again proved no persistent delta. Exact 24G830
`BKEnrollOperation` deliberately discards the return from
`-[BiometricKitXPCClient enrollContinue]`. The reducer therefore treats a
well-formed matching reply as the dispatch boundary, queues its interleaved
validated service events, journals the numeric return as non-authoritative, and
continues. Start, cancel, persistence, malformed-event, and connection-
generation checks remain fail-closed.

The same runs exposed a more fundamental continuation bug. Linux initially
reused the negotiated enrollment payload version for every command, so a
protocol-v2 enrollment sent payload-less continue `0x0e` with wire version 2.
Every observed reply was `0xe00002c2` (`kIOReturnUnsupported`): SEP accepted
the first node, then emitted contact/lift telemetry but captured no later node.
Matching-daemon disassembly distinguishes the wrappers exactly. Enrollment
start calls the versioned wrapper because its request layout is versioned;
`enrollContinue` calls `performCommand:inValue:...`, whose implementation
forwards to the versioned primitive with constant version 1. Cancellation uses
the same payload-less contract. The adapter now keeps start at negotiated
version 1/2 and sends continue/cancel with wire version 1.

Two later approved attempts confirmed sustained capture and progress at 20% and
22%, but the latter stopped after a quiet scan interval because the original
Bridge socket retained its 60-second command timeout while waiting for the next
asynchronous service event. That timeout began before any frame header arrived,
so it was an ordinary idle period rather than evidence of a malformed or lost
frame. Enrollment now performs one-second readiness polls before reading an
event frame. An idle poll consumes no bytes, does not poison the generation,
does not consume the bounded event budget, and gives the signal handler a
chance to request protocol cancellation. Once any frame starts, the existing
bounded receive and fail-closed partial-frame handling remain unchanged.

The negative live gate was also rehearsed on the target: an invocation with the
password-fallback acknowledgement but without both mutation acknowledgements
exited from argument validation with status 2, before runtime configuration,
the operation lock, ACM, or Bridge hardware was opened.

The proven machine's copied macOS archive passes the executable fixture check
for the user, master, and bio-lockout components: original strict schemas,
neutral semantic re-emission, independent-oracle read-back, opaque secure-data
preservation, and account/keybag binding preservation all succeed. This is not
evidence that copying files into macOS preserves APFS metadata, and no
write-back was performed.

## Not yet verified

The following remain disabled or unverified:

- broader command-level fault rehearsal beyond the completed, persisted, and
  post-reboot-verified first live Linux enrollment;
- broader crash/fault rehearsal around the concrete coordinator boundary;
- creation of new AppleKeyStore/OpenDirectory/APFS users from Linux;
- whole-biometric-user removal with command `0x48`;
- writing Linux-generated Catacombs back into macOS; and
- transparent continuation of enrollment across suspend or reconnect.

## Privacy and legal notice

Catacomb files, keybags, account/persona inventories, raw UUIDs, and diagnostic
captures are private security material. The repository intentionally contains
none of them. Collector output is ignored by Git, created with restrictive
permissions, and must be reviewed and sanitized before sharing.

Apple binaries and firmware are not redistributed here. Obtain them from
software installed on hardware you control or from Apple's official restore and
update packages, subject to the terms that apply to you.

This is experimental research, not a supported enrollment implementation. Keep
password login and macOS recovery available, and never test destructive paths
against the only enrolled finger or only usable account.
