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

After transferring an archive privately, inspect a Catacomb component on Linux
without printing its UUIDs:

```sh
enrollment_research/scripts/inspect-catacomb.py path/to/user_000001f5.cat
```

The JSON inventory reports identity labels, counters, creation times, owner UID,
and schema version. UUID output is deliberately opt-in with
`--include-identifiers`; never paste that form into a public issue or log.

To exercise the strict encoder and an independent semantic reader against the
complete private capture without printing names or UUIDs, run:

```sh
t2-catacomb-fixture-check /path/to/t2-enrollment-evidence.tar.gz \
  --apple-user-id 501
```

The checker is offline and non-mutating. It requires a private mode-0600
archive, reads components directly from the tar stream, and emits only counts
and compatibility booleans.

The append-only journal now has a typed enrollment layer. It rejects skipped or
reordered start/continue/cancel/terminal milestones, stale concurrent appends,
changed connection generations, boot or mapping reuse, exhausted capacity, and
untyped generic records. A journal produced by the standalone baseline command
is intentionally not mutation-ready because that command closes its inventory
connection; a future broker must collect E0 and execute E1 under one connection
lease.

A synchronous operation core now composes the typed journal and pure event
machine through a dependency-injected transport. Tests cover start rejection,
disconnect, progress/continue, duplicate delivery, cancellation, request
erasure, stale E0 generations, provisional identity, and journal failure after
device dispatch. The repository intentionally supplies no live implementation
of that transport and no enrollment CLI; the next live-capable broker must keep
this whole core inside the authorized ACM callback and continue through E3
reconciliation before reporting completion.

The persistence journal now enforces the recovered component order between E2
and E3. It binds an immutable user/master batch plus an optional separate
bio-lockout batch, requires prepare and complete intent/observations, records
only secure-blob and final-file digests, forces early confirms before advancing,
and forces host batch commit before the final confirm. It cannot become
`persistence-ready` until stable SEP/host generation equality and independent
archive read-back are journaled. No raw secure blob may enter the journal.
The dependency-injected operation core now executes this ordering against fake
transport and temporary host-store interfaces, wipes its secure and encoded
buffers, and freezes post-dispatch transport, codec, host-store, journal, or
read-back ambiguity as outcome-unknown. There is still no concrete SEP/Bridge
persistence transport and no user-facing command.

The matching daemon disassembly also fixes the reply contract precisely:
prepare `0x3d` returns exactly one 32-bit expected secure-blob length, complete
`0x3e` returns a variable blob that must equal that length, and confirm `0x3f`
returns no payload. `t2_catacomb_protocol.py` enforces those rules as a pure,
non-sending codec for opaque 4-byte v1 and 24-byte v2 component descriptors.
The final SEP component hash is therefore evidence from independent stable
read-back, not a value invented from the confirm reply.

The hardware-free `t2_catacomb_bridge.py` adapter now joins that codec to the
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
match to its reconciliation snapshot plus advanced user/master/SEP state. A
reported failure can reconcile only against unchanged persistence. If that
failure nevertheless left one new UUID, the journal records the stable read-back
as provisional E2 success before attempting E3. This is a pure classifier: no
snapshot collector, Catacomb writer, Bridge adapter, or hardware enrollment
command has been added.

E4 post-reboot verification is now a typed journal gate, not a live command. A
successful enrollment can cross it only on a genuinely new Linux boot and
Bridge connection while reproducing the E3 snapshot, mapping, account/bag,
identity, protocol, host/SEP equality, and keybag-ready state. Failed enrollment
transactions cannot manufacture E4, and this repository does not trigger the
required reboot.

## Current boundary

Existing, already-provisioned Apple users appear protocol-feasible for
serialized Linux enrollment and identity management. The host authorization
path, event protocol, per-identity deletion, Catacomb schema, and crash windows
are substantially recovered.

Active development includes two non-mutating foundations: a privacy-safe
offline Catacomb decoder and a live, double-collected SEP inventory that joins
protocol-v2 global and per-user identities plus capacity and Catacomb state. The internal
mutation journal implementation durably syncs append-only, hash-chained intent
and observation records, rejects secret-shaped fields and raw bytes, and fails
closed on tampering or insecure storage. It is not yet connected to any T2
mutation command.

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

The recovered enrollment framing and asynchronous event matrix are now encoded
in a pure, non-sending protocol module. It accepts only the broker's 16-byte
mode-0 ACM external form, wipes its request buffer, deduplicates and sequences
events within one connection/operation generation, never treats progress as
success, and stops at `SEP-identity-observed`. It is deliberately not wired to
BridgeXPC, fprintd enrollment, or Catacomb mutation.

The proven machine's copied macOS archive now passes the executable fixture
check for the user, master, and bio-lockout components: original strict schemas,
neutral semantic re-emission, independent-oracle read-back, opaque secure-data
preservation, and account/keybag binding preservation all succeed. This is not
evidence that copying files into macOS preserves APFS metadata, and no write-back
was performed.

The following remain disabled or unverified:

- final biometric-consumer acceptance, replay, and one-shot behavior for the
  freshly authorized mode-0 ACM context;
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
software installed on hardware you control or from Apple's official restore
and update packages, subject to the terms that apply to you.

This is experimental research, not a supported enrollment implementation. Keep
password login and macOS recovery available, and never test destructive paths
against the only enrolled finger or only usable account.
