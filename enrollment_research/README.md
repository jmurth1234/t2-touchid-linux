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

The narrow endpoint-10 research transport has also completed a live tracked
ACM context create/delete lifecycle on the proven machine. The client accepts
only the recovered create and delete frames, binds creation to the configured
macOS UID, redacts the returned context identifier, and attempts deletion even
when response parsing fails. The staged kernel transport now additionally
enforces one owner and one exact context lease, deletes an active context when
its owner exits, and poisons the endpoint generation after an ambiguous reply.
Those new fail-closed guarantees are unit-tested and await activation on the
next normal reboot. The authorization diagnostic also accepts only a
sudo/pkexec caller matching the Linux account in the private mapping; it never
accepts a caller-supplied Apple UID. An internal callback-scoped broker keeps
the exclusive device/context lease from creation through policy success, one
trusted consumer, and deletion; the currently exposed diagnostic uses a
no-mutation consumer. This validates transient context lifecycle only; it does
not authorize enrollment or expose a general ACM command interface.

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

- policy authorization and replay behavior for a fresh mode-0 ACM context;
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
