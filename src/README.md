# T2 SEP staged transport

This module is the write-capable successor to `t2-sep-probe`, but defaults to
observation-only behavior. In its default mode it claims PCI function
`106b:1802`, maps BAR4, and reads the two mailbox status registers. It performs
no DMA allocation and no MMIO writes.

The explicit `register_ool=1` mode mirrors the recovered Apple transport setup
for AppleKeyStore endpoint 7:

- enables a 44-bit coherent DMA mask and PCI bus mastering;
- allocates separate 16 KiB, page-aligned input and output buffers;
- sends endpoint-0 `SET_REMOTE_DMA_IN` and `SET_REMOTE_DMA_OUT` control calls;
- validates the matching transaction tag and zero SEP result.

It sends no AppleKeyStore request unless the additional
`probe_capabilities=1` option is supplied. That option issues exactly one
read-only opcode `0x4d` capability query after both OOL registrations succeed.
The recovered v1 request is 92 bytes and uses SHA-256 truncated to 16 bytes for
its integrity field. It does not request a fingerprint, modify SKS lock state,
or read/write enrollment records. Loading is not automated.

After OOL registration the module also creates `/dev/t2-aks` as a mode-0600
root-only exchange device. The kernel, rather than userspace, owns header
generation, transaction matching, SHA-256 verification, size bounds, and
request-buffer scrubbing. It accepts only the recovered AppleKeyStore opcodes
`0x03` (load keybag), `0x04` (change lock state), `0x06` (copy one live keybag
UUID), `0x19` (get device state),
`0x21` (verify secret with either a 16-byte ACM context or the bounded
password-only diagnostic), and `0x4d` (capabilities);
every other opcode is rejected. Operation `0x21` is additionally restricted to
the recovered codec, session, password, context, and option layouts. Capability
negotiation uses the required v1 header, while normal operations use the
negotiated v2 header and calendar-time extension.

The research-only `get-device-state-v1 SESSION HANDLE SELECTOR OUTPUT` command
implements the recovered 24-byte operation-`0x19` codec. Its output can contain
a private keybag UUID, is created mode `0600`, and must never be committed or
published. Decode only a private copy, redact identifiers in notes, and remove
the raw output when the observation is complete.

The read-only `copy-keybag-uuid SESSION HANDLE OUTPUT` command implements the
matching kext's exact raw endpoint operation `0x06`: a zero result placeholder,
session `1`, and one nonzero signed handle. The kernel rejects every other body.
Success writes exactly 16 UUID bytes to a newly created mode-0600 file and never
prints the UUID; an absent handle returns exit status 3 and creates no file.
Output paths are no-follow/exclusive and existing files are never overwritten.

Operation `0x21` codec v1 contains the password and 16-byte ACM
external-context blobs followed by one 64-bit device-options value. Exact
selector `42` supplies plaintext-secret option `0x200`; the kernel accepts only
that canonical value. Memento and structured-credential variants are not
exposed by this research interface. Endpoint-7 mailbox failures are returned
to the root-only caller as a signed SEP status in the fixed-size ioctl record,
so diagnostics do not depend on scraping the kernel log.

`verify-password-only SESSION HANDLE` emits the same recovered codec with a
zero-length external-context blob. It is deliberately restricted to a nonzero
handle, session `1`, a nonempty bounded password, and option `0x200`. This
stage-isolation diagnostic has passed on the proven machine with SEP status
zero and the expected 12-byte response, proving password/keybag verification
before ACM attachment. It does not enroll, delete, or evaluate an ACM policy.

`t2-touchid-identities` is the privacy-safe identity-management inventory. It
joins the strict committed user Catacomb with a stable live per-user/global SEP
inventory under the operation lock and emits only numbered slots and local
labels. It fails closed on any local/live divergence and never exposes UUIDs.

`t2_user_mapping.py` is the first non-exposed multi-user policy boundary. It
strictly parses a root-owned mode-0600 JSON file through a no-follow descriptor,
hashes the exact bytes as the mapping generation, and rejects duplicate keys,
unknown fields, ambiguous UID/account/bag/keybag ownership, unsafe paths, and
implicit capabilities. Each record targets an already-provisioned Apple user;
it cannot create an account, keybag, persona, or biometric container. Its
resolver checks only target mapping and capability. Authenticated-caller and
delegation policy remain separate from the file parser.

`t2_user_policy.py` implements that next pure boundary for the operations
`verify`, `inventory`, `enroll`, `rename`, and `delete-one`. It accepts only an
authenticated active self-session, resolves the target exclusively by numeric
Linux UID through the protected mapping, and requires an operation-specific
grant bound to caller, target, exact mapping bytes, operation UUID, Linux boot,
and a maximum five-minute monotonic validity interval. Cross-user delegation
is disabled, root has no implicit authority, mutation-disable policy is
independent, and grants are not transitive between action classes. A locked or
absent target additionally requires a separately bound `activate-user` grant;
lockout and quarantine can never use that route. The returned mapping and
binding are internal while the report is identifier-free.

`t2_user_readiness.py` is the next pure runtime boundary. Given a validated
mapping plus independently collected Linux-account/keybag/Catacomb and live
alias evidence, it returns one redacted typed decision. Exact binding and known
safe SKS state are required for `ready`; an absent alias requests activation,
device-lock/first-unlock requests password bootstrap, lockout requests recovery,
and binding collisions, Catacomb corruption, or unknown state bits quarantine
the mapping. The classifier deliberately has no transport and cannot perform
the requested next step. This keeps future observation/recovery logic separate
from AKS mutation and prevents an error return from becoming an implicit retry.

`t2_user_activation_journal.py`, `t2_user_activation_operation.py`, and
`t2_user_activation_recovery.py` encode the serialized activation transaction
without supplying a live transport. The
hash-chained journal binds mapping/boot/runtime generations, target capability,
Apple/account/bag/keybag authority, derived alias, and whether that alias
predated the operation. The injected core writes intent before load, bind, and
unlock; verifies a loaded handle's bag UUID before bind; re-observes alias and
lock state after every ambiguous command return; accepts ready state over a
lost reply; and never retries. Password input must be a bounded `bytearray` and
is wiped on every exit. A post-mutation transport, observation, or journal fault
becomes a terminal reconciliation-required record. Recovery requires a fresh
runtime generation and an unchanged exact mapping, performs one read-only alias
observation, and never retries a password, bind, unlock, or unknown handle. It
can close only as observed ready, observed not-ready, blocked, or quarantined.
The activation operation now refuses to observe or mutate unless supplied the
exact policy binding. It accepts an ordinary operation grant only while the
target remains ready, accepts activation only with the separate activation
grant, and uses the policy-bound operation UUID as its journal UUID so a grant
cannot be detached from recovery evidence.
`t2_aks_state.py` strictly decodes the exact ten-field DER keybag-state schema
observed on the proven build, including canonical SET ordering, integer
encoding, queried handle, lock state, and private user UUID. `t2_aks_observer.py`
brackets that state with two operation-`0x06` bag-UUID reads, stores raw output
only inside a private transient directory, and deletes it immediately.
`t2_aks_transport.py` composes that observer with the existing load, bind, and
unlock commands; password bytes traverse a pipe and command output must match
the exact typed reply. These modules provide the concrete dependency boundary,
but no PolicyKit evidence collector, recovery CLI, or public activation command
is present. Hardware validation of operation `0x06` requires installing
the rebuilt pinned module and rebooting before this adapter can be enabled.

The `t2-touchid-manage` rename path resolves one slot only after that
reconciliation gate,
proves its strict archive rewrite changes only the selected label, and binds an
operation-fresh SEP secure envelope. Its typed journal permits exactly one user
Catacomb component and records prepare, complete, host-stage, commit, confirm,
read-back, and post-reboot phases. Every post-dispatch fault becomes
outcome-unknown. Its recovery broker records a direction before touching the
local transaction, discards only a validated pre-boundary `prepare/`, rolls
forward only a complete journal-bound `commit/`, and never replays a SEP
mutation. Fresh stable host/SEP read-back must classify the result uniquely as
unchanged or committed; a committed recovery still requires post-reboot proof.

The independent rename read-back additionally requires the identity set,
account/keybag binding, master enrollment count, component ownership/modes,
and unrelated master/bio-lockout hashes to remain unchanged. The committed
user archive must equal the strict rename plan, the live per-user/global sets
must equal it, and both the selected-user and master SEP Catacomb states must
be clean before the journal can reach `reconciled`.
The post-reboot verifier additionally requires a different Linux boot and
Bridge connection, the exact journaled user-component hash and label, unchanged
account/keybag/master and unrelated component state, exact local/live identity
equality, and clean selected-user/master SEP state.

The `t2-touchid-manage delete` path is a separately acknowledged,
single-identity-only broker. It resolves an ephemeral slot against a stable
reconciled inventory, durably binds the exact 20-byte UID+UUID command-`0x0d`
request, and refuses the final remaining identity. The command's return status
is never sufficient evidence: a stable same-connection per-user/global
inventory must prove either exact target absence or, after a failed command,
an exact unchanged baseline. Proven absence is followed by a user-component
only Catacomb save, independent read-back, and a different-boot verification.
The companion `plan-delete --slot N` runs the same reconciled target planner
but does not create a journal, dispatch `0x0d`, or write a Catacomb component.
It reports only the selected label and before/after counts.

Deletion recovery never replays command `0x0d`. It records the local
transaction direction before resolving it and uses a fresh Bridge generation
to classify state as exact no-change, exact committed survivors, or an
unconfirmed SEP deletion requiring forward persistence. The forward path can
rebind either the exact baseline archive or an exact journaled survivor archive,
resets persistence onto the fresh lease, and cannot claim rollback. Ambiguous states stay
`outcome-unknown`. Delete-all, zero-identity archives, whole-user deletion, and
cross-user mutation are not implemented.

The installed wrapper selects the known positive runtime keybag and requires a
narrow acknowledgement for this non-ACM path:

```sh
sudo t2-acm-authorize-test --diagnostic-password-only \
  --acknowledge-password-verification
```

The wrapper refuses direct-root and cross-user invocation: `SUDO_UID` or
`PKEXEC_UID` must resolve to the single Linux account in the protected mapping,
and the Apple UID and special bag are always read from that root-owned mapping.
This is an explicit research authorization boundary; a dedicated production
PolicyKit action is still required before any enrollment API is exposed.

The internal `with_authorized_context` broker primitive holds the exclusive
device lease across context creation, policy preflight, explicit command-`0x13`
externalization, password binding, final policy-1007 evaluation, one trusted
consumer callback, and mandatory deletion. The callback is invoked only after
policy success and before deletion; callback failure still takes the same
cleanup path, and asynchronous consumers are rejected so work cannot escape
the context lifetime. No command-line option exposes the context bytes, and the
current diagnostic supplies a no-mutation consumer. This entire producer path
has passed on hardware: the initial type-1 requirement was satisfied, policy
1007 became true, and deletion/reconciliation succeeded without performing a
fingerprint mutation.

`t2_enrollment_protocol.py` is a transport-independent next layer. It builds
only the exact mode-0, 16-byte ACM enrollment request, keeps that request in
wipeable operation-local storage, parses the two-level service envelope, and
implements conservative progress, feedback, cancellation, terminal-result,
connection-generation, and duplicate-event rules. A terminal SEP identity is
only provisional; the state machine deliberately has no `completed` state
because durable Catacomb persistence and stable read-back are still required.
The module opens no device or socket and is not installed as a command.

`t2-catacomb-fixture-check` performs the separate offline archive-compatibility
gate. It accepts only a private regular archive, extracts no filesystem paths,
strictly decodes the captured user/master/bio-lockout component set, neutrally
re-emits each component, and requires a second independent semantic reader to
agree. Its JSON output contains counts and booleans only. It never changes the
archive or writes to a macOS Catacomb location.

`t2_enrollment_journal.py` adds typed E0/E1/E2/E3 ordering above the generic
durable journal. It permits start, continue, cancellation, terminal identity,
terminal failure, stable identity read-back, reconciliation, and outcome-unknown
records only in their recovered order; every append uses an atomic expected-head
check. Before E1 it requires the same Linux boot, protected mapping,
caller/target pair, protocol, capacity, and exact Bridge connection generation
as E0. Consequently the standalone
`t2-touchid-baseline` command remains evidence collection only: it closes its
inventory connection and reports `same_connection_enrollment_ready: false`.
An outcome-unknown attempt may cross the distinct
`E3_RECOVERY_NO_CHANGE_RECONCILED` transition only on a fresh Bridge generation
whose stable host/SEP read-back proves identity, capacity, Catacomb, and binding
state are all unchanged.

`t2_enrollment_operation.py` composes those two pure layers into a synchronous
E1/E2 operation core. It requires a same-connection E0 journal, accepts only an
injected transport interface, durably records start/continue/cancel intent
before dispatch, records observations afterward, wipes the authorization
request, and converts transport, protocol, or post-dispatch journal ambiguity
into `ENROLL_OUTCOME_UNKNOWN`. It must run inside the
`with_authorized_context` callback and stops at a provisional identity or
reconciliation-required failure. No BridgeXPC implementation or command-line
entry point is supplied, so this still cannot start enrollment on hardware.

`t2_enrollment_bridge.py` supplies the first concrete boundary beneath that
operation core without opening a socket. It accepts only an already-open,
exclusive Bridge lease whose canonical connection-generation UUID matches E0;
emits exact start `0x03`, continue `0x0e`, and cancel `0x0c` commands; validates
and queues the recovered five-item service callbacks; and requires empty
command output. Zero-capacity commands accept the equivalent Bridge encodings
`[status]`, `[status, null]`, `[status, empty-data]`, and the one exact fixed
`bkremoted` nil-output placeholder; every other string and any nonempty data are
still rejected. A generation change, malformed reply/event, disconnect, or
nonzero authoritative start/cancel reply permanently poisons or rejects the
operation. Exact 24G830 discards the numeric `enrollContinue` return, so a
well-formed matching continue reply queues its interleaved service events and
journals that return as non-authoritative. It composes
with the journaled enrollment core in tests, but no live lease, baseline-to-
authorization coordinator, or enrollment CLI is exposed.

`t2_bridge_wire.py` now holds the shared BridgeXPC framing previously embedded
in the read-only probe. `t2_bridge_connection.py` owns one initialized socket,
negotiates the matching API-v2 client contract, assigns one canonical generation
UUID, acknowledges synchronous and asynchronous service callbacks, rejects
reentrant use, and closes permanently on transport ambiguity. The existing
probe uses the same wire implementation.

`t2_bridge_inventory.py` double-collects the complete E0 inventory on that owned
connection and validates protocol, global/per-user identity agreement, capacity,
Catacomb metadata, SKS state, and exact snapshot equality. Any dispatched but
untrustworthy collection invalidates the generation. `t2_enrollment_coordinator.py`
then composes this E0, the typed journal, the live-scoped ACM callback, the
enrollment Bridge adapter, and a mandatory injected finalizer without releasing
the socket. A provisional identity cannot be reported as complete unless the
finalizer attests both persistence readiness and same-generation reconciliation;
finalizer ambiguity invalidates Bridge and still triggers ACM deletion. These
modules have no CLI and cannot initiate enrollment by themselves.

`t2_enrollment_persistence_journal.py` makes the recovered persistence ordering
mandatory after a provisional identity. An immutable plan contains exactly a
user-then-master primary batch followed by one separate bio-lockout batch. A
terminal failure instead permits exactly one bio-lockout-only refresh batch.
For every component it requires prepare intent/result, complete intent and
secure-blob digest, and host-stage digest. Non-final components must be
confirmed before advancing; the final component requires a separately
journaled host-batch commit before final confirm. Only a matching stable
SEP/host generation and independent archive read-back can reach
`persistence-ready`. The journal stores lengths and hashes, never secure bytes.

`t2_enrollment_persistence_operation.py` composes that journal with injected
prepare/complete/confirm, archive-encoder, host-store, and stable-read-back
interfaces. Intent is synced before every external dispatch, each component is
durably staged in protocol order, the host batch crosses its commit boundary
before the final SEP confirm, and secure/archive bytearrays are wiped on every
exit. A transport, codec, store, journal, or read-back ambiguity after SEP
dispatch becomes `CATACOMB_PERSISTENCE_OUTCOME_UNKNOWN`. Tests use only fake
transport and temporary Catacomb copies; no live adapter or command exists.
The Linux-local store makes its recovery direction durable with stricter fsync
ordering than the minimum host sequence: it syncs the root immediately after
`prepare/` becomes `commit/`, then syncs both the source `commit/` directory and
the destination root after every cross-directory component promotion. A real
forked child exits at the commit boundary in the test suite; a fresh store
instance proves that recovery rolls the transaction forward to the complete new
generation. An interrupted partial `prepare/` is rollback-only and may be
discarded only when every present component is schema-valid and belongs to the
journaled batch; a `commit/` can roll forward only when the journal contains a
validated digest for every planned component and a durable batch-commit intent.

`t2_catacomb_protocol.py` captures the exact non-sending command boundary
recovered from the matching daemon: prepare `0x3d` returns one 32-bit expected
secure-blob length, complete `0x3e` must return exactly that many bytes, and
confirm `0x3f` returns no payload. Every command carries the component descriptor
unchanged (4 bytes for protocol v1, 24 bytes for v2). The v2 value is decoded
exactly as `userID:u32 + groupType:u32 + groupUUID[16]`; typed constructors
distinguish canonical user, master, and group components. The same module parses
exact `0x3c` 8-byte user-state and `0x50` 28-byte group-state records and derives
a built-in enrollment save list only when the selected user is the sole dirty
non-master component, always placing master last. The pure builders/parsers
reject nonzero status, malformed descriptors, zero or unbounded sizes, length
drift, immutable complete buffers, and unexpected confirm output. They do not
open BridgeXPC or expose a command.

`t2_catacomb_bridge.py` is the bounded user/master composition layer. Its caller
must inject an already-open exclusive Bridge lease; this module creates no
socket and has no CLI. It pins one canonical connection-generation UUID,
requires an exact two-item `[status, data]` reply with no service events, and
drives only `idle -> prepared -> completed -> confirmed`. A disconnect,
generation change, malformed reply, capacity violation, nonzero command status,
or unexpected event permanently poisons the adapter, so an ambiguous component
cannot be retried. The complete blob is converted immediately to a wipeable
`bytearray`. Integration tests compose this adapter with the typed persistence
journal and crash-safe host store; malformed complete output becomes durable
`CATACOMB_PERSISTENCE_OUTCOME_UNKNOWN`.

`t2_enrollment_reconciliation.py` is the pure E3 classifier. It accepts only a
stable same-generation SEP inventory and a strict host Catacomb read-back,
requires the mapping, account, bag, existing identities, entity numbers,
component metadata, and Catacomb UUID to remain bound, and permits exactly one
new identity. A provisional identity reaches E3 only after the typed journal
has replayed every persistence milestone and its reconciliation-snapshot digest
matches the classifier's stable read-back. A terminal failure with no persistence
reconciles only to a byte-for-byte unchanged persistent state; the concrete
finalizer's bio-lockout-only path instead permits only that component to refresh.
If stable read-back reveals a new UUID despite failure, the journal first
promotes it to a provisional E2 identity. An outcome-unknown start can be closed
only as no-change recovery on a fresh generation; a new identity instead refuses
automatic recovery. These modules perform no I/O and no persistence themselves.

`t2_enrollment_finalizer.py` is the concrete no-CLI producer. It derives the
post-E2 built-in save list on the owned connection, composes the strict
user/master encoders with the separate bio-lockout export, commits both batches
through `CatacombStore`, performs stable same-generation SEP and independent
local archive read-back, and appends E3 only when the snapshot digest agrees. A
real-codec end-to-end test reaches E3; malformed bio-lockout output or an
injected read-back disconnect after commit is durably outcome-unknown. Hardware
enrollment is exposed only through a privileged, explicitly acknowledged broker.

`t2-touchid-enroll` is the stable subcommand frontend for that experimental
broker. It maps `status`, `preflight`, `start`, `verify-post-reboot`, and the
three typed recovery commands directly to the existing fail-closed engine;
`list` directly invokes the reconciled, UUID-redacting identity command. It
does not duplicate protocol or mutation logic. `t2-touchid-enroll-test.py`
remains the installed compatibility backend. Its `--preflight-only`
cannot enter ACM or enrollment; it verifies the sole protected backup, private
local store, sensor readiness, operation lock, same-connection E0, and capacity.
The original macOS archive remains an immutable recovery anchor, not a frozen
copy of current state: after a successful mutation, later preflight/enrollment
decodes the complete local Catacomb as the current host baseline, requires its
account and keybag bindings to remain equal to the protected backup, and then
requires that current identity set to equal stable SEP inventory. This permits
subsequent enrollments without accepting binding drift or overwriting advanced
state with the older archive.
`--status-only` does not warm hardware or provision the store; under the same
operation lock it reports only redacted unfinished-phase counts, whether live
enrollment is blocked, whether exactly one outcome-unknown journal is a
candidate for no-change recovery, whether a local Catacomb transaction is
pending and recoverable, and whether one successful E3 awaits E4.
Recovery now refuses any mixed set of unfinished journals. The read-only
`--verify-post-reboot` mode opens the existing mutated Catacomb without selecting
or restoring the original backup, collects stable host/SEP state on the new
boot, and appends E4 only when the exact E3 digest is reproduced. A pending E4
blocks another enrollment so later mutations cannot invalidate its snapshot.
The non-live `--recover-local-transaction` mode handles exactly one journal-bound
interruption in the persistence phase. It durably records an outcome-unknown
direction before touching files, then either discards a validated partial
`prepare/` or rolls a complete `commit/` forward. Re-running it after a process
crash continues the already-recorded direction rather than creating a second
transition. The resulting ambiguous biometric outcome must then pass the normal
fresh-generation `--reconcile-outcome-unknown` proof before another live run.
The live branch additionally requires explicit live-fingerprint and local-store
mutation acknowledgements, derives all security subjects from protected runtime
state, retains one Bridge lease through E3, and provides cancellation/audio
feedback. Immediately before live dispatch it acquires and verifies a block-mode
systemd sleep inhibitor; failure to acquire it aborts without entering ACM or
enrollment. The authorized consumer checks the actual logind inhibitor registry
again immediately before writing start intent or dispatching the first
enrollment command; a merely live helper process is insufficient. If the
inhibitor disappears or cancellation arrives while password authorization is
in progress, a typed `aborted-before-start` record with
`mutation_possible=false` is synced and neither enrollment transport nor
finalization runs. The inhibitor
is held by a parent-owned pipe, so normal exit or broker death releases it,
while SIGINT, SIGTERM, and SIGHUP request the typed cancellation path.
User-facing summaries omit internal operation and identity UUIDs. Progress and
retry guidance is best-effort: a closed terminal or
unavailable desktop notification service cannot alter the biometric outcome,
and handled live-path errors still emit the terminal failure cue. Its preflight
has passed on the target hardware. Five explicitly
approved live runs reached password-bound E1, then conservatively stopped
outcome-unknown while the adapter learned the real Bridge reply/event variants;
fresh stable read-back after each proved no identity or Catacomb delta. The
second run exposed a fixed 36-character placeholder. Exact `bkremoted`
disassembly proves that this constant is substituted for a nil Objective-C
output, and a non-mutating reset command on the target matched it without
disclosing the value. The adapter now accepts only that exact constant in
addition to omitted/null/empty-data encodings. The third run then recorded a
successful start before the event parser rejected a normal status message. A
non-mutating match/cancel control proved the common header's final qword is a
monotonic timestamp; the actual 32-bit status begins at byte 24, followed by
padding and a 64-bit detail length. The parser now uses that status and the
timestamp as its ordering key. `--reconcile-outcome-unknown` records no-change
proof without issuing enrollment or persistence. The fourth run crossed the
corrected common parser and stopped on another service envelope. The exact
non-mutating control already proves type `0xe3ff8004` statistics share this
stream during normal operations, so the reducer now ignores only version-1
statistics meeting the daemon's 12-byte minimum without feedback or state
advancement; all other non-enrollment
types remained fail-closed and are reported numerically. The fifth run then
exposed version-1 `0xe3ff800a`. Exact matching-daemon disassembly requires at
least a 32-bit user ID plus 16-bit SKS state. Depending on the state bits, the
daemon can synchronize the template list, save the bio-lockout record, cancel
a tokenless unlock match, notify observers, and emit analytics. None of those
callbacks is an enrollment transition. A later live run proved its embedded
user can differ from the active enrollment user, matching the daemon's behavior
of routing the ambient record by its own user field. The reducer therefore
validates the exact version and minimum shape but never lets the event select an
identity, send feedback, or send continue; the finalizer owns persistence for
the enrolled user. Live enrollment refuses to start while
an earlier mutation journal remains unfinished. The first complete Linux
enrollment reached E3, survived reboot/E4, appeared as a second reconciled
local/SEP identity, and matched independently through fprintd. Any next live
attempt remains explicitly operator-gated.

The typed journal also defines `E4_POST_REBOOT_VERIFIED` for a successful
identity. It is accepted only after E3, on both a different Linux boot UUID and
a different Bridge connection generation, with an exact match to the E3
snapshot digest (which includes account and bag bindings), protected mapping,
identity UUID, and protocol. Double collection, host/SEP equality, binding
checks, and keybag runtime revalidation must all be literal true. The broker
supplies the collector but never initiates the required reboot.

The v2 platform field formerly labelled `uid` is the caller's macOS audit
session ID (`ai_asid`). `aks_platform_asid` names it accordingly. The adjacent
64-bit field is the macOS process-unique ID, not a PID. Both are research-only,
boot-scoped data; they must not be inferred from the configured account UID.

When endpoint 10 is enabled, `/dev/t2-acm` permits one root/CAP_SYS_ADMIN owner
at a time and leases at most one live context to that open file. Policy and
delete commands must carry that exact context. Closing the file with a live
context performs a kernel-side delete, covering ordinary exit and process
death. A timeout, excess unrelated replies, or an unknowable create result
increments the endpoint generation, marks it poisoned, rejects all later
commands, and requires a reboot; this prevents a late uncorrelated ACM reply
from being mistaken for a later operation. This is still a narrow research
transport, not an enrollment API or a general ACM command device.

After either buffer is successfully registered, the module pins itself in
memory. SEP retains the DMA address and Apple exposes no matching unregister
control message; freeing that memory while SEP is live would be unsafe. A
reboot clears the registration and unloads the module.

Build with `make`. Do not load both this module and `t2_sep_probe` together.
The currently loaded registration-only revision is pinned; testing a rebuilt
revision requires a reboot rather than an unload.
