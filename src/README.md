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
`0x03` (load keybag), `0x04` (change lock state), `0x19` (get device state),
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

`t2_enrollment_operation.py` composes those two pure layers into a synchronous
E1/E2 operation core. It requires a same-connection E0 journal, accepts only an
injected transport interface, durably records start/continue/cancel intent
before dispatch, records observations afterward, wipes the authorization
request, and converts transport, protocol, or post-dispatch journal ambiguity
into `ENROLL_OUTCOME_UNKNOWN`. It must run inside the
`with_authorized_context` callback and stops at a provisional identity or
reconciliation-required failure. No BridgeXPC implementation or command-line
entry point is supplied, so this still cannot start enrollment on hardware.

`t2_enrollment_persistence_journal.py` makes the recovered persistence ordering
mandatory after a provisional identity. An immutable plan contains exactly a
user-then-master primary batch and, optionally, one separate bio-lockout batch.
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

`t2_catacomb_protocol.py` captures the exact non-sending command boundary
recovered from the matching daemon: prepare `0x3d` returns one 32-bit expected
secure-blob length, complete `0x3e` must return exactly that many bytes, and
confirm `0x3f` returns no payload. Every command carries the opaque component
descriptor unchanged (4 bytes for protocol v1, 24 bytes for v2). The pure
builders/parsers reject nonzero status, malformed descriptors, zero or
unbounded sizes, length drift, immutable complete buffers, and unexpected
confirm output. They do not interpret the still-opaque v2 descriptor and do
not open BridgeXPC or expose a command.

`t2_catacomb_bridge.py` is the next bounded composition layer. A future broker
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
matches the classifier's stable read-back. A generic failure reconciles
only to a byte-for-byte unchanged persistent state; if stable read-back reveals
a new UUID despite that failure, the journal first promotes it to a provisional
E2 identity. These modules perform no I/O and no persistence themselves, and
there is still no live producer for the persistence milestones.

The typed journal also defines `E4_POST_REBOOT_VERIFIED` for a successful
identity. It is accepted only after E3, on both a different Linux boot UUID and
a different Bridge connection generation, with an exact match to the E3
snapshot digest (which includes account and bag bindings), protected mapping,
identity UUID, and protocol. Double collection, host/SEP equality, binding
checks, and keybag runtime revalidation must all be literal true. No collector
or automatic reboot is attached to this gate.

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
