# Proper fprint integration design

This document tracks the remaining boundary between the proven T2 mutation
brokers and the standard fprint D-Bus API. It is deliberately stricter than a
subprocess wrapper: `fprintd` is privileged, so forwarding a label or username
from D-Bus directly to a root command would lose the caller identity and turn
presentation data into authority.

The upstream ABI reference is the freedesktop.org
[`net.reactivated.Fprint.Device`](https://fprint.freedesktop.org/fprintd-dev/Device.html)
interface.

## Implemented verification boundary

The repository now implements the non-mutating half:

1. Every list or verify transaction refreshes the redacted, stable,
   local/live-reconciled identity projection.
2. Legacy, duplicate, or unknown labels expose only the configured
   compatibility alias. That alias and `any` select all identities.
3. A complete projection exposes every unique canonical fprint finger name.
4. Named verification repeats the private per-user and global SEP inventories
   on the same Bridge connection, reconciles the committed local Catacomb,
   selects exactly one opaque identity record, and requires the match event to
   contain that identity.
5. A complete-projection `any` match retains all identities but resolves a
   success to exactly one canonical name. The service emits that name through
   `VerifyFingerSelected` and `VerifyFingerMatched`; ambiguous events fail
   closed.
6. Both resolved modes repeat both SEP identity views and reread the local
   Catacomb after matching. A state change invalidates the verdict.

No Apple user ID, identity UUID, Catacomb bytes, or biometric payload crosses
the public result boundary.

## Upstream mutation lifecycle to preserve

- `EnrollStart` requires a claimed device and one canonical finger name;
  `any` is invalid.
- Enrollment is asynchronous. Nonterminal feedback uses `EnrollStatus` with
  `done=false`; terminal outcomes use `done=true`, after which the client calls
  `EnrollStop`.
- `EnrollStop` must cancel an active transaction without replaying an ambiguous
  command.
- `DeleteEnrolledFinger` deletes one named identity for the currently claimed
  user. `DeleteEnrolledFingers2` deletes all identities for that claimed user.
- `ListEnrolledFingers` must raise `NoEnrolledPrints` for an empty inventory,
  not manufacture a compatibility slot.

The T2 broker already has journaled enrollment, single-identity deletion,
rename, cancellation, outcome-unknown recovery, local Catacomb persistence,
and post-reboot verification. The missing work is a caller-safe adapter and
automatic recovery policy, not another biometric protocol implementation.

## Required caller and authorization boundary

Before mutation is exposed, a claim must be bound to the unique system-bus
sender that created it. The adapter must resolve that sender to stable kernel
process credentials and an authenticated active local session, then keep the
following evidence together for the claim lifetime:

- system-bus unique name;
- Linux UID and account-generation digest;
- process identity/start time or pidfd-backed equivalent;
- session identity and active/authenticated state;
- Linux boot and broker runtime generations;
- exact protected mapping generation and requested capability;
- one bounded PolicyKit authorization ID for the exact operation.

`Release`, `VerifyStart`, `EnrollStart`, `EnrollStop`, and deletion must accept
only the same live claim owner. A caller-supplied username, fprint finger name,
slot number, or D-Bus well-known name is never sufficient authority. The
existing `t2_user_policy`, `t2_polkit_grant`, account-generation, session,
mapping, and readiness types should remain the source of these checks.

The first three layers are implemented. A sender-aware dbus-next dispatcher
preserves the immutable system-bus unique sender in task-local context. During
`Claim`, the service asks the bus daemon for `GetConnectionCredentials`,
requires `UnixUserID`, `ProcessID`, and `ProcessFD`, validates that the received
descriptor is a pidfd for that exact PID, and pins the process UID/start time.
Every claim-scoped call must retain both the exact sender and the live pinned
process identity. The pidfd is then duplicated into the existing libsystemd
session collector and joined to a protected local-account generation. A normal
user may use the existing unique same-UID active-session fallback. A
setuid-root PAM client is accepted only with the exact four-UID shape
`real=user; effective=saved=filesystem=root`; its real UID is pinned alongside
the bus UID and start time. Because sudo's PAM helper is not itself registered
with logind, it may use the unique same-real-UID active-local-session fallback;
it cannot select another UID or an ambiguous session. An all-root client still
requires a direct pidfd-to-session binding and can never borrow an arbitrary
session. The process credentials, session, and account generation are all
revalidated on every claim-scoped call.
Claims are serialized so a concurrent claim cannot pass while evidence
collection is suspended. `NameOwnerChanged` cleanup cancels active
verification, closes the pidfd, and releases the claim when that connection
disappears. This prevents a second allowed D-Bus connection from using a claim
by repeating its username and prevents PID reuse from rebinding an existing
claim. Protected mapping and bounded PolicyKit binding remain required before
mutation is enabled.

The claim can now derive an independently owned `AuthorizationSession` from
the same pidfd/session/account snapshot for a future mutation request. This is
strictly self-service: the D-Bus process UID must equal the claimed Linux UID,
and the process must not carry the setuid-root PAM marker. A privileged PAM
claim may continue through verification, but cannot be converted into mutation
authority. The derived session retains the existing
revalidation and bounded PolicyKit collector. `t2_fprint_broker` can hand that
session to the existing joined broker through a mutually exclusive,
pre-created authorization path. It permits only the exact `enroll`, `rename`,
and `delete-one` operations, forces modification policy on, and closes the derived
session even if the broker fails before entering it. The resulting authority
now carries a fail-closed pre-dispatch guard which repeats caller, mapping,
keybag, runtime-generation, and grant-expiry checks immediately before a SEP
enrollment start. Source `EnrollStart` now reaches this adapter only through an
explicit worker client; the installed service still constructs no mutation
client unless the separate research activation flag is deliberately staged.

## Mutation worker boundary

The long-lived fprint facade must not receive or retain the macOS password.
Enrollment needs ACM password binding, so it should run in a short-lived,
operation-scoped privileged worker that receives the encrypted system
credential through systemd's credential mechanism. The worker must receive a
typed authorization binding and canonical finger name over a bounded local
socket—not command-line arguments—and independently revalidate:

1. the caller/claim binding and PolicyKit grant;
2. the enabled target mapping and `enroll` or `identity-management`
   capability;
3. keybag, alias, Catacomb, operation-lock, and mutation-journal readiness;
4. a fresh same-connection E0 inventory;
5. exact target resolution under that lock.

The worker owns the operation lock and one Bridge generation for the mutation.
The D-Bus facade only translates typed progress/results. Closing the client or
calling `EnrollStop` sends a typed cancellation request; it never kills and
blindly retries the worker. An interrupted or transport-ambiguous operation is
journaled as outcome-unknown and reconciled read-only before any new mutation.

The internal T2 consumer side is now implemented and attached only to the
default-off source enrollment path.
`t2_recovery_anchor` writes an operation-scoped, immutable, root-private tar
archive of the validated committed Linux-local Catacomb before any mutation;
the existing version-1 baseline journal records this genuine backup, so no
legacy `backup_references` field is repurposed. Publication is exclusive,
fsynced, single-link, idempotent only for byte-identical state, and followed by
a second store read. `LiveUserReconciliationSession` releases enrollment
material only after the broker's repeated stable reconciliation, retains the
same operation lock and Bridge lease, and requires the anchored account/keybag
to equal the protected mapping.

`t2_fprint_enrollment_consumer` then composes that exact lease and anchor with
the existing ACM coordinator, journal, persistence finalizer, cancellation
predicate, feedback stream, Linux boot, operation ID, and mapping generation.
It accepts only an `operate`-stage, self-service, canonical-name enrollment
authority and passes the broker's fresh pre-dispatch guard directly to E1.
Inside the worker-held machine operation lock, the consumer also projects the
broker's same-generation reconciled identity inventory. It requires a complete
canonical projection and proves the requested finger name is absent before it
creates a recovery anchor, ACM context, journal, or enrollment command. The
facade's earlier projection check is therefore feedback, not trusted mutation
authority.
The short-lived worker boundary is now implemented and attached only when the
daemon receives its explicit research enrollment flag.
`t2_fprint_worker_launcher` creates one root-private operation socket and
starts a hardened transient service with `LoadCredentialEncrypted`; its argv
contains only the random socket path. `t2_fprint_worker_protocol` transfers
exactly one live pidfd plus canonical finger, account, and login-session
evidence over bounded Unix seqpackets. The worker independently reconstructs
the pinned authorization session before PolicyKit, mapping, Bridge, or T2
access. It accepts only an enabled `host-encrypted-credential` mapping.

`t2_system_credential` first proves password fallback against the positive
runtime keybag, then supplies the 16-byte ACM external form and password to the
new stdin-only AKS command. Plaintext is confined to the transient worker and
its child tool, wiped from mutable buffers, suppressed from stdout/stderr, and
never reaches fprintd. Progress is identifier-free; cancel, peer close, or
facade task cancellation sets one cooperative predicate and waits for the
journaled terminal response. `t2_fprint_worker_client` revalidates the original
claim before and after worker launch and retains completion until stop.

The credential-free `t2-touchid-post-reboot` oneshot now supplies automatic
post-reboot proof in source. It runs before fprintd, selects exactly one
eligible reconciled enrollment, label-rename, or single-delete journal,
reproduces the protected mapping/account/keybag binding, checks both the
positive runtime handle and special alias, and collects stable local/host/SEP
state on a fresh Bridge generation. It then appends only that journal's typed
terminal proof:
`E4_POST_REBOOT_VERIFIED`, `RENAME_POST_REBOOT_VERIFIED`, or
`DELETE_POST_REBOOT_VERIFIED`. It has no password credential and no
enrollment, rename, delete, or persistence command path.
Installed `EnrollStart` remains disabled until this path and the worker
negatives are proven on the machine.

## Enrollment status translation

The existing enrollment parser already distinguishes finger presence, lift,
quality guidance, progress, terminal identity, failure, and cancellation.
Translation should be deterministic:

| T2 broker transition | fprint status | done |
| --- | --- | --- |
| accepted progress stage | `enroll-stage-passed` | false |
| retryable quality failure | the closest documented retry status | false |
| lift/place required | `enroll-remove-and-retry` | false |
| independently proven duplicate identity | `enroll-duplicate` | true |
| lock-held stable capacity exhausted before dispatch | `enroll-data-full` | true |
| reconciled identity and committed Catacomb | `enroll-completed` | true |
| cancelled/reconciled failure | `enroll-failed` | true |
| unresolved or malformed outcome | `enroll-unknown-error` | true |

The facade must not invent a fixed progress percentage or enrollment-stage
count from variable T2 progress. `num-enroll-stages` remains undefined (`-1`)
until a stable protocol-derived stage model is proven.

The facade also emits the historical
`org.freedesktop.DBus.Properties.PropertiesChanged` signal whenever
`finger-present` or `finger-needed` changes. These Boolean notifications are
best-effort UI feedback only: D-Bus delivery failure cannot cancel, retry, or
reinterpret a journaled biometric operation.
Verification marks `finger-needed` while its match task is active and clears
it on every terminal, cancellation, and stop path. Enrollment derives both
properties from its typed worker stream.
Its raw compatibility layer now advertises those same five historical
properties through `Introspect`; a generic desktop client therefore sees the
same property contract that `Get` and `GetAll` actually serve.

The pure `t2_fprint_enrollment_runtime` translator now enforces the proven
subset of this table.
It emits `enroll-stage-passed` only for strictly increasing, bounded T2
progress; suppresses duplicate progress; maps quality guidance only to the
documented fprint vocabulary; and reports completion only after the typed
coordinator result proves policy, persistence, and final reconciliation.
Regressed progress, identity/terminal events that bypass final reconciliation,
or incomplete success become fail-closed errors. The facade also serves the
complete historical property set through `Get` and `GetAll`; stage count stays
`-1`, while finger-present/needed state is ready for the future worker stream.
The worker now preserves a stable lock-held capacity refusal as
`enroll-data-full` before recovery anchoring or SEP dispatch. No recovered T2
event yet distinguishes an already-enrolled physical finger from a generic
reconciled failure, so source deliberately does not emit `enroll-duplicate`
until that outcome can be independently proven.

The D-Bus facade now has the tested final adapter around that stream. When an
explicit client is supplied, canonical `EnrollStart` passes the exact pinned
claim to it, updates the historical properties, emits ordered `EnrollStatus`,
keeps verify/enroll mutually exclusive, and makes `EnrollStop`, `Release`,
sender departure, and terminal grace expiry wait for worker reconciliation.
Before it can launch the worker, `EnrollStart` collects a fresh projection
under the biometric operation lock. It refuses incomplete legacy or duplicate
labels and refuses a requested canonical name that is already assigned. A
collection failure, malformed result, or claim change during the asynchronous
check also fails closed before any mutation client is called.
The daemon now has an explicit `--enable-native-enrollment` process flag that
constructs this exact worker client. The installed systemd unit deliberately
omits the flag, so its method remains disabled and cannot launch the worker.
This is a staging switch for the installed hardware controls, not a default.
The installed `t2-touchid-fprint-enrollment-gate` is read-only and combines the
exact stack, mapping, AKS observer, canonical projection, journal-clear, and
effective-daemon state with explicit attestations for the live fallback,
two-finger, and worker-negative controls. It can report readiness but cannot
install the separate research drop-in or dispatch a mutation.

Incomplete legacy labels now have a read-only migration bootstrap rather than
a guessing rule. `t2_fprint_match_gate.prepare_slots` joins every opaque SEP
identity to the same ephemeral slot ordering used by the identity-management
preflight, after exact repeated local/per-user/global reconciliation. The
probe selects all identities, reports only the matched slot, and repeats the
inventory and local-component attestation after the scan. The installed
`t2-touchid-identify-finger` wrapper exposes that slot with an explicit
`mutation_performed: false` result. It cannot assign an anatomical name; the
operator must know which finger was presented and separately invoke the
existing acknowledged, journaled rename transaction. That transaction refuses
a label already assigned to another identity and reports the resulting
canonical projection completeness without exposing an identity identifier.
The installed `plan-fprint-rename` path performs the same fresh target and
projection calculation without creating a journal or sending a mutation, and
`rename-fprint` refuses any name outside fprint's fixed anatomical vocabulary.

`t2_fprint_enrollment_controller` now supplies that stream boundary without
starting a real mutation. It runs the synchronous journaled worker in a
separate thread, delivers each translated update back onto the D-Bus event loop
in order, and retains the completed transaction until `EnrollStop`. Stop,
release, and even accidental asyncio task cancellation set the worker's
cooperative cancel predicate and wait for its reconciled terminal result; they
never kill the worker thread or replay a command. Worker, feedback, or result
failures terminate as `enroll-unknown-error`.

After an immediate E3 success, E4 still requires a reboot. The boot-time
read-only reconciler now completes that proof automatically when every binding
and digest reproduces exactly. Failure remains visible in its private systemd
journal and leaves the blocking E3 journal untouched; desktop-visible failure
feedback is still pending. Native enrollment remains disabled until the
installed automatic path is proven.

## Deletion policy

The source facade now stages `DeleteEnrolledFinger` behind an injected client
that the installed daemon never supplies by default. It binds the method to
the exact claim owner, rejects `any`, requires a fresh complete projection and
an enrolled canonical name, refuses the final remaining identity, and keeps
verification/enrollment/deletion mutually exclusive. Release or D-Bus peer
loss waits for deletion reconciliation; it never cancels and replays an
ambiguous command. Success requires an exact typed result proving the named
mutation reconciled locally and still awaits its different-boot proof.

The deletion worker is now implemented as a separate credential-free transient
service. Its distinct seqpacket protocol transfers exactly one live caller
pidfd plus claim evidence and rejects enrollment packets. Inside the broker's
operation lock and Bridge generation, `prepare_deletion_material` re-reads the
committed Catacomb, reproduces the cached private SEP snapshot digest, freezes
an immutable recovery anchor, and resolves the requested canonical name to one
private UUID. The consumer records that target before command `0x0d`, shares
the management CLI's persistence/reconciliation tail, and returns only an
exact reconciled completion. Peer loss after handoff cannot cancel or replay
the deletion.

Because neither the native worker nor the older management rename/delete CLI
reads or verifies the macOS password, their durable baselines record
`password_fallback_verified: false`. The generic journal schema preserves that
truthful Boolean while enrollment creation and the typed enrollment reader
still require it to be true. Thus no credential-free identity-management path
can manufacture an enrollment-only password attestation or weaken the
enrollment boundary.

`t2_fprint_delete_worker_client` is wired only by the explicit
`--enable-native-deletion` process flag. The ordinary installed unit contains
neither mutation flag. The uninstalled combined research drop-in atomically
replaces `ExecStart` with both enrollment and deletion flags after the read-only
activation gate passes.

Do not implement bulk deletion as a loop over the single-delete API. A crash
would create a partially deleted set with unclear client semantics. Keep
`DeleteEnrolledFingers` and `DeleteEnrolledFingers2` fail-closed until there is
an explicit batch journal, deterministic recovery, and a tested policy for the
last remaining identity.

## Delivery gates

Native mutation remains disabled until all of these are demonstrated:

- D-Bus claim ownership cannot be stolen, rebound, or used cross-user.
- Mapping-disabled, capability-denied, inactive-session, wrong-account-
  generation, expired-grant, wrong-boot, and wrong-runtime controls fail before
  a mutation worker receives authority.
- Enrollment cancellation works at finger-wait, progress, persistence, and
  outcome-unknown boundaries.
- A successful enrollment appears in fresh list/verify, survives reboot, and
  completes E4 automatically.
- Named delete removes only the selected finger; the survivor matches before
  and after reboot and the deleted finger does not.
- Contention, daemon restart, client disconnect, suspend fault, and broker
  crash all fail closed without command replay.
- Standard `fprintd-enroll`, `fprintd-list`, explicit
  `fprintd-verify -f any`, named `fprintd-verify -f FINGER-NAME`, PAM, sudo,
  lock screen, and desktop settings UI paths behave consistently. Bare
  `fprintd-verify` is not an all-identity control once multiple canonical
  names are listed: the upstream utility selects the first listed name.

## Next implementation order

1. Use the read-only slot matcher plus separately acknowledged renames to make
   the two existing identities a complete unique canonical projection.
2. Prove mapping-disabled, wrong-caller, expired-grant, disconnect,
   wrong-generation, cancellation, and automatic-E4 worker controls on the
   installed machine.
3. Stage the uninstalled research drop-in, then validate canonical enrollment,
   fresh listing, targeted verification, cancellation, and reboot survival
   through standard fprint clients.
4. Exercise standard `fprintd-delete -f <canonical-name>` through the staged
   single-name worker and prove its deleted-target and survivor controls before
   and after reboot.
5. Add batch deletion only after a separate atomic/recoverable design.
