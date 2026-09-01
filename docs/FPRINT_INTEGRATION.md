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
user may use the existing unique same-UID active-session fallback; a root PAM
client must be directly attached to the claimed non-root user's exact active
local physical login session and can never borrow an arbitrary session. Both
the session and account generation are revalidated on every claim-scoped call.
Claims are serialized so a concurrent claim cannot pass while evidence
collection is suspended. `NameOwnerChanged` cleanup cancels active
verification, closes the pidfd, and releases the claim when that connection
disappears. This prevents a second allowed D-Bus connection from using a claim
by repeating its username and prevents PID reuse from rebinding an existing
claim. Protected mapping and bounded PolicyKit binding remain required before
mutation is enabled.

The claim can now derive an independently owned `AuthorizationSession` from
the same pidfd/session/account snapshot for a future mutation request. This is
strictly self-service: the D-Bus process UID must equal the claimed Linux UID.
A root PAM claim may continue through verification, but cannot be converted
into mutation authority. The derived session retains the existing
revalidation and bounded PolicyKit collector. `t2_fprint_broker` can hand that
session to the existing joined broker through a mutually exclusive,
pre-created authorization path. It permits only `enroll` and
`identity-management`, forces modification policy on, and closes the derived
session even if the broker fails before entering it. No D-Bus mutation method
or T2 mutation consumer is connected to this adapter yet.

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

## Enrollment status translation

The existing enrollment parser already distinguishes finger presence, lift,
quality guidance, progress, terminal identity, failure, and cancellation.
Translation should be deterministic:

| T2 broker transition | fprint status | done |
| --- | --- | --- |
| accepted progress stage | `enroll-stage-passed` | false |
| retryable quality failure | the closest documented retry status | false |
| lift/place required | `enroll-remove-and-retry` | false |
| duplicate identity | `enroll-duplicate` | true |
| capacity exhausted | `enroll-data-full` | true |
| reconciled identity and committed Catacomb | `enroll-completed` | true |
| cancelled/reconciled failure | `enroll-failed` | true |
| unresolved or malformed outcome | `enroll-unknown-error` | true |

The facade must not invent a fixed progress percentage or enrollment-stage
count from variable T2 progress. `num-enroll-stages` remains undefined (`-1`)
until a stable protocol-derived stage model is proven.

The pure `t2_fprint_enrollment_runtime` translator now enforces this table.
It emits `enroll-stage-passed` only for strictly increasing, bounded T2
progress; suppresses duplicate progress; maps quality guidance only to the
documented fprint vocabulary; and reports completion only after the typed
coordinator result proves policy, persistence, and final reconciliation.
Regressed progress, identity/terminal events that bypass final reconciliation,
or incomplete success become fail-closed errors. The facade also serves the
complete historical property set through `Get` and `GetAll`; stage count stays
`-1`, while finger-present/needed state is ready for the future worker stream.

`t2_fprint_enrollment_controller` now supplies that stream boundary without
starting a real mutation. It runs the synchronous journaled worker in a
separate thread, delivers each translated update back onto the D-Bus event loop
in order, and retains the completed transaction until `EnrollStop`. Stop,
release, and even accidental asyncio task cancellation set the worker's
cooperative cancel predicate and wait for its reconciled terminal result; they
never kill the worker thread or replay a command. Worker, feedback, or result
failures terminate as `enroll-unknown-error`.

After an immediate E3 success, the existing E4 post-reboot proof still must be
completed. A boot-time read-only reconciler should finish that proof
automatically and audibly/visibly report failure; ordinary users should not
need a repository command. Until that reconciler exists, native enrollment
must remain disabled rather than strand an invisible blocking journal.

## Deletion policy

Implement `DeleteEnrolledFinger` first. Resolve its canonical name to one
private UUID only after a fresh complete projection and invoke the existing
journaled single-target delete broker. A label is presentation metadata; the
journal records the resolved private authority before command `0x0d`.

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
- Standard `fprintd-enroll`, `fprintd-list`, `fprintd-verify`, PAM, sudo, lock
  screen, and desktop settings UI paths behave consistently.

## Next implementation order

1. Finish the protected per-user mapping and read-only broker exposure gates.
2. Bind each mutating call to a bounded PolicyKit grant derived from the
   pidfd/session/account claim.
3. Define a typed streaming mutation protocol and short-lived credentialed
   worker; prove authorization negatives before wiring T2 mutation.
4. Adapt journaled enrollment with cancellation and automatic E4 recovery.
5. Adapt single named deletion and its survivor controls.
6. Add batch deletion only after a separate atomic/recoverable design.
