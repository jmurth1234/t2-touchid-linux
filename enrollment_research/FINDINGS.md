# Linux-native T2 Touch ID management research

Research-only ledger started 2026-08-28. No enrollment, deletion, or user-data
command has been sent to the T2 during this work.

## Objective

Determine whether Linux can safely create, extend, enumerate, name, delete, and
scope T2 Touch ID identities for multiple users without relying on a macOS-side
enrollment/export cycle.

## Evidence levels

- **Observed:** exercised successfully against this machine.
- **Static-confirmed:** directly visible in the matching Apple binary or local
  disassembly, but not exercised.
- **Inferred:** consistent with symbols or nearby code but structure/semantics
  remain incomplete.

## Current findings

### Identity model

- **Observed:** Biometric command `0x42` returns 20-byte
  `identity_record_v1_t` entries scoped by a 32-bit user ID. Each entry combines
  that user ID and a 16-byte identity UUID; field order can be prefix or suffix
  depending on protocol behavior. Linux matching currently selects only records
  returned for the configured user.
- **Static-confirmed:** Apple exposes operations named
  `getEnrolledUserIDs`, `getFreeIdentityCount:forUser:withClient:`,
  `getIdentityFromUUID:withClient:`, and `getMaxIdentityCount:withClient:`.
- **Static-confirmed:** Apple tracks identity count, template count, enrolled
  user count, identity UUID, template UUID, and identity-to-user association as
  distinct concepts. A Linux username is therefore not itself a SEP identity.
- **Static-confirmed:** maximum capacity is queried with command `0x0f`, no
  input, and an exact 4-byte unsigned count reply. Per-user free capacity is
  command `0x41`, with a 4-byte Apple user ID input and an exact 4-byte unsigned
  reply. Protocol v2 also accepts a 24-byte input consisting of that user ID
  followed by the 20-byte accessory-group record. On older protocols the
  built-in group (type 1) falls back to the 4-byte form. Capacity can therefore
  be checked safely before starting enrollment, without interpreting failure
  events or counting host-side names.

### Enrollment

- **Static-confirmed:** Apple has `BiometricEnrollOperation`,
  `enroll:forUser:withOptions:withClient:`, `performEnrollCommand:`, progress,
  completion, cancellation, timeout, and extended-enrollment paths.
- **Static-confirmed:** `enrollContinue` sends biometric command `0x0e` with no
  input payload. See `biometrickitd.bridge-disasm.txt` around virtual address
  `0x100031cad`.
- **Static-confirmed:** bridge messages include an enrollment-node-v2 event
  (`message_enroll_node_v2_t`) and enrollment info v2. Enrollment is therefore
  asynchronous and multi-touch; a single request/reply is insufficient.
- **Static-confirmed:** the matching Mesa daemon maps the raw
  `message_enroll_node_v2_t` event to biometric status `0x107`, retaining the
  raw message `NSData` for client delivery. In the no-delegate path, its status
  dispatcher automatically calls `enrollContinue` for statuses in the inclusive
  `0x64...0x163` range. Consequently `0x107` is a nonterminal enrollment node
  that participates in the continue loop; it must not be treated as success.
- **Static-confirmed:** the successful-result path logs the new identity to its
  analytics/reporter, calls `saveCatacomb`, then saves the biometric lockout
  record, emits an enrollment-changed notification, and delivers the result to
  the active foreground client. See `enrollResult:withTimestamp:` at
  `0x100037c8a`. Neither the `saveCatacomb` nor `saveBioLockoutRecord` return
  value is tested before notification/client delivery. SEP success can
  therefore be reported after either host-persistence step failed; the state
  must then be classified as **indeterminate and reconciliation-required**, not
  success and not safely rolled back.
- **Static-confirmed:** initial enrollment is biometric command `0x03`.
  Protocol version 1 sends a 48-byte request laid out as a reserved 32-bit zero,
  the operation's 32-bit `userID`, and 40 bytes returned by its `authData`
  accessor. Protocol version 2 sends the same prefix plus 20 bytes returned by
  its `deviceGroup` accessor, for 68 bytes total. See `performEnrollCommand:` at
  `0x10002e313`.
- **Static-confirmed, exact macOS 15.7.9 (24G830):** the matching x86_64h
  `BiometricSupport` implementation of `parseAuthDict:toAuthData:` at
  `0x7ffa016c87cd` defines the complete 40-byte authorization container: a
  32-bit mode, 32-bit length, and at most 32 data bytes. It zeroes all 40 bytes
  first. Credential-set options (`BKOptionAuthWithCredentialSet`,
  `BKOptionEnrollWithCredentialSet`, and
  `BKOptionMatchCredentialSetForExtendEnrollment`) select mode `0`, require a
  nonempty `NSData` value, permit lengths 1–32, and copy those bytes directly
  into the container. Auth-token options select mode `1` and require exactly
  16 bytes. With no recognized nonnil option it succeeds with mode `1`, length
  `0`, and zero data. A wrong value class or length returns error `258`. Thus
  the externalized enrollment credential set is not transformed into a mode-1
  token by BiometricSupport; only its eventual T2-side validation remains
  unknown. Empty-parser success still does not prove SEP enrollment acceptance.
- **Static-confirmed, same-generation corroboration:** the 20-byte
  `deviceGroup` is a 32-bit `BKAccessoryGroup.type` followed by its 16-byte
  UUID. It is populated only for `BKOptionEnrollAccessoryGroup`; built-in
  enrollment with no accessory group leaves it all zero.
- **Static-confirmed:** extended enrollment uses match authorization options
  (`BKOptionMatchForExtendEnrollment` and
  `BKOptionMatchAuthTokenForExtendEnrollment`) and is not equivalent to creating
  a new identity.

#### Enrollment authorization container and trust boundaries

- **Static-confirmed, matching daemon:** `performEnrollCommand:` does not create,
  transform, or validate enrollment authorization. It asks the operation for
  `userID` and `authData`, then copies the complete 40-byte `authData` value into
  command `0x03`. The protocol-v2 accessory group is appended after that value;
  it is not part of the authorization container.
- **Static-confirmed, exact macOS 15.7.9 (24G830):**
  `initEnrollOperation:biometricType:userID:options:client:` first assigns the
  requested 32-bit user ID and client to a new operation, then calls
  `parseAuthDict:toAuthData:` directly into the operation's storage. The parser
  always clears all 40 bytes before examining the options dictionary. Fresh
  Objective-C operation allocation is also zero-initialized, but the explicit
  clear is the relevant reuse/error-path guarantee.
- **Static-confirmed:** the exact host-side representation is
  `{ uint32_t usingAuthToken; uint32_t tokenLength; uint8_t token[32]; }`.
  The field name `token` is generic: in mode `0` the bytes are a credential set;
  in mode `1` they are an authorization token. This structure contains no
  visible user ID, identity UUID, nonce, timestamp, policy identifier, keybag
  UUID, or expiry field. Any binding or freshness property of nonzero bytes must
  therefore be inside the opaque bytes and enforced by SEP, not inferred by the
  Linux host from this wrapper.
- **Static-confirmed:** recognized credential-set keys, in priority order, are
  `BKOptionAuthWithCredentialSet`, `BKOptionEnrollWithCredentialSet`, and
  `BKOptionMatchCredentialSetForExtendEnrollment`. Recognized token keys are
  `BKOptionAuthWithAuthToken`, `BKOptionEnrollWithAuthToken`,
  `BKOptionMatchAuthTokenForExtendEnrollment`, and
  `BKOptionMatchAuthTokenToBypassPasscodeBiolockout`. The first present
  credential-set key wins before any token key is considered.
- **Static-confirmed with older-build assertion corroboration:** credential-set
  mode accepts 1--32 bytes; auth-token mode accepts either zero bytes or exactly
  16 bytes. A missing recognized option deliberately yields mode `1`, length
  zero, and zero payload, and is successful at the host parser. A wrong object
  class or invalid length returns `258` before the SEP command is sent.
- **Static-confirmed:** ordinary enrollment and extended enrollment are separate
  consumers of the same representation. Ordinary enrollment parses the
  enrollment/general keys into `BiometricEnrollOperation.authData`. Extended
  enrollment first creates a match operation, pins one selected identity's
  `userID + UUID`, parses the extend-match keys into
  `BiometricMatchOperationMesa.extendEnrollmentAuthData`, and copies both into
  the match request when `forExtendEnrollment` is true. The match step does not
  visibly manufacture a reusable enrollment token for the host.
- **Exact 24G830 static finding with an enforcement qualification:** caller
  capability is independent of the 40-byte SEP value. At XPC connection
  acceptance, the server maps the private entitlement
  `com.apple.private.biometrickit.allow-enroll` to capability bit `0x04`;
  `allow-id-mgmt`, `allow-match`, and `allow-config` are different bits. The
  exact exported enrollment selector passes permission group 2 and deletion
  passes group 3 to `isClient:entitled:forMethod:`. That method tests bits
  `0x04` and `0x08` respectively, but every valid permission-group path returns
  true; a missing bit only enters additional diagnostics on internal builds.
  Therefore these are exact advertised/audited capability boundaries, not
  effective selector-denial gates in this build. They remain separate from the
  operation's Apple user ID and from whether that user's AKS bags happen to be
  loaded/unlocked. Root, a sudo password, an unlocked keybag, or a successful
  fingerprint match is not evidence of the private enrollment entitlement, and
  Linux must enforce the capabilities independently even if Apple only audits
  them in a particular build.
- **Negative static finding:** no explicit secure wipe of an operation's
  authorization storage has yet been found at terminal result, cancel, or
  object destruction. Parsing clears the destination before use, but ordinary
  Objective-C release is not an evidence-backed secret-erasure guarantee.
  Consequently a future Linux implementation must keep nonzero authorization
  bytes operation-local, never journal or log them, explicitly zero its own
  buffers on every terminal/cancel/transport-reset path, and never replay them
  after reconnect or restart.
- **Unresolved:** host binaries do not establish the SEP semantics of a 16-byte
  nonzero token or credential-set bytes: user binding, keybag binding, session
  binding, expiry, single-use behavior, and replay rejection remain opaque.
  Default zero-length mode proves only that the host permits a tokenless request;
  it does not prove the SEP will authorize that request in every lock state or
  for every user. No safe design may synthesize, persist, copy between users, or
  retry opaque nonzero authorization bytes until those properties are recovered.

#### What the zero-length default does—and does not—depend on

The matching daemon narrows this question to the device side. In
`performEnrollCommand:` (`0x10002e313`) its only preflight before constructing
command `0x03` is the ordinary operation-validity check. It then reads the
operation's `userID` and copies all 40 bytes of `authData` into the request.
There is no host-side call in this path to query an AKS keybag, login session,
screen-lock state, passcode state, or previously cached authorization, and
there is no branch on `usingAuthToken` or `tokenLength`. A zero-length value is
sent by exactly the same host path as a nonzero value.

The recovered current macOS Settings producer also does **not** normally rely
on that default. It evaluates `LAPolicyTouchIDEnrollment`, externalizes the
authorized `LAContext`, and supplies it to BiometricKitUI as `credset` together
with `userid`. Thus parser acceptance of an absent option is an API fallback or
alternate-client behavior, not evidence that the normal macOS enrollment UI
starts unauthenticated.

Consequently no host-visible lock/keybag/session predicate explains acceptance
of zero-length authorization. If command `0x03` with mode `1`, length `0` is
accepted only in particular states, that predicate is enforced after the
request crosses the BiometricKit transport—most likely in bridgeOS/SEP—and is
not recoverable from the available plaintext host binaries. The encrypted J132
SEP image prevents proving whether the deciding state is a loaded/unlocked bag,
an authenticated session retained inside SEP, manufacturing/provisioning mode,
an entitlement-derived channel property, or no additional predicate at all.

The safe conclusion is deliberately asymmetric: **host construction is
state-independent; device acceptance is unknown**. Linux must not interpret an
unlocked bag, successful earlier match, root caller, or length-zero parser
success as authorization to send tokenless enrollment. A future implementation
must require an evidence-backed credential-set/auth-token producer or an
explicitly isolated experiment with rollback, and must report device rejection
rather than retrying under guessed state transitions.

### Deletion

- **Static-confirmed:** `performRemoveIdentityCommand:` sends biometric command
  `0x0d` with one 20-byte identity record. See disassembly near
  `0x100044ed1`. This is destructive and must not be probed with invented data.
- **Static-confirmed:** `performRemoveUserDataCommand:` sends biometric command
  `0x48` with a 4-byte user ID. See disassembly near `0x100045251`. This appears
  broader than deleting one fingerprint and must be treated as a whole-user
  destructive operation.
- **Static-confirmed:** higher layers expose both
  `removeIdentity:withOptions:withClient:` and
  `removeAllIdentitiesForUser:withOptions:withClient:`.
- **Exact 24G830 static finding:** single deletion validates the user/component,
  calls the subclass SEP `performRemoveIdentityCommand:` first, removes the
  corresponding in-memory host identity object second, and calls
  `saveCatacomb` last. It propagates a Catacomb-save error and suppresses the
  enrollment-changed notification on that error, but there is no inverse SEP
  command that restores the deleted identity. A reported deletion error may
  therefore already mean irreversible SEP deletion plus unsaved host metadata;
  safe recovery cannot assume conventional application-level rollback.
- **Exact 24G830 static finding:** bulk deletion snapshots/enumerates the
  in-memory identities for the target user and performs the same SEP-remove then
  host-object-remove pair for each identity. It calls `saveCatacomb` only once,
  after the loop, and notifies only after that save succeeds. If a later SEP
  removal fails, earlier templates have already been deleted and their host
  objects removed but the revised Catacomb has not been saved; if the final save
  fails, every SEP deletion may already be complete. The returned error carries
  no rollback guarantee or per-identity completion list.

#### Destructive-operation vocabulary and result interpretation

Three operations must never share one UI label or internal opcode name:

- **Remove one identity:** one immutable `(Apple userID, identity UUID)` target,
  sent as biometric command `0x0d`.
- **Remove all identities for a user:** a host-orchestrated snapshot and loop of
  the same per-identity `0x0d` command, followed by one Catacomb save. It does
  not use `0x48` and is not atomic.
- **Remove biometric user data/container:** biometric command `0x48` with only
  the numeric Apple user ID. This is broader, has no identity UUID guard, and is
  reserved for an independently authorized deprovisioning workflow.

The phrase “delete all” is therefore forbidden in a journal or privileged API
unless it is qualified as either `remove-all-identities` or
`remove-biometric-user-container`. An fprintd-compatible operation may at most
mean the former; it must never dispatch `0x48`.

For a per-identity command, the terminal truth is the stable post-operation SEP
inventory, not the transport return alone:

| Command observation | Stable exact UUID inventory | Classification |
|---|---|---|
| success | absent | SEP deletion observed; Catacomb persistence still requires separate reconciliation |
| success | present | contradictory/unstable result; freeze mutation and recollect, never report deletion |
| error, timeout, or lost reply | absent | deletion occurred despite the reported failure; record the raw error and continue only to authorized persistence/reconciliation |
| error, timeout, or lost reply | present | not proven deleted; do not replay without fresh authorization and an unchanged immutable baseline |
| any result | inventory unstable/unavailable | outcome unknown; preserve intent and prohibit another mutation |

Host metadata is a separate domain. If SEP absence is stable but the validated
host Catacomb still contains the UUID, the state is
`SEP_DELETED_HOST_STALE`, not rollback and not completed deletion. The only
forward repair candidate is a newly authorized Catacomb rewrite derived from
the stable surviving SEP identity set, using the full prepare/complete/stage/
commit/confirm journal. Restoring the deleted UUID is impossible because no
template recreation primitive exists. Conversely, host absence with the UUID
still in SEP is `HOST_MISSING_SEP_PRESENT`; neither an empty archive nor
`no-Catacomb` may be sent as an implicit delete.

For `remove-all-identities`, apply that matrix independently to every UUID in
the original immutable target set. The batch return is only a convenience
summary and never overrides per-UUID read-back. A newly appearing UUID is a
concurrent-change conflict and cannot be absorbed into the destructive target;
an identity absent before the operation cannot be counted as deleted by it.
The batch reaches `identities-removed` only when every original UUID has two
stable absence observations, and reaches `durably-reconciled` only after the
resulting user/master Catacomb components also agree with SEP.

For `0x48`, per-identity absence is necessary but not sufficient evidence of
container removal: an empty container and an absent container can both have no
identity rows. A future validator must use a recovered explicit user/container
presence query or a fully characterized combination of command result and
Catacomb state before claiming container absence. Until then, an `0x48` success
can be reported only as `command-accepted; container-removal-unverified`, and
the operation remains disabled for ordinary management.

#### Exact macOS Settings identity-management scope

The extracted macOS 15.7.9 `Touch ID & Password` extension confirms the UI
wrapper does not create biometric users or accounts. Its
`PSBiometricIdentity` methods are thin calls on the existing Touch ID device:

- `identities` -> `identitiesWithError:`;
- `identitiesForUID:` -> `identitiesForUser:error:` with the supplied 32-bit
  numeric UID;
- `remainingIdentityCountForUser:` -> `freeIdentityCountForUser:error:`;
- `removeIdentity:` -> `removeIdentity:error:` with a previously returned
  identity object; and
- `setName:forIdentity:` first changes that identity object's name, then calls
  `updateIdentity:error:`.

This proves that a privileged client can explicitly select an **already known
biometric user** for inventory/capacity, while mutation remains identity-object
based. None of these paths creates an OpenDirectory account, AKS top-level
identity, persona, keybag, numeric alias, or initial Catacomb. The existence of
`identitiesForUID:` therefore supports multi-user management only after the
Linux UID -> Apple biometric UID mapping and all Apple-side state already exist;
it is not a provisioning primitive.

The client contains no persistence transaction of its own. Remove and rename
return the BiometricKit call's Boolean/error, while the daemon performs SEP
mutation, host identity mutation, and Catacomb save. Consequently UI success
cannot strengthen the daemon's non-atomic guarantees: delete may already be
committed in SEP when Catacomb save fails, and rename is durable only after the
daemon's Catacomb transaction is verified. Linux must target an immutable
`(Apple userID, identity UUID)` tuple and perform post-operation inventory;
accepting a mutable UI object or a label alone would permit stale or cross-user
targeting.

### Persistence and dual boot

- **Observed:** templates remain SEP-owned and matching works only after the
  relevant normal and special user keybags are loaded/unlocked.
- **Static-confirmed:** Apple synchronizes a `TemplateList.cat`, version-3
  Catacomb state, serialized templates per user, and template-list update
  events. SEP mutation alone may require a host-side save/synchronization step
  to remain consistent across reboot and macOS.
- **Static-confirmed:** Apple has prepare/save Catacomb operations and template
  validity/synchronization calls. The recovered sequence is not atomic and has
  no general rollback, so Linux-native enrollment needs explicit compensating
  recovery rather than relying on an Apple transaction guarantee.
- **Static-confirmed:** the SEP-side Catacomb protocol is explicitly phased:
  prepare (`0x3d`, protocol v1/v2), complete (`0x3e`, v1/v2), and confirm
  (`0x3f`, v1/v2). Catacomb loading is command `0x40`; declaring no Catacomb is
  command `0x31`. This strongly indicates a transactional host/SEP persistence
  handshake, not an optional metadata write.
- **Static-confirmed, same-generation corroboration:** saving a component calls
  SEP prepare, obtains the secure blob with SEP complete, archives secure data
  plus version/user/identity metadata, stages each host file, commits the host
  write on the final component, and then issues SEP confirm for each component.
  Error `269` is treated as invalid Catacomb state and can trigger identity-list
  clearing plus Catacomb deletion. The ordering exposes crash windows and makes
  the load-time reconciliation path part of the safety design.

### Linux/fprintd user model

- **Primary-source confirmed:** fprintd models access by a claimed Linux
  username. Enrolling or inspecting another username requires its
  `setusername` PolicyKit authorization (root by default). It supports a
  multi-stage `EnrollStart`/`EnrollStatus`/`EnrollStop` lifecycle and deletion
  of one named finger or all fingers for the claimed user.
- **Design implication:** fprintd's username and finger-name layer can provide
  the Linux UI and authorization boundary, but it cannot create AppleKeyStore
  users, derive SEP enrollment authorization, or decide Apple user IDs. The T2
  backend needs a durable, private mapping from Linux account to an already
  valid Apple/SEP user context plus identity UUID to human finger name.
- **Design implication:** because the T2 is a match-on-device reader, fprintd's
  stored record should be a small reference/mapping record, not biometric
  imagery or a copied template.

### Apple account and keybag binding

- **Exact 24G830 static finding:** Catacomb user components
  persist two independent UUIDs: `CatacombUserUUID` and
  `CatacombUserKeybagUUID`. On matching macOS,
  `getUserKeybagUUIDForUID:` negates the numeric UID, calls
  `aks_get_bag_uuid(-UID, bytes)`, and wraps the returned 16 bytes as `NSUUID`.
  The archived value is therefore the live UUID of the installed negative
  special-bag alias, not a UUID derived from the Unix UID and not merely a
  property of an arbitrary positive temporary handle.
- **Exact 24G830 static finding:** `getUserUUIDsForUIDs:userUUIDs:` converts the
  requested numeric UIDs to strings and queries OpenDirectory's Users records,
  matching `kODAttributeTypeUniqueID` and returning
  `kODAttributeTypeGUID`. It parses each GUID as `NSUUID` and constructs the
  UID-to-account-UUID dictionary used by `getUserUUIDForUID:userUUID:`. Thus
  matching macOS binds `CatacombUserUUID` specifically to the OpenDirectory
  user GUID. Validation compares both that current OD GUID and the current
  `aks_get_bag_uuid(-UID)` result with Catacomb metadata; missing or conflicting
  state invalidates the component rather than synthesizing a Linux mapping.
- **Design implication:** using an arbitrary Linux UID is unsafe even if SEP
  accepts the integer. A durable Linux mapping would need an existing Apple
  account identity, its loaded AKS bag handle/UUID, and compatible Catacomb
  metadata. Creating those prerequisites remains outside the biometric command
  protocol.
- **Exact 24G830 static finding:** the matching macOS executable contains the
  `BiometricKitXPCServerMesa` hardware subclass, whose archive override calls
  the inherited base implementation before adding only the master-component
  keys `CatacombEnrollmentCount` and `CatacombCurrentDate`. The recovered exact
  `BiometricSupport` superclass proves the macOS base behavior: it obtains the
  account UUID with `getUserUUIDForUID:userUUID:`, obtains the live bag UUID
  with `getUserKeybagUUIDForUID:`, archives them as `CatacombUserUUID` and
  optional `CatacombUserKeybagUUID`, restores the account UUID during decode,
  and rejects a present bag-UUID mismatch. The precise backing account-manager
  calls remain outside this framework, but the macOS Catacomb binding itself is
  no longer merely mobile corroboration.

## Provisional feasibility assessment

- **Per-finger management for an existing, provisioned Apple/SEP user:**
  protocol-feasible, but not yet safe to expose. Enrollment authorization,
  start/continue, single-identity delete, enumeration, count, typed archive,
  Catacomb save, and recovery boundaries are recovered.
- **Multiple Linux accounts backed by multiple already-existing macOS/SEP
  users:** protocol-feasible under a serialized broker, conditional on a fully
  reconciled mapping and per-user bag/ACM/Catacomb lease.
- **Creating a brand-new T2 biometric user solely from Linux:** the AKS create
  protocol is recovered, but remains unsafe because OD, APFS, identity-file,
  registry, bag, and Catacomb effects are non-atomic and lack complete
  compensation. An arbitrary Linux UID cannot replace Apple provisioning.
- **Safe coexistence with macOS:** unproven. A Linux mutation must update the
  Catacomb and host TemplateList coherently or macOS may restore stale state,
  discard names, or see corruption/divergence.

## Key unresolved questions

1. Whether a complete, evidence-backed compensation strategy can ever make
   new top-level AppleKeyStore/OD/APFS user creation safe from Linux.
2. APFS inheritance/xattr behavior only for optional synchronization of a
   Linux-local Catacomb back into macOS; it is not a Linux-local persistence
   or SEP protocol requirement.
3. The final T2 biometric consumer's replay/one-shot treatment of the mode-0
   ACM external form. Host-visible generic status 67 is already settled as
   non-duplicate-specific and must map to `enroll-failed`.
4. Whether SEP snapshots the UID/keybag association at operation start or
   re-evaluates it during later Catacomb phases. Host-side evidence cannot
   distinguish the two, so the current protocol deliberately holds the same
   verified UID context through final confirmation.
5. Observed dual-boot behavior after a controlled Linux-side mutation. This
   remains deliberately untested until all safety gates and explicit approval
   exist.

### Exact macOS superclass acquisition status (historical attempt and closure)

An exact macOS 26.1 x86_64 cache family has now been copied from the machine and
validated (`dyld_v1 x86_64`, platform macOS, OS 26.1, 710 images, one
subcache). Its main and `.01` SHA-256 values are respectively
`2731b3979a0b31df7a15215d9a9b9edcdd28b357b7d5b9da1c26d939e016102d`
and `98a93bc5d53ea0f929c451022d72a79d009f6dfb01aa1fe5a91cbc36b6af173c`.
This removed uncertainty about that captured cache's version, but its image
manifest establishes that it is the reduced Recovery/BaseSystem cache. It
contains AppleKeyStore and LocalAuthentication but no BiometricSupport image,
`BiometricKitXPCServer`, or `BiometricKitXPCExportedObject`. Searching its image
list and symbol cache therefore could not recover the missing superclass from
that particular Recovery cache.

This boundary was rechecked directly rather than inferred from filenames. The
cache advertises UUID `E0F2B6DB-51BF-359C-90DC-331DE06552E8`; `ipsw dyld info
-l` lists all 710 images without a Biometric image, and an exact extraction
request for
`/System/Library/PrivateFrameworks/BiometricKit.framework/BiometricKit`
returns `image ... not found in cache`. The path does occur as an ordinary
string in the cache, but that is dependency/loader metadata, not proof that the
Mach-O image is present. The captured `BaseSystem.dmg` was also mounted
read-only from its APFS container and searched; it contains no BiometricKit or
BiometricSupport executable. Finally, the framework captured from the running
system contains only its outer symlink and resources: the symlink target
`Versions/Current/BiometricKit` was not copied. There was therefore no
extractable matching superclass in those initial 26.1 Recovery artifacts. This
was an acquisition limitation at that stage, not a permanent protocol gap.

The exact AppleKeyStore framework was extracted from this cache as
`apple-artifacts/macos-recovery-26.1-AppleKeyStore` (Mach-O x86_64, UUID
`6672C2F6-9188-3AB6-A7C4-51F694E85A44`, source version `2155.40.12`, SHA-256
`d5e6cee8f3d185af6bd69901872646514668c30861032ad64a4405134931181e`).
It is authoritative for the matching OS generation's public/private AKS client
surface, but RecoveryOS presence does not by itself establish ordinary-login
authorization behavior.

The original update asset is a delta payload, and the first cross-platform
attempts could not apply its Darwin-only RawImagePatch/AppleArchive forms. That
acquisition limitation is now historical for the target build: the materialized
24G830 `dyld_v1 x86_64h` cache family (UUID
`FDD97301-9818-3865-A1D2-FEC1D3914796`) and exact x86_64 BiometricSupport,
BiometricKit, BiometricKitUI, and LocalAuthenticationCore images are present and
used throughout the later sections. The 26.1 Recovery cache remains valid only
for the specifically version-qualified AppleKeyStore evidence above; it is no
longer described as the source required to close the target-macOS superclass.

## Enrollment client state machine (same-generation static evidence)

The iOS 26.1 `BKEnrollOperation` client wrapper makes the otherwise opaque
Mesa enrollment statuses actionable:

- Statuses **100 through 355 inclusive** are enrollment progress. The client
  computes `100 * (status - 100) / 255`, reports that percentage, and
  immediately issues `enrollContinue` (wire command `0x0e`). The matching T2
  daemon's parsed status `0x107` (263) is therefore approximately **63%**, not
  a terminal result.
- Status **70** also issues `enrollContinue`, but without reporting a new
  percentage.
- Statuses **66, 67, and 68** terminate through enrollment failure reasons
  **1, 2, and 3**, respectively. The shipping UI identifies these as
  **cancelled**, **failed**, and **timeout**.
- Status **501** means accessory authorization is required; its details carry
  `BKAuthRequiredForAccessory`. Other statuses fall through to the generic
  operation handler.
- Successful enrollment is delivered through the distinct
  `enrollResult:details:client:` callback containing the new server identity;
  it is not inferred from the progress range. Interruption maps to failure
  reason 2.

`BKEnrollTouchIDOperation` does not decode detailed finger topology from the
progress notification itself. For each progress status it separately calls
`pullAlignmentData`, runs a component-set update, and generates the richer UI
progress object. Therefore a minimal fprintd implementation can drive the
continue cadence and percentage without understanding the complete
`message_enroll_node_v2_t` payload; Apple’s graphical coverage UI needs the
additional alignment query.

## Terminal enrollment-result event

The matching T2 daemon's service-status jump table identifies raw status
**`0xe3ff8003`** as the enrollment-result event. Its parser has two explicit
wire-version paths:

- Version 1 requires exactly 20 bytes. The daemon copies those 20 bytes into a
  zeroed 40-byte buffer and sets the dword at offset 20 to `1`, producing the
  newer form before entering the common parser.
- Version 2 requires at least 40 bytes. Bytes 0..3 become the identity's
  32-bit Apple user ID; bytes 4..19 initialize its UUID; and the record at
  offset 20 is passed to `getAccessoryObject:`. The 40-byte minimum and legacy
  expansion show that this trailing accessory/group record is 20 bytes.

The host constructs the identity object with type 1, attribute 0, entity 0,
and the current creation time; these values are not supplied by the terminal
message. If accessory decoding succeeds it attaches that object, inserts the
identity into the daemon's in-memory list, reports it to analytics, calls
`enrollResult:withTimestamp:`, and advances the operation queue. No finger name
or Linux username appears in this event. The durable device handle is therefore
exactly the Apple user ID plus identity UUID; naming remains host metadata.

This resolves the previously open terminal-payload question. It also confirms
that a progress status must never synthesize success: only service status
`0xe3ff8003`, after a structurally valid result record, creates and delivers the
new identity.

### Raw service-envelope map

Decoding the matching daemon's 16-entry jump table gives the surrounding event
map and removes ambiguity between an envelope type and its ordinal/status:

| Raw service status | Host interpretation |
|---|---|
| `0xe3ff8001` | Generic status message; ordinal carries statuses such as 66..68 and 100..355 |
| `0xe3ff8002` | Match result |
| `0xe3ff8003` | Enrollment result |
| `0xe3ff8004` | Statistics message |
| `0xe3ff8005` | Sensor-status message |
| `0xe3ff8006`, `0xe3ff8007` | Home/Touch ID button state transitions |
| `0xe3ff8008` | Kernel log message |
| `0xe3ff8009` | Sensor-recovery reason |
| `0xe3ff800a` | Secure Key Store lock-state update |
| `0xe3ff800b` | Match-event message |
| `0xe3ff800c` | Accessory-list change/cache refresh |
| `0xe3ff800d` | Sensor initialization and template-list synchronization |
| `0xe3ff800e` | Device/accessory authorization required |
| `0xe3ff800f` | Mesa hardware-pass report |
| `0xe3ff8010` | Accessory image-information message |

Each case enforces its supported wire version and minimum/exact data length
before dispatch. Unknown envelopes are not enrollment outcomes; the daemon
attempts legacy normalization or rejects them. A Linux bridge should preserve
this two-level model (`envelope`, `ordinal`) and validate lengths before any
state-machine transition.

### Duplicate and capacity result mapping

The complete recovered `BKEnrollOperation` status switch has only three
terminal failure reasons: cancellation (status 66), generic enrollment failure
(67), and timeout (68). Successful enrollment arrives through the separate
identity callback described above. Neither that wrapper, the matching daemon's
enrollment-result parser, its strings, nor the shipping Touch ID enrollment UI
contains a duplicate-specific terminal mapping.

The matching daemon's lower-level dispatch resolves one more layer: raw service
status **`0xe3ff8001`** is the generic biometric status-message envelope, and
its 64-bit ordinal is forwarded as the public biometric status. Ordinals
100..355 are enrollment progress; selected lower ordinals, including 66..68,
take the same forwarding path. Thus enrollment failure is physically delivered
as envelope `0xe3ff8001`, ordinal 67. The host does not derive 67 from an error
code and does not retain a second duplicate/full subtype in this path.

This is negative evidence, not proof that SEP firmware can never internally
recognize a previously enrolled finger. Any finer producer-side cause would
have to be recovered from SEP/Mesa firmware rather than `bkremoted`, which only
transports the service envelope. It is sufficient to set a safe API rule: the Linux
backend must not translate status 67 into fprintd `enroll-duplicate`, because
the same status represents generic enrollment failure. It may report
`enroll-data-full` after a zero result from the read-only free-capacity command,
before command `0x03` is sent. Until a producer-side distinct result is found,
all other terminal failures remain `enroll-failed`.

### Producer-side firmware boundary

The matching bridgeOS 10.1 / build 23P1072 restore image contains the J132 SEP
firmware at `Firmware/all_flash/sep-firmware.j132.RELEASE.im4p`. It has been
preserved with the other read-only artifacts under
`apple-artifacts/bridgeos-sep/`. The IM4P is type `sepi`, approximately 4.1 MB,
encrypted, and has SHA-256
`c52ae05d9319d5c00aa150da0c49b529d466da27e5e4d2077c1e895f5e3632f4`.
The containing restore image has SHA-256
`c268942f49a9f0ac4c2e72a9f5394481e9f971ea92f2e741f41f0cf9dd99912d`.
Its embedded production and development KBAG records contain
wrapped IV/key material; passing those displayed bytes directly as an AES
IV/key produces random data, not a SEP firmware container. No public plaintext
key was returned by the available firmware-key lookup for build 23P1072.

This boundary was rechecked against the preserved artifact on 2026-08-28 with
the current local `ipsw` parser. `im4p info` reports type `sepi`, payload length
4,141,056, and `Encrypted: true`; `im4p extract --kbag` reproduces the two KBAG
records. Supplying the displayed production IV/key bytes to the decrypt path
produces a same-length high-entropy blob beginning
`70 a2 62 9a 8e 64 b7 85`, with neither a recognized container magic nor
meaningful strings. Therefore the printed KBAG `Key` field is wrapped material,
not a usable firmware AES key. The final mode-0 enrollment-authority consumer
is not present in the plaintext bridgeOS root or host binaries and cannot be
recovered from this firmware package without an independently obtained
plaintext J132 key/image.

This establishes that the producer-side artifact is available but cannot yet be
statically disassembled. The host-side evidence remains decisive for API
behavior: the complete generic status envelope supplies only ordinal 67 and no
details object or subordinate error code. Even if a duplicate-specific reason
exists internally inside the encrypted SEP firmware, macOS discards it before
the callback observed by clients. Linux therefore still cannot safely emit
`enroll-duplicate` from status 67. Resolving the internal producer distinction
would require a legitimate plaintext SEP firmware key or a separately obtained
decrypted image; it is not necessary for conservative host-compatible mapping.

The exact 24G830 Touch ID capture-status mapper is now instruction-decoded in
`BiometricKit`: status 78 -> capture error 6; statuses 79 through 84 -> no
capture error; 85 -> 1; 86 -> 2; 87 -> 3; 88 -> 4; 98 -> 5; every other
status -> no capture error. `BiometricKitUI`'s exact capture-error switch treats
error 2 as insufficient/small coverage, counting consecutive occurrences and
showing the small-coverage alert under its configured thresholds. Errors 1,
3, 4, 5, and 6 share the ordinary rejected-capture animation path rather than
producing distinct terminal failures. The UI contains a separate error-7
dirty-sensor alert branch, but the current status mapper never produces 7;
it must not be synthesized from an unknown status.

The same exact UI's terminal delegate further confirms deliberate information
loss. `enrollOperation:failedWithReason:` accepts reason 1 (cancellation), 2
(generic failure), and 3 (timeout). Generic failure and timeout show different
UI text paths but both report final enrollment result 2 to the outer delegate;
ordinary cancellation reports result 3 (a private cancel-for-restart path
suppresses that terminal report and restarts). No fourth duplicate result or
details object exists. Therefore Linux may expose timeout separately only while
it directly observes raw status 68; after a reconnect or a UI-level collapsed
result it must report generic failure/outcome unknown, not reconstruct a cause.

UI behavior shows capture error 2 represents insufficient/small coverage;
errors 1 and 3–6 are ordinary failed estimates with phase-specific feedback.
Capture error 7 is a dirty-sensor alert reached through another path.

The UI supplies two additional operational meanings: status **74** schedules
“lift your finger”, and status **93** displays the dirt-on-sensor alert. It
treats 78, 85, 87, 88, and 98 identically as failed estimates, while 86 alone
drives small-coverage counters. No recovered evidence safely distinguishes
those five failed-estimate statuses into fprintd's more specific “too short”,
“too fast”, or “not centered” strings. The conservative mapping is therefore:
74 -> `enroll-remove-and-retry`; 78/85–88/98 -> `enroll-retry-scan` (with 86
optionally described as low coverage in a richer UI). Do not invent detailed
causes from their numeric order.

### Enrollment event-flow conformance matrix

The transport envelope, ordinal, operation identity, and connection generation
must all validate before an event can move enrollment state. The minimal
conservative state machine is:

| Observed event | Required transition | Automatic `0x0e` continue | External result boundary |
|---|---|---:|---|
| `0xe3ff8001`, ordinal 100..355 | Active -> progress; compute `floor(100 * (ordinal-100) / 255)` | yes, exactly once for that accepted event | progress only; never success |
| `0xe3ff8001`, ordinal 70 | Active -> continue-without-new-progress | yes, exactly once | no terminal result |
| ordinal 74 | Active -> waiting-for-finger-removal | no invented continue | `enroll-remove-and-retry` feedback |
| ordinals 78, 85, 87, 88, 98 | Active -> rejected-capture feedback | no invented continue | generic `enroll-retry-scan` |
| ordinal 86 | Active -> rejected-small-coverage feedback | no invented continue | `enroll-retry-scan`; richer UI may say low coverage |
| ordinal 93 | Active -> dirty-sensor advisory | no invented continue | advisory/retry only, not terminal failure |
| ordinal 66 | Active/cancel-requested -> cancelled-terminal | no | cancellation only after event and post-cancel inventory |
| ordinal 67 | Active -> generic-failure-terminal | no | `enroll-failed`, never duplicate |
| ordinal 68 | Active -> timeout-terminal | no | timeout may be retained only while this raw event is directly observed; otherwise generic failure/unknown |
| `0xe3ff8003` with valid v1/v2 identity record | Active -> SEP-identity-observed | no | provisional identity only; `enroll-completed` waits for Catacomb and stable read-back |
| `0xe3ff800e` / ordinal 501 accessory authorization | Active -> accessory-authorization-required | no guessed retry | unsupported for built-in-only Linux flow unless the accessory protocol is explicitly implemented |
| unknown envelope, ordinal, version, length, operation, or generation | no transition | no | protocol error; freeze/reconcile if an operation was active |

“Exactly once” is scoped to a uniquely accepted event on the current operation
and transport generation. A duplicate delivery must not send a second continue;
an out-of-order or late event from an old connection must be rejected. The
broker needs a bounded event fingerprint/sequence discipline even if the Apple
wire record lacks an explicit monotonic sequence number. It may serialize one
interactive enrollment at a time and remember accepted envelope/ordinal/raw-
payload hashes for that operation; ambiguity freezes the operation rather than
guessing whether SEP is waiting for another `0x0e`.

The 100..355 range is a 256-node Apple progress space, not automatically
fprintd's declared stage count. An adapter must choose and publish a stable
monotonic bucketing policy, coalesce repeated or regressive percentages, and
emit a stage transition only when a new bucket is crossed. It must not emit 256
unbounded callbacks merely because ordinals arrived, and it must not convert
100% progress into success. Only the separate structurally valid identity event
can establish `SEP-identity-observed`.

Cancellation is a handshake, not a local state flip. `EnrollStop` records
cancel intent and sends cancel only on the still-owned live operation. Until
ordinal 66 or a stronger terminal event arrives, state is `cancel-requested`.
If the connection disappears, no event from the replacement connection may be
attached to the old operation; a fresh stable identity inventory determines
whether an identity appeared, but cannot reconstruct the lost terminal reason.
The old authorization is wiped and never reused regardless of inventory.

Terminal delivery to fprintd is intentionally later than Apple UI delivery:
generic failure, timeout, and observed cancellation can finish after the
post-operation inventory establishes no newly created UUID; an identity result
advances through Catacomb persistence and `E3_RECONCILED` before
`enroll-completed`. If a UUID appeared alongside an error, cancel, timeout, or
disconnect, report persistence/reconciliation-required rather than the raw
failure as though no mutation occurred.

## Enrollment completion and persistence failure

The matching local T2 macOS daemon's
`enrollResult:withTimestamp:` implementation (VA `0x100037c8a`) establishes the
completion ordering directly:

1. Log the returned identity/result.
2. Call `saveCatacomb`.
3. Call `saveBioLockoutRecord`.
4. Update counters and post the enrollment-changed notification.
5. Deliver `enrollResult:` to the active registered foreground client.

### Multi-component Catacomb save ordering

Same-generation superclass recovery clarifies how a *first* per-user Catacomb
is created. There is no separate host-side `create user Catacomb` operation in
this path. A successful first enrollment dirties the SEP/component state;
`enrollResult:` calls `saveCatacomb` with no component restriction;
`getCatacombSaveListForComponents:nil` reads current Catacomb state, selects
every component whose state contains dirty bit `0x04`, places non-master
components first, and appends the master component whenever anything is dirty.
The ordinary prepare/complete/archive/write/commit/confirm sequence then
materializes `user_<UID>.cat` and rewrites `master.cat`. The observed
delete/re-enroll capture—user file absent before re-enrollment, then user and
master files created/rewritten afterward—is consistent with this exact flow.

This makes initial Catacomb creation an enrollment-triggered persistence
milestone, not a prerequisite provisioning API. It also means a successful SEP
enrollment can exist before any user component has been durably created, and
the caller still receives the new identity because the matching macOS
`enrollResult:` ignores `saveCatacomb`'s return value.

The same-generation superclass archives ownership fields only after SEP
prepare and complete have already returned the secure component blob. For a
user component it obtains the account UUID from a per-UID cache or
`getUserUUIDForUID:userUUID:`. Failure to obtain that account UUID aborts the
archive. It then queries `getUserKeybagUUIDForUID:`; a successful live result
updates a per-UID cache, while a failed live query falls back to the cached
value. If both are absent, the code simply omits
`CatacombUserKeybagUUID` and continues successfully.

Therefore the two ownership fields do not have equal creation-time strength:
the account UUID is a host-side archive gate in this generation, whereas the
keybag UUID is optional at serialization time even though later validation
uses it when present. Linux must adopt a stricter rule. A newly provisioned
user component may not be committed unless both the independently resolved
Apple account/membership UUID and the live loaded-bag UUID are present and
match the journaled target. It must never reuse a stale cached bag UUID merely
to make first enrollment persist, and it must classify a component lacking a
bag UUID as legacy/degraded evidence rather than silently blessing it as a
fully bound new mapping.

The corresponding unarchive path confirms that omission is an intentional
compatibility case rather than merely a decompiler artifact. A missing
`CatacombUserUUID` is repaired only by resolving the current account UUID, and
failure to resolve either value rejects the component. By contrast, a missing
`CatacombUserKeybagUUID` is accepted immediately. When the archived keybag UUID
is present, the loader caches it and compares it with the live keybag UUID only
if the live query succeeds; an unavailable live UUID also accepts the archived
component. Only a present archived UUID plus a present, unequal live UUID
produces error `269`.

This is a fail-open compatibility rule for legacy/unavailable keybag metadata,
not a safe provisioning invariant. A Linux importer may preserve such a
component for read-only recovery, but it must not create or activate a new
Linux-to-Apple user mapping until a live bag UUID is independently obtained and
the Catacomb is reconciled against it. “Apple's loader accepted it” is not
proof of a complete account-to-keybag binding.

`saveCatacombForComponents:` is not a conventional atomic two-phase commit.
For every component it archives host metadata, stages a file with `writeData:`,
and—unless it is processing the final component—immediately sends SEP confirm
command `0x3f`. Only on the final component does it call `commitWrite` for the
staged host-file batch before sending that component's SEP confirmation.

Therefore a later archive/write failure can occur after earlier components have
already been confirmed inside SEP but before the corresponding host-file batch
is committed. There is no abort/inverse command for those confirmations. A
failure of `commitWrite` similarly cannot undo earlier SEP confirmations. This
means a multi-user or multi-accessory save journal must record, per component:
prepared, host-staged, SEP-confirmed, host-batch-committed, and read-back
reconciled. A single global “save succeeded” boolean loses essential recovery
state.

The error cleanup is also destructive. If the save returns error **269**, the
server clears its entire cached template list and calls `deleteAll` on the host
Catacomb store. It does not roll back SEP first. Linux must never copy this as
automatic recovery: it should preserve evidence and backups, stop mutations,
and expose a degraded/reconciliation-required state. Error 269 must not trigger
automatic deletion of either local metadata or SEP identities.

Crucially, the return value from `saveCatacomb` is **not tested**. The success
identity is still delivered to the client if host-side Catacomb persistence
fails. No inverse identity-delete or other enrollment rollback is visible in
this callback. Thus a Linux implementation must not equate the SEP enrollment
result with durable success: it must independently verify Catacomb save,
re-enumerate identities/state, and surface a persistence failure even if the
sensor returned a new identity.

Cancellation is explicit but only protects an operation that has not already
completed: an active operation is marked cancelled and sent the SEP cancel
command, while queued operations are removed and receive their cancellation
status. Reconnect cleanup also reports queued/running operations as cancelled.
This provides no evidence that cancellation after an enrollment result deletes
the newly created SEP identity.

## Catacomb commit and crash windows

`saveCatacombForComponents:` locks the cached identity collection, obtains a
save list, and for each component performs prepare (`0x3d`), complete (`0x3e`),
archives secure data plus host identity metadata, and stages a host file write.
It calls the host file transaction's `commitWrite` once, after staging the last
component, then sends SEP confirm (`0x3f`) for that final component. Earlier
components are confirmed during the loop before the final host transaction
commit.

Consequences visible from this ordering:

- a prepare/complete/archive/write error exits without a visible protocol-level
  abort or compensating identity mutation;
- in a multi-component save, SEP may have confirmed earlier components before
  the host files are committed;
- a final host commit failure occurs after any earlier confirmations and before
  the last confirmation;
- a final confirm failure occurs after host data has already committed;
- error 269 triggers destructive recovery (`clearTemplateList` and deletion of
  all Catacomb files), but other errors merely propagate to the caller; and
- the enrollment-result caller ignores even that propagated save error.

The protocol therefore behaves as a reconciliation scheme, not an atomic
two-phase transaction spanning SEP and APFS. Crash recovery must be treated as
an explicit requirement, with read-back comparison of SEP Catacomb state,
persisted component files, and the identity list.

### Recovered legacy single-file Catacomb writer

The matching `biometrickitd` contains the C support implementation identified
by its embedded Apple source path as `AthabaskanSnapshot/support/catacomb.c`.
This resolves the older `TemplateList.cat` storage path and its exact local
replacement sequence, but must not be conflated with the higher-level
multi-component object that receives `writeData:` and `commitWrite`.

Its directory helper calls `CFCopyHomeDirectoryURLForUser(NULL)`, appends the
literal path component `Library/Catacomb`, converts the URL to a POSIX path,
and calls `mkdir(path, 0777)`, accepting `EEXIST`. `0777` is the requested mode,
not proof of the final mode: the daemon's process umask still applies. The
single-file writer then:

1. derives `<name>.tmp` in that directory (a fixed suffix, not a unique file);
2. opens it with `fopen(..., "wb")`, truncating any prior temp file;
3. requires one full `fwrite` of the requested byte count;
4. invokes `fcntl(fd, 0x33)`, Darwin `F_FULLFSYNC`, and closes the stream;
5. renames the temp file over the final pathname;
6. opens `Library/Catacomb` with Darwin `O_DIRECTORY` (`0x100000`), invokes
   `F_FULLFSYNC` on the directory descriptor, and closes it.

There is no advisory file lock in this C writer. Every write failure after the
temp file is opened closes the stream but does not unlink `<name>.tmp`; a
rename failure likewise leaves it behind. A crash before rename can therefore
leave a partial or complete stale temp file. A crash after rename but before
the directory `F_FULLFSYNC` leaves the new pathname visible in memory/cache but
without the writer's final rename-durability guarantee. Because concurrent
writes to the same name share one temp pathname, correctness depends on a
higher-level serialization scope not present here.

The companion deletion helper builds the final path and calls `unlink`, but
does not inspect or return the `unlink` result: once path construction succeeds
it reports success even if deletion failed. Recovery and verification must
therefore inventory both final and `.tmp` files, validate their archive content
and hashes independently, and never infer absence from this helper's return
value. No recovered branch promotes a stale `.tmp` automatically, so Linux
must preserve it as evidence rather than guessing that it is newer or valid.

The apparent `_NSFileProtectionKey` / `_NSFileProtectionNone` reference in the
matching daemon is not Catacomb evidence. Its surrounding routine builds dated
diagnostic/log attachment paths, supplies an owner-account attribute, and is
adjacent to the daemon's BioLog/sysdiagnose collection flow. It must not be
used to assign a protection class to Catacomb archives. The modern Catacomb
coordinator is implemented by the external `BiometricKitXPCServer` superclass
from `BiometricSupport`; the subclass's `saveCatacombForComponents:` first
calls that superclass implementation and only then removes legacy
`TemplateList.cat`. Consequently the fixed-temp C writer is definitively the
legacy compatibility path.

### Exact 24G830 multi-component file transaction

The exact macOS 15.7.9 (24G830) System dyld cache has now supplied the matching
x86_64h `BiometricSupport` framework. It contains complete local symbols for
`BKCatacomb` and `BiometricKitXPCServer`, including
`writeData:toFile:`, `commitWrite`, `recover`, and
`saveCatacombForComponents:`. This replaces the previous same-generation
extrapolation with target-build evidence.

The store root defaults to `/Library/Catacomb/`. In the exact daemon
initializer, `gethostuuid` supplies 16 bytes, `uuid_unparse_upper` renders the
uppercase UUID, and the server constructs `/Library/Catacomb/<host UUID>/`
plus `biolockout.cat` before calling `+[BKCatacomb catacombWithDir:]` and then
`recover`. Thus the Catacomb directory identifier is specifically the Darwin
host UUID, not a user, account, keybag, persona, or biometric identity UUID.
Within that root,
`writeData:toFile:` implements staging as follows:

1. Refuse the write if `commit/` already exists. This preserves an interrupted
   promoted transaction for `recover` instead of mixing a new batch into it.
2. Create `prepare/` with intermediate directories if it does not exist.
3. Create `prepare/<component filename>`, obtain an `NSFileHandle`, write the
   complete encoded `NSData`, and call Darwin `fcntl(fd, 0x33)`
   (`F_FULLFSYNC`) on the file descriptor.
4. Close the file and call `syncDir:` on `prepare/`; `syncDir:` opens the
   directory with `O_DIRECTORY` (`0x100000`) and also applies
   `F_FULLFSYNC`.
5. On any write/sync exception or error, call `recover` and return a failure;
   the caller must still treat the wider SEP transaction independently.

After every selected component has been staged, `commitWrite` requires
`commit/` to be absent and `prepare/` to be present, then performs a directory
rename from `prepare/` to `commit/`. It enumerates the filenames in `commit/`
and promotes them **one at a time**: if the corresponding root file exists it
removes that root file, then moves `commit/<name>` to `<root>/<name>`. Only
after all files have moved does it remove the now-empty `commit/` directory and
`F_FULLFSYNC` the Catacomb root.

This is a durable staged batch but not an atomic directory exchange. Between
the first root-file removal and the final root-directory sync, readers may see
a mixed old/new component set, and power loss may leave a partially promoted
batch. The server mitigates concurrent in-process access by locking its
`catacombLock` for the entire `saveCatacombForComponents:` operation and
unlocking it on every exit. That lock does not serialize a separate Linux
writer while macOS is offline or running.

`recover` gives the on-disk names exact transaction meaning:

- if `prepare/` exists, remove it unconditionally; it represents a batch that
  never crossed the commit boundary and is rolled back locally;
- if `commit/` exists, enumerate it and complete the same per-file root
  replacement loop, then remove `commit/` and `F_FULLFSYNC` the root; it is a
  committed batch and recovery rolls it **forward**, never back; and
- if both exist, discard `prepare/` first and then roll `commit/` forward.

Thus `prepare/ -> commit/` is the host-file irreversibility boundary. A future
Linux recovery implementation may inspect these directories without guessing:
it must discard only a validated `prepare/`, finish only a validated `commit/`,
and refuse either action when filenames, archive schemas, ownership, or the
journaled transaction ID are not the expected immutable set. It must then
reconcile every component against SEP because host forward recovery does not
repair or reverse the already non-atomic SEP confirmations.

The default `BKCatacomb` initializer leaves its private write-attributes slot
nil, and `catacombWithDir:` changes only the root directory. The exact writer
passes that slot to Foundation directory/file creation, so this class itself
does not explicitly select `_NSFileProtectionKey`. This narrows the remaining
protection question to filesystem/directory inheritance, daemon-side private
ivar mutation outside the public method surface, or platform behavior; the
tar captures still cannot prove xattrs or APFS protection classes. Crucially,
that uncertainty is a **macOS-volume synchronization** question, not part of
the serialized Catacomb or SEP protocol. Linux already loads the opaque secure
component bytes from its private root-owned store. A Linux-native manager can
persist new components on its own filesystem with equivalent file/directory
fsync ordering and private permissions; it does not need to invent APFS data-
protection metadata. Copying those files back into `/Library/Catacomb` remains
a separate macOS-side operation and must preserve or deliberately re-establish
the destination directory's inherited attributes.

Read-only archives captured from this machine establish the modern visible
layout as `/Library/Catacomb/<machine UUID>/`, containing `master.cat`,
`user_000001f5.cat`, and `biolockout.cat`. Across the pre-freeze, empty/fresh,
and re-enrolled captures, both directories are recorded as `root:wheel 0755`
and all component files as `root:wheel 0644`. The empty/fresh capture retains
master and biolockout while the per-user file is absent; re-enrollment creates
the user component again and rewrites all three component timestamps. This is
useful observed replacement/absence behavior, but the captures use POSIX ustar
and contain no xattrs or APFS protection-class metadata. They therefore prove
mode/owner values as archived, not the files' data-protection class, ACLs,
flags, or coordinator staging layout.

The 2026-08-30 one-shot evidence capture closes part of that metadata gap on
the observed macOS 26.1 host. `ls -ldeO@`, `xattr -lr`, and `stat` were recorded
against the live Catacomb tree while `biometrickitd` was frozen. The root,
machine directory, and three component files had no visible ACL entries,
extended attributes, or filesystem flags; ownership and modes remained
`root:wheel 0755` for directories and `root:wheel 0644` for files. This is
positive evidence for that installation, not a universal claim about APFS data
protection or other macOS releases.

Independent `plistlib` decoding of the same private capture reproduced the
18-object user keyed-archive graph exactly: one `BiometricKitIdentity`, its
accessory and accessory group, an identity array, secure data, creation date,
and the account and keybag `NSUUID` objects. The account UUID joined the
OpenDirectory/persona record, the Catacomb machine directory joined the host
UUID, and numeric UID 501 joined the filename and identity owner. The identity
name was Apple's ordinal label `Finger 1`; the Catacomb did not encode an
anatomical finger position. Linux therefore needs its own explicit fprintd
finger-name mapping rather than inferring `right-index-finger` from Catacomb.
Although this newer fixture had one identity, its master enrollment-count hint
was 2, reinforcing that the field is a generation/change counter rather than a
current identity count. No private UUID, hostname, raw component, or component
hash from this capture is published here.

### Observed generation and rollback signals

Structural decoding of the preserved NSKeyedArchiver files gives one complete
before/delete/re-enroll sequence for Apple UID 501. This is observational
evidence from the actual machine, not a claim that every counter is guaranteed
monotonic by Apple's protocol.

- The pre-freeze and later `t2-touchid-catacomb.tar.gz` user components are
  byte-for-byte identical (SHA-256
  `<redacted-private-catacomb-sha256>`).
  Their secure blobs, identity UUID, counters, account UUID, and keybag UUID
  are identical as well. Archive/copy time therefore cannot establish
  freshness; a recently copied file may contain an old generation.
- The empty/fresh state omits `user_000001f5.cat` but retains exactly the old
  master component. Its master has `CatacombEnrollmentCount = 1`, and the
  entire master file is byte-for-byte identical across those captures.
- Re-enrollment produces a different user secure blob and changes the identity
  UUID from `<old-biometric-identity-uuid>` to
  `<current-biometric-identity-uuid>`. The new identity's creation time is
  2026-08-27 20:11:39 UTC and its match/update counters begin at zero, as
  expected for a newly enrolled identity.
- `CatacombUserUUID` remains
  `<od-account-uuid>`, and
  `CatacombUserKeybagUUID` remains
  `<aks-bag-uuid>`. These bind the component to the same
  account/keybag; they identify the owner context, not the biometric
  generation.
- The re-enrolled master changes secure data and advances
  `CatacombEnrollmentCount` from 1 to 2. This counter is a useful ordering hint
  within the same machine/account history, but static evidence does not prove
  wrap, reset, restore, or cross-version semantics, so it cannot be the sole
  rollback authority.
- `CatacombCurrentDate` remains the exact same NSDate value
  (2026-08-27 08:16:06 UTC) in both old and re-enrolled masters. It is therefore
  demonstrably not a per-save commit time. Filesystem mtimes likewise describe
  replacement/copy time and are not authenticated generation identifiers.
- `biolockout.cat` changes independently in every preserved capture, including
  captures where master and user are unchanged. Its hash is consequently a
  separate lockout-state signal, not a Catacomb-generation number.

A rollback-safe reader must consequently classify a generation using a tuple,
not one field: machine-directory UUID; Apple numeric UID; account UUID; AKS bag
UUID; ordered identity UUID set plus metadata; raw host component hash; decoded
secure-blob hash; master enrollment-count hint; and the current SEP-reported
Catacomb UUID/hash (`0x38`/`0x3a`). The SEP value and a previously journaled,
durably acknowledged generation are authoritative comparisons. A well-formed
archive whose owner UUIDs match but whose secure hash or identity UUID set is
older is a rollback candidate, even if its mtime is newer and its
`CatacombCurrentDate` looks valid. Linux must not load, promote, or overwrite it
automatically.

The 32-byte SEP Catacomb hash is not established as SHA-256 of either the
NSKeyedArchiver file or its `CatacombSecureData` object. The preserved daemon
log exposes only a redacted prefix (`54f2***`), while neither corresponding
host SHA-256 begins with that value. A future verifier must compare the exact
`0x3a` result according to the recovered protocol or by a confirmed load/check
operation; it must not substitute a convenient host-file digest.

Minimum non-mutating recovery classification is therefore:

| SEP state | Host final file | Temp/staging evidence | Classification and safe action |
|---|---|---|---|
| no Catacomb | absent | absent | Consistent empty component; retain journal evidence |
| no Catacomb | present | any | Orphan/stale host component; quarantine logically and do not load or delete automatically |
| UUID/hash present | absent | absent | Host-loss/incomplete commit; fail closed and preserve SEP state |
| UUID/hash present | absent or old final | candidate present | Interrupted commit; preserve both, validate candidate offline, never auto-promote |
| UUID/hash present | structurally invalid | any | Corrupt host component; fail closed, preserve bytes, require explicit recovery |
| UUID/hash present | valid but tuple/hash differs | any | Divergent or rollback candidate; do not load, confirm, overwrite, or invoke Apple's destructive error-269 repair |
| UUID/hash present | valid and all bindings/read-back agree | absent | Reconciled generation; matching may be enabled, mutation still requires its separate gates |

This table is deliberately asymmetric: ambiguity never authorizes a write,
delete, SEP confirmation, or `no Catacomb` declaration. Recovery promotion
requires a journaled expected generation and exact SEP/host reconciliation,
not merely successful plist decoding.

## Required mutation journal and restart state machine

No recovered Apple layer supplies an atomic transaction across SEP identities,
SEP Catacomb confirmation, host Catacomb files, keybags, APFS records, and the
Linux mapping. A future implementation therefore requires a durable
write-ahead journal; logging after API returns is insufficient.

Each operation record must have a format/version, random operation UUID,
operation kind, creation time (diagnostic only), caller and target numeric Linux
UIDs, Apple UID, account UUID, bag UUID/handles and special alias *identifiers*
(never credentials), component/group IDs, transport and bridge-boot generation,
protocol version, policy decision, and the complete stable pre-operation
inventory. The baseline includes ordered identity UUID/entity records,
capacity, SEP Catacomb UUID/hash/presence, host component byte hashes and
metadata, master counter, mapping generation, and verified backup references.
Runtime bag handles are recorded only to explain the original boot's events;
they are never reusable authority after unload, reconnect, suspend, or reboot.

Journal entries are append-only milestones with a hash chain or equivalent
tamper-evident sequence. Before every possibly mutating request, append and
durably sync an `intent` entry; after the call, perform independent read-back,
then append a separate `observed` entry and sync it. A successful return alone
never advances observed state. Journal replacement/rotation requires file and
parent-directory durability; backups live separately, encrypted and hashed.
There is no cross-filesystem atomicity between the Linux journal and macOS APFS,
so write-ahead ordering and later reconciliation are mandatory.

### New-user provisioning milestones

These milestones remain a research model, not authorization to implement the
mutating operations:

1. `P0_DIRECTORY_BASELINE`: numeric Apple UID and membership/ODUUID exist and
   are stable; no equality with a Linux UID is inferred.
2. `P1_AKS_CREATE_INTENT`: record the exact target ODUUID/session and complete
   top-level identity, APFS cryptographic-user, access-token, identity-file,
   temporary-file, persona-list, Catacomb, and biometric inventories before
   request 10 or kernel selector `0x76`.
3. `P2_AKS_KERNEL_CREATE_OBSERVED`: a concrete new bag handle and returned
   material were observed. Any later error becomes
   `TOP_LEVEL_IDENTITY_CREATE_OUTCOME_UNKNOWN`; it does not return to `P1` and
   must not be retried.
4. `P3_ACCOUNT_TOKEN_AND_APFS_OBSERVED`: independently verify the intended
   OpenDirectory access-token binding and APFS VEK/user-protection record. The
   daemon's return path alone is insufficient.
5. `P4_IDENTITY_DURABLE_OBSERVED`: verify top-level identity-list membership,
   final identity-file content, absence/classification of `.tmp`, loadability,
   exact user UUID, and live bag UUID.
6. `P5_PERSONA_RECONCILED`: if the platform requires an AKS keybag persona,
   verify its selector-`0x61` membership and durable post-reload presence. The
   UserPersona unique string remains a separate field unless an observed call
   proves equality.
7. `P6_BIOMETRIC_EMPTY_BASELINE`: prove no biometric identity and no user
   Catacomb component for the Apple UID while preserving reconciled master/SEP
   state. This is the only valid entry to first enrollment.
8. Run the ordinary `E0`--`E4` enrollment transaction. The transition from
   `E2_TERMINAL_IDENTITY_OBSERVED` to Catacomb persistence is the first creation
   of the per-user Catacomb file; it is not part of `P4` or `P5`.

No Linux mapping becomes active at `P4`, `P5`, or even SEP enrollment result
`E2`. Activation requires `E3_RECONCILED` with both account UUID and live bag
UUID embedded and verified, followed by the ordinary post-reboot gate where
policy requires it.

### Enrollment milestones

1. `E0_BASELINE_RECONCILED`: stable double-collect, recovery backup, password
   fallback, capacity, mapping tuple, keybag lease, and modification policy all
   verified.
2. `E1_ENROLL_START_INTENT/OBSERVED`: exact authorization data and operation
   parameters are hashed/redacted into the intent; observed means SEP accepted
   the start and the operation is active.
3. `E2_TERMINAL_IDENTITY_OBSERVED`: only the separate enrollment-result event
   supplies the new UID+identity UUID. Status 67 does not. Immediately inventory
   SEP; if an identity appeared despite cancellation/error/connection loss,
   enter this state rather than claiming cancellation or retrying enrollment.
4. For every Catacomb component in the immutable save list, record
   `PREPARE_INTENT`, `PREPARED`, `COMPLETE_INTENT`, `SECURE_BLOB_CAPTURED`, and
   `HOST_STAGED`, including the returned size/blob hash and intended final-file
   hash. Earlier components additionally record `CONFIRM_INTENT/CONFIRMED`
   before the loop advances.
5. For the final component record
   `HOST_BATCH_COMMIT_INTENT/HOST_BATCH_COMMITTED`, followed by
   `FINAL_CONFIRM_INTENT/FINAL_CONFIRMED`. These are separate because Apple
   commits host files before the last SEP confirmation but may confirm earlier
   SEP components before the host batch commit.
6. `E3_RECONCILED`: repeat identity, component UUID/hash, host archive,
   account/bag binding, capacity, and mapping checks on a stable connection.
   Only now may fprintd receive `enroll-completed` and the mapping publish the
   new opaque print handle.
7. `E4_POST_REBOOT_VERIFIED`: after the next genuine reload/reboot boundary,
   prove the same generation again before compacting the active journal into a
   retained tombstone/audit record.

`EnrollStop` writes cancel intent and waits for the terminal cancel status, but
cancellation never deletes a UUID already observed. Loss of the connection
between prepare/complete/confirm phases invalidates the transaction lease; the
broker cannot reconstruct SEP pending state from a host blob and must enter
reconciliation-required state.

### Single and batched deletion milestones

Deletion starts from the same reconciled baseline plus an immutable target UUID
set. For each UUID, record `DELETE_INTENT`, command return, and
`DELETE_ABSENCE_OBSERVED` only after two stable inventories prove that exact
UID+UUID absent. A batched delete never rewrites the remaining target set after
starting. After all reachable targets, Catacomb persistence uses the same
per-component milestones above and ends with stable read-back.

If the process stops after some absence observations, those identities are
already gone and there is no inverse/recreate operation. Recovery reports
`partially-deleted` with exact completed and remaining UUID sets. It may resume
remaining deletions only after fresh authorization, unchanged mapping/bag and
Catacomb baseline for the surviving set, and explicit confirmation; it must not
silently continue at boot. “Delete all” succeeds only when the original target
set is absent and the resulting Catacomb is reconciled. Newly appearing UUIDs
are conflicts, not additions to the destructive batch.

Whole-user removal (`0x48`), AKS persona mutation, top-level identity creation,
and APFS record changes require their own journal namespaces. They cannot reuse
per-print deletion milestones because their partial commits and recovery
objects differ.

### Restart classification

| Last durable evidence | Required restart behavior |
|---|---|
| Intent with no observed result | Outcome unknown: read back every affected layer; never blindly replay |
| Enrollment active, no terminal UUID | Cancel only if same live operation/connection is provable; otherwise wait/reconnect and inventory |
| New UUID observed, Catacomb not reconciled | Enrollment-persistence failure; disable mutation/mapping publication and preserve identity plus backups |
| Prepared/completed SEP component, connection lost | Pending transaction unknowable; do not synthesize confirm/abort; enter manual reconciliation |
| Host staged, no committed evidence | Preserve staging artifacts; validate offline; never auto-promote |
| Earlier SEP components confirmed, host batch uncommitted | Cross-domain divergence; fail closed and require expert recovery |
| Host batch committed, final confirmation absent | Do not assume either outcome; compare SEP UUID/hash and host generation before any retry |
| Delete return without stable absence | Outcome unknown; inventory exact UUID before deciding retry |
| Some UUID absences observed | Report partial deletion; retain remaining immutable set; no automatic continuation |
| Full read-back reconciled, no post-reboot proof | Usable for the current boot under policy, but retain active journal |
| Post-reboot tuple verified | Operation may be finalized; retain a compact non-secret audit tombstone |

Compensation is limited to actions whose safety is independently proven by
current read-back. Restoring an old host file, deleting a newly enrolled UUID,
issuing no-Catacomb, replaying confirm, rebinding a keybag alias, or invoking
Apple's error-269 cleanup is never a generic rollback. Any one of those is a
new explicitly authorized recovery transaction with its own baseline and
journal.

The SEP-produced secure data has a small observable envelope. Every preserved
master and user blob begins with ASCII `LTFC`, little-endian version 10, then a
signed 32-bit component UID at offset 8 (`-1` for master, `501` for the user),
followed by zeroed reserved bytes through offset 31. The lockout blob instead
begins `HRLB`, little-endian version 2, and the same zeroed reserved region.
The remainder is opaque and changes independently; user blob length also
changed substantially across re-enrollment (36,980 to 20,795 bytes), so size is
not a generation counter or fixed schema invariant.

Linux can safely reject obvious envelope mismatches before talking to SEP:
wrong magic/version, a master whose embedded UID is not `-1`, or a user blob
whose embedded UID differs from both its filename and archived
`CatacombUserID`. This is only structural rejection. No recovered host code or
captured value establishes a host-verifiable MAC/checksum over the opaque
remainder, and the visible header can be forged in a stale/corrupt file. Only
the SEP load/check path and exact UUID/hash reconciliation can authenticate the
component. The raw secure data must otherwise remain byte-exact and opaque.

## AKS provisioning boundary

The recovered BiometricKit server contains no user/keybag creation path.
Enrollment initialization merely records the requested user ID, client,
authorization structure, and optional accessory group. Before issuing the SEP
enroll command, the server runs its platform-specific `isValidUser:` check and
loads/checks that user's existing Catacomb component.

An exhaustive audit of the same-generation server's named SEP command wrappers
strengthens this negative result. The surface includes enumeration, capacity,
enroll/match/cancel, Catacomb prepare/complete/confirm/load/no-Catacomb,
identity deletion, whole-user deletion, lockout records, protected
configuration, and diagnostics. It contains no create-user, add-user,
provision-user, create-keybag, or bind-account command. The only whole-user SEP
primitive is destructive command `0x48`. The matching macOS daemon subclass
likewise contains no such selector or imported symbol, although final proof for
the inherited macOS framework still awaits its dyld-cache image.

For persistence and later validation it obtains identity material from two
pre-existing platform services:

- the platform account manager supplies the account with the matching numeric
  UID and its stable UUID (`alternateDSID` in the same-generation iOS build);
- AppleKeyStore supplies the already-created bag UUID through
  `aks_get_bag_uuid` for the UID-derived bag handle.

The daemon only reads these values. It neither creates an AKS bag nor creates a
platform account identity. Missing/changed account or keybag UUIDs invalidate
the biometric user and can trigger removal. This separates the project into
three distinct layers: Apple account creation, AKS bag provisioning/unlock, and
BiometricKit/SEP enrollment. Recovering the third layer does not provide the
first two.

Consequently, Linux-native management can safely target multiple users only if
each maps to an already-provisioned Apple user with a stable account UUID and
loadable/unlockable AKS bags. Creating arbitrary Linux-only biometric users
would require the separate AppleKeyStore/OD/APFS provisioning transaction
recovered below; its message and side-effect ordering are known, but its
non-atomic failure windows make it unsafe to expose. Substituting Linux UID
numbers is insufficient.

#### Top-level AKS identity service is distinct from personas

The exact macOS 26.1 AppleKeyStore framework now partially recovers that
separate provisioning layer. In addition to keybag-persona APIs, it exports
`AKSIdentityCreateFirst`, `AKSIdentityCreate`, `AKSIdentityAdd`,
`AKSIdentityReset`, `AKSIdentityDelete`, `AKSIdentityLoad`,
`AKSIdentityExists`, and `AKSIdentityCopyUserUUID`. These are client wrappers
for the privileged `com.apple.applekeystored` XPC service, not calls to the
BiometricKit daemon and not the kernel persona selector family.

The exact create request uses XPC request number `10` and can contain:

- `user_uuid` (a CFUUID, optional for the first-identity case);
- `secret`;
- `session` (omitted when the caller supplies `-1`);
- `session_secret`; and
- `secret_is_acm`.

The add/reset family uses request number `11` and carries `disk`, `user_uuid`,
`acmcred`, `existing_user_uuid`, `existing_user_acmcred`, and a `replace`
boolean. Public wrappers differ mainly in which of those fields they populate.
This is direct evidence that top-level AKS identity creation is keyed by a
stable user UUID plus authentication material and session state, and that
adding/replacing a user may require credentials for an already-existing user.
It is not equivalent to choosing a free numeric UID or adding a persona UUID
inside one loaded bag.

This narrows, but does not remove, the provisioning blocker. The exact client
message schema is known sufficiently to trace the transaction. The matching `applekeystored` executable was
subsequently found in the copied macOS material at
`.local/share/t2-touchid/macos-system/applekeystored` (UUID
`080CDAC0-BCE7-3998-A68C-FA6D2BB92049`, SHA-256
`e9f3ae005c581cb0f8083f91f0e0c0e8155c9c31fcc322ff2d5701cc4fdd1211`,
macOS minimum/SDK 26.1). Its caller authorization, on-disk transaction,
generated bag-handle path, APFS/OD side effects, and lack of full rollback are
recovered below. Nor is there matching-host evidence that an AKS
identity's `user_uuid` is the same value placed into
`CatacombUserUUID`; the mobile `alternateDSID` mapping remains corroborative.
A Linux implementation must therefore not send request 10/11, emulate them at
the SEP endpoint, or claim that `AKSIdentityCreate` creates a complete
BiometricKit user until those two identity domains are proven to join.

The newer `LocalAuthenticationCore` convenience layer independently confirms
the intended administrative split and its argument ordering. Its
`LACAKSIdentityHelper` exposes two user-creation methods. The simple
`createUser:credential:error:` converts the target UUID string to `CFUUID`,
extracts the credential bytes, and calls `AKSIdentityNew(targetUUID,
credential, error)`. The authorized form
`createUser:credential:authorizerUUID:authorizerCredential:error:` converts
both UUID strings, extracts both credentials, and calls
`AKSIdentityAdd(targetUUID, targetCredential, authorizerUUID,
authorizerCredential, error)`. Password changes call
`AKSIdentityChangePasscodeForUuid`; deletion converts only the target UUID and
calls `AKSIdentityDelete(targetUUID, error)`. The wrapper returns success only
when the C API reports true and produces no error object.

This is useful interface evidence, not permission to invoke those APIs from
Linux. `AKSIdentityNew` is the first/unopposed-identity ceremony;
`AKSIdentityAdd` is an explicitly existing-user-authorized ceremony. Neither
creates a BiometricKit user or fingerprint, and delete's lack of a credential
argument means caller/service authorization cannot be inferred from its public
shape. A future administrator must select the ceremony from an inventory of
existing top-level identities and preserve the separate target and authorizer
UUID/credential roles; it must not use the simpler `New` path merely because
an inventory lookup failed.

The matching framework does prove the local UID-to-AKS-identity rule for its
newer OTI (`AppleKeyStore/oti`) path. `AKSIdentityLoad(userUUID, uid, ...)`
uses the caller's explicit UUID when present; otherwise it invokes
`mbr_uid_to_uuid(uid)`, constructs a CFUUID from the resulting 16 bytes, and
passes that UUID together with the numeric UID to the identity-service client.
The legacy path falls back to a UID-only loader. Thus the top-level AKS identity
UUID on this macOS generation is, by default, the OpenDirectory/membership UUID
for that local UID. It is not a free Linux mapping field, a persona UUID, or
proven to be the mobile account-manager `alternateDSID`.

The matching `AKSIdentityLogin` legacy path also shows why provisioning and
login cannot be collapsed into one raw SEP unlock. It asks `applekeystored` to
load the keybag for the UID; when the service returns its not-found status, it
calls the service's keybag-create operation, otherwise it unlocks the loaded
bag. The newer OTI path delegates login using user UUID, secret/credential, and
session. Therefore macOS may create durable keybag state lazily as part of a
coordinated identity login. Reproducing only the final AKS load/unlock packets
would omit the directory UUID binding and the daemon's persistent records.

Static tracing of the exact macOS 26.1 `applekeystored` request-10 handler now
recovers the top-level create transaction more precisely. The dispatcher
passes `user_uuid`, `secret`, `session`, `session_secret`, and
`secret_is_acm` into `service_identity_create_internal`. That routine first
normalizes the numeric session into the special-handle namespace and validates
the supplied user UUID. It then builds a packed create request and invokes the
AppleKeyStore user client with selector `0x76`. The reply contains a newly
created bag handle and up to `0x400` bytes of returned material. A missing
handle is explicitly treated as unsupported, not as successful creation.

After the kernel create succeeds, the daemon still has several independently
fallible milestones. Depending on access-token state and first-user/session
conditions, it can:

1. create or bind an OpenDirectory access token to the user UUID;
2. wrap the returned buffers as `CFData`;
3. bind a new KEK to the APFS VEK or enable APFS user protection;
4. serialize/save the identity through the durable identity writer; and
5. for one access-token state, perform an additional access-token persistence
   step after the identity/APFS work.

The durable writer itself serializes into a bounded buffer, creates a
mode-`0600` temporary file with a `.tmp` suffix, writes the full serialized
identity, optionally updates the APFS unlock record, and then performs the
rename into place. Consequently neither kernel create, access-token binding,
APFS enablement, temporary-file creation, file write, APFS-record update, nor
rename is individually proof of a committed top-level identity.

The create routine does not present an atomic rollback story. Once selector
`0x76` has returned a concrete handle, later access-token, APFS, and save
failures branch through error construction and the common failure exit. That
exit calls `aks_unload_bag(-1)`, whereas the ordinary success cleanup unloads
the concrete returned handle. No compensating top-level identity delete or
APFS/access-token rollback is visible in this function. Static analysis cannot
prove that helper layers secretly undo every prior milestone, so any error
after selector `0x76` must be classified as
`TOP_LEVEL_IDENTITY_CREATE_OUTCOME_UNKNOWN`, not “nothing was created.”

A future Linux broker therefore needs a pre-operation inventory and a durable
journal before attempting top-level creation. Recovery must reconcile at least
the top-level `AKSIdentityList`, loadability and bag UUID, identity file and
temporary file, OpenDirectory access-token binding, APFS cryptographic-user
record, and post-reboot inventory. It must not retry request 10 or raw selector
`0x76` merely because the original call returned an error.

The newer `LACUserControllerDaemon` adds a second, host-side transaction
boundary after the AKS operation. Its first-user and authorized-add closures
both call the corresponding `LACAKSIdentityHelper` create method first. Only
after that reports success do they construct an `LACUserRecord` and invoke the
`LACUserRegistryProviding.writeRecord` witness. If the registry write throws,
the closure propagates the error; no compensating `AKSIdentityDelete` call is
visible. Deletion is ordered the same way in reverse intent but not atomically:
it calls `LACAKSIdentityHelper.deleteUser` first and, only on success, calls
`LACUserRegistryProviding.deleteRecord`. A registry-delete failure has no
visible AKS recreation compensation.

Thus even Apple's higher-level user controller does not make AKS identity state
and the LocalAuthentication user registry one atomic commit. Besides the
lower-level applekeystored/APFS partial states, Linux recovery must distinguish
“AKS identity created, LA registry missing” and “AKS identity deleted, stale LA
registry record.” Retrying either create or delete from the outer error alone
is unsafe; reconciliation must inventory both namespaces and resume the missing
registry milestone without repeating the already-committed AKS operation.

This exact evidence revises the future mapping schema: for each imported macOS
user, preserve numeric macOS UID, macOS membership UUID, AKS bag UUID, and the
separately observed Catacomb user UUID. Do not merge the last three merely
because they are all 16-byte values. A read-only inventory can report equality
or mismatch among them, but only matching superclass/server evidence can define
which equality is required.

There is a matching read-only top-level inventory path. `AKSIdentityList` calls
the volume-aware form, which sends `applekeystored` XPC request `23` with an
optional `disk` and reads the reply's `identities` data field. The framework
requires its length to be divisible by 16, converts each 16-byte entry into a
CFUUID, and returns a CFArray. This list is a different namespace from kernel
selector `0x61`'s per-keybag persona UUID list and from BiometricKit's numeric
user/identity list. A complete non-mutating inventory should eventually join,
without conflating:

1. directory-service `(numeric UID, membership UUID)` records;
2. `AKSIdentityList` top-level identity UUIDs;
3. each loaded keybag's AKS bag UUID;
4. each keybag's selector-`0x61` persona UUIDs;
5. BiometricKit numeric user IDs and enrolled identity UUIDs; and
6. Catacomb user UUID and keybag UUID metadata.

Only exact equality observed across those columns should be reported. Missing
rows are valid diagnostic states, not permission to repair or synthesize a
record. The `AKSIdentityDelete` client request (`12`) notably carries only
`user_uuid`; any credential/authorization enforcement must therefore occur at
the `applekeystored` service boundary. The matching server confirms that
boundary and is analyzed next; deletion remains completely unsafe.

#### Captured UUID joins for the current UID 501 user

The preserved macOS files now provide a concrete, read-only join for this
machine rather than merely a relationship inferred from framework code. The
copied user keybag
`Users/<macos-user>/Library/Keychains/<darwin-host-uuid>/user.kb`
is an Apple TLV-style `DATA` object whose outer fields include:

- `UUID` = `<aks-bag-uuid>`; and
- `USID` = `<od-account-uuid>`.

Those byte values are visible directly in the file at offsets `0x28` and
`0x19e`, respectively. They exactly equal the independently decoded Catacomb
`CatacombKeybagUUID` and `CatacombUserUUID`/account UUID for UID 501. This is
positive evidence, on the captured installation, that the Catacomb's bag UUID
identifies this user keybag and that its user UUID is the keybag's `USID`.
It does not prove that either value may be derived from the other or that the
relationship is universal across macOS generations.

The independently copied binary plist `/private/var/db/keybags/persona.kb`
adds the account/persona side of the join. Its `UserPersonaDictionary` has an
entry keyed by `<od-account-uuid>`; the nested record has:

- `UserPersonaUserODUUID` = that same UUID;
- `UserPersonaUserUID` = 501; and
- `UserPersonaUniqueString` =
  `<userpersona-unique-uuid>`.

The matching captured `keybagd.log.0` makes the interpretation explicit:
`PersonaLoginEvent` reports ODUUID `<od-account-uuid-prefix>`, UID 501, ASID <redacted-session-id>, and
then records the same ODUUID-to-ASID mapping. Therefore the value previously
described conservatively as the Catacomb account UUID is, for this host and
user, observed to equal the OpenDirectory UUID carried by the persona system
and the keybag `USID`. The UserPersona manifest's own unique string is different
and must not be substituted for it. User-manager boot traces from the same
UserPersona subsystem show that `UserPersonaUniqueString` is supplied as the
Darwin kernel persona's `Name` when `kpersona` records are allocated. That is a
positive semantic use of the field, but it is a different subsystem from the
AppleKeyStore keybag-persona map. Static evidence does **not** yet prove that
this kernel-persona name is also the UUID passed to AppleKeyStore's separate
`AKSIdentityAddPersona` API or returned by keybag-persona selector `0x61`.

The capture also establishes one cross-subsystem path correlation:
`<darwin-host-uuid>` names both the user's Keychains
directory and the Catacomb machine subdirectory. It appears nowhere in the
visible top-level `UUID`/`USID` fields of this `user.kb`. The exact 24G830
Catacomb constructor now proves that the Catacomb-side value is the uppercase
Darwin `gethostuuid` result. The equality with the user's Keychains directory
remains an observed path correlation; it does not turn this value into an
account, bag, persona, or biometric identity UUID.

The proven captured tuple is consequently:

| Typed field | Captured value | Proven equality |
|---|---|---|
| Apple numeric UID | `501` | persona record and keybagd login event |
| OpenDirectory UUID / keybag `USID` / Catacomb user UUID | `<od-account-uuid>` | byte/string equality across all three artifacts |
| AKS bag UUID / Catacomb keybag UUID | `<aks-bag-uuid>` | byte equality across user keybag and Catacomb |
| UserPersona unique string | `<userpersona-unique-uuid>` | explicitly distinct UserPersona value; equality with an AKS keybag-persona UUID is unresolved |
| Darwin host UUID / Catacomb directory UUID | `<darwin-host-uuid>` | exact 24G830 constructor uses uppercase `gethostuuid`; equality with the captured Keychains directory is observational |
| Current enrolled biometric identity UUID | `<current-biometric-identity-uuid>` | Catacomb identity only; explicitly distinct from every value above |

This materially narrows the mapping schema for imported users: UID, ODUUID,
bag UUID, UserPersona unique string, AKS keybag-persona UUID, host UUID,
and biometric identity UUID remain separate typed columns, while the observed
aliases can be checked as strict cross-source consistency constraints. A
mismatch must quarantine the row; it must not be repaired by copying one UUID
into another namespace. UserPersona-to-AKS-persona equality may be added as a
constraint only after an observed API call or selector-`0x61` result proves it.

The matching server's authorization dispatcher is fail-closed and
request-specific. It rejects a request marked root-only when the XPC client's
effective UID is nonzero. Independently, every request must be authorized by at
least one of:

- broad entitlement `com.apple.private.applekeystored`;
- device entitlement `com.apple.keystore.device`; or
- the entitlement assigned to that request.

For the recovered identity request range, root is required for create-v0
(`10`), create/add-v1 (`11`), delete (`12`), recovery (`13`), change-passcode
(`17`/`18`), recovery create/delete (`19`/`20`), and the root-only tail
(`25`-`28`). Exact symbol recovery names that last group: request
`25` is identity ownership transfer, `26` is identity ownership query, `27` is
identity recovery-list, and `28` is identity persona-add. All four are indeed
root-only according to the server's `0x1e1e3f78` request bitmap, even though
two names sound read-only. The non-root-capable read/control requests still require these
specific entitlements:

| Request | Operation | Specific entitlement |
|---:|---|---|
| `14` | identity load | `com.apple.private.applekeystored.load` |
| `15`, `16` | identity login / login with ACM credential | `com.apple.private.applekeystored.login` |
| `21` | identity verify | `com.apple.private.applekeystored.verify` |
| `22` | identity exists | `com.apple.private.applekeystored.exists` |
| `23` | identity list | `com.apple.private.applekeystored.list` |
| `24` | identity policy status | `com.apple.private.applekeystored.status` |

Requests without a specific entitlement are not public: they still need the
broad private or device entitlement, and the root-only bit where assigned.
Request `28` has no narrow persona-specific entitlement in the recovered
selector-to-entitlement function, so it requires root plus either the broad
`com.apple.private.applekeystored` or device entitlement. Root alone is not
sufficient on macOS. This is a materially stronger policy than ordinary
identity listing and must remain a separate Linux provisioning capability.
Therefore macOS's model supports a narrowly delegated read-only list capability
without granting creation/deletion. A future Linux broker should mirror that
split: inventory authorization must not imply unlock, enrollment, persona
mutation, identity creation, or identity deletion.

The current Linux transport reinforces this boundary operationally. Its
root-only AKS interface deliberately allow-lists only load-keybag (`0x03`),
change-lock-state/unlock (`0x04`), make-system-keybag (`0x0d`), device-state
(`0x19`), and capability discovery. The loader imports one already-exported
`user.kb`, receives its runtime handle, binds it to one configured special bag,
and unlocks both. It has no create-user/create-keybag operation, no collection
of per-user bag records, and no Linux-account-to-Apple-account UUID database.
Supporting several existing macOS users is therefore more than changing the
fprintd UID: it requires a private per-user keybag bundle, special-bag mapping,
runtime handle state, account UUID, and unlock lifecycle for each mapping.

### Per-user Catacomb archive binding

The same-generation archive schema makes those ownership constraints explicit.
Every component file securely archives:

- `CatacombVersion` (32-bit schema version);
- `CatacombUserID` (32-bit Apple biometric UID);
- `CatacombSecureData` (opaque bytes produced by SEP prepare/complete);
- for non-master components, `CatacombIdentityList` (host identity metadata);
- for user components, `CatacombUserUUID` and, when available,
  `CatacombUserKeybagUUID`;
- for accessory-group components, `CatacombGroup`.

Unarchive rejects a schema-version mismatch, a component/user-ID mismatch, any
identity whose embedded user ID differs from its containing component, or an
accessory-group mismatch. For user components it restores the stable account
UUID and compares an archived keybag UUID—when present—with the live UUID from
AppleKeyStore. A mismatch returns error 269. Absence of the older optional
keybag-UUID field is tolerated, but a present conflicting value is not.

#### Exact observed keyed-archive graph and parser boundary

The machine-native version-3 (`CatacombVersion = 0x00030000`) captures narrow
the serialization contract further. All three files are binary plists with
`$archiver = NSKeyedArchiver`, `$version = 100000`, `$objects[0] = "$null"`,
and UID references into a finite object table. The exact 24G830
`BiometricSupport` superclass is now recovered rather than missing. Its save
wrapper creates an `NSKeyedArchiver` with secure coding required, calls
`archiveCatacombDataForComponent:toArchiver:`, finishes encoding, and stages
the resulting `encodedData` through `BKCatacomb`.

The exact common encoder writes `CatacombVersion` with `encodeInt32:forKey:`,
`CatacombUserID`, `CatacombSecureData`, and, for non-master components when
present, `CatacombIdentityList`. The user-component branch additionally writes
`CatacombUserUUID` and optional `CatacombUserKeybagUUID`; the group-component
branch writes `CatacombGroup` as an eight-byte data object. The matching
decoder uses `decodeObjectOfClass:forKey:` for secure data, user UUID, group,
and keybag UUID, and `decodeObjectOfClasses:forKey:` with an explicit class set
for the identity list. It then checks identity user IDs, compares the group
bytes, restores the account UUID for the component UID, and compares a present
archived keybag UUID with the live AppleKeyStore value. This is a typed secure-
coding contract, not permission to generically deserialize arbitrary archived
classes.

The Mesa subclass adds its component-specific fields. For a master component it archives
`CatacombEnrollmentCount` and `CatacombCurrentDate`; on decode it requests the
date specifically with `decodeObjectOfClass:[NSDate class]`. If the decoded
date is absent/nil, it substitutes the current date. Thus date presence is not
an integrity requirement and cannot serve as a generation proof.

The exact observed object graphs are:

- **master:** five objects: null; mutable-data secure blob; its
  `NSMutableData -> NSData -> NSObject` class descriptor; NSDate payload; and
  `NSDate -> NSObject` descriptor;
- **biolockout:** three objects: null; mutable-data secure blob; and the same
  data class descriptor;
- **UID-501 user with one identity:** eighteen objects: null; secure data and
  descriptor; mutable identity array; one `BiometricKitIdentity`; its name and
  NSDate; built-in `BiometricKitAccessory`; built-in
  `BiometricKitAccessoryGroup`; descriptors for those classes plus
  `NSMutableArray`; two NSUUID objects (account and keybag) sharing one NSUUID
  descriptor.

The observed identity record contains `BKIdentityUUID`, `BKIdentityUserID`,
`BKIdentityEntityNumber`, `BKIdentityType`, `BKIdentityName`,
`BKIdentityCreationTime`, `BKIdentityFlags`, `BKIdentityAttribute`,
`BKIdentityMatchCount`, `BKIdentityMatchCountContinuous`,
`BKIdentityUpdateCount`, and `BKIdentityAccessory`. The built-in accessory and
group both use all-zero 16-byte UUIDs and name `Builtin`; accessory flags are 6
and both types are 1. Those values describe this built-in sensor fixture and
must not be silently imposed on future external/accessory components.

A Linux reader must not instantiate arbitrary archived Objective-C/Python
classes. It should parse the binary plist as primitives and UID references,
with all of these fail-closed checks before considering the contents usable:

1. bound total file bytes, object count, nesting depth, string/data lengths,
   array length, and aggregate decoded allocation before traversal;
2. reject out-of-range UID references, cycles where the schema expects a tree,
   duplicate map keys, non-finite dates, wrong primitive widths/types, and
   class descriptors outside the component's explicit allowlist;
3. require exact 16-byte identity/accessory/group/account/keybag UUID payloads,
   unique identity UUIDs and entity numbers, and nonnegative bounded counters;
4. require top-level UID, filename-derived UID, secure-envelope UID, every
   identity's UID, and the operation's pinned Apple UID to agree exactly;
5. require the identity set/count/entity records to reconcile with the
   read-only SEP identity inventory, rather than trusting archive or SEP
   ordering; and
6. validate account UUID, live AKS bag UUID, component/group binding, schema
   version, and SEP Catacomb UUID/hash before enabling use.

Limits must come from a versioned local policy and the sensor's queried
capacity, not from attacker-controlled archive lengths or the SEP prepare-size
reply alone. The matching save wrapper accepts a 32-bit length returned by
prepare and hands the resulting buffer to complete without a visible local
upper-bound check, which is not a pattern the Linux broker should copy.

For an archive with an unknown schema version, top-level key, class, or identity
field, read-only inventory may retain the original bytes and report
`unsupported-version/unknown-field`; it must not normalize and rewrite the
file. Mutation must be disabled. Even for the known schema, re-encoding must
start from a freshly validated semantic model while preserving the SEP secure
blob byte-for-byte. Round-tripping through a generic plist library is not
sufficient by itself because it may discard unknown data or emit disallowed
classes. Binary-plist object ordering and deduplication are not, however,
semantic integrity fields: the exact decoder follows keyed UID references and
validates typed values. A Linux encoder need not reproduce Foundation's byte
ordering. It must build the exact allowed secure-coding graph from a freshly
validated model, preserve the SEP secure blob byte-for-byte, emit only the
recovered class descriptors and keys, and immediately reparse its output
through an independent strict reader. macOS-side fixture acceptance remains
desirable before cross-OS synchronization, but byte equality with one
Foundation archive is not a prerequisite for Linux-local persistence.

Thus a Linux mapping database cannot replace or rewrite these Apple ownership
fields. It can only index a verified archive by Linux UID and assert that the
archive's Apple UID, account UUID, keybag UUID, identity UUIDs, and SEP-reported
component agree. Copying one user's Catacomb under another UID or unlocking it
with another user's bag is structurally invalid and may enter Apple's
destructive error-269 recovery path.

#### Offline Catacomb codec compatibility-test specification

No raw `master.cat`, `user_*.cat`, or `biolockout.cat` fixture is currently
present in the Linux research workspace. The decoded graphs and hashes above
remain evidence, but they are not substitutes for executable fixtures. A codec
must therefore remain a design artifact until exact read-only copies of all
three component types are supplied. Tests must never use the live Catacomb
directory as either input or output.

The minimum fixture corpus is:

1. one exact 24G830 master component;
2. one exact 24G830 biolockout component;
3. a user component containing zero identities, if macOS can naturally produce
   one, plus user components containing one and at least two identities;
4. before/delete/re-enroll generations for the same Apple UID;
5. a legacy user component with omitted `CatacombUserKeybagUUID`, obtained from
   a real Apple writer rather than synthesized; and
6. the manifest captured alongside every file: machine directory UUID,
   filename, byte length, SHA-256, Apple UID, account UUID, live bag UUID,
   identity UUID set, and contemporaneous read-only SEP component UUID/hash.

The reader and writer acceptance contract is semantic, not byte-identical:

- parse only binary-plist primitives, dictionaries, arrays, strings, numbers,
  dates, data, and UID references; never instantiate archived classes;
- require `$archiver = NSKeyedArchiver`, `$version = 100000`, object zero equal
  to `$null`, one valid `$top` root reference, and a fully reachable bounded
  object graph with no forbidden or dangling objects;
- allow only the recovered class-descriptor inheritance chains for the selected
  component type, and reject a class-name match paired with a different chain;
- require exactly the recovered keys and value types for version `0x00030000`.
  Missing optional keybag UUID is a read-only legacy case; unknown keys are
  preserved only as opaque original-file evidence and disable rewriting;
- preserve `CatacombSecureData` exactly, including length and every byte;
- preserve all UUIDs, dates, labels, flags, entity numbers, and counters as
  semantic values. Object-table order, UID numbers, and legal deduplication may
  differ because the Apple decoder does not treat them as integrity fields;
  and
- after encoding, parse the emitted bytes using an independently implemented
  strict reader and compare the complete semantic model. Reusing the writer's
  traversal or validation routines is not independent read-back.

Positive test oracles must prove all of the following for every fixture:

1. Apple fixture -> strict reader -> semantic manifest matches the separately
   recorded manifest;
2. semantic model -> Linux writer -> independent strict reader preserves every
   modeled field and the secure-blob hash;
3. repeated encoding of the same validated model is deterministic for the
   Linux codec, even though it need not match Foundation bytes; and
4. reordering the input object table without changing references produces the
   same semantic model, proving that accidental UID numbering is not trusted.

The negative corpus must mutate one property at a time and require fail-closed
rejection: archive/version/top-root mismatch; out-of-range or cyclic UID;
duplicate dictionary key; forbidden class or inheritance chain; wrong UUID
length; wrong integer width/sign; NaN/infinite date; duplicate identity UUID or
entity number; identity/component/filename UID mismatch; accessory/group
mismatch; conflicting account or live bag UUID; unknown key; truncated trailer,
offset table, object, or secure data; excessive object/depth/string/data/array
limits; and trailing bytes not accounted for by the binary-plist container.
Fuzzing success means a bounded rejection or a model satisfying every invariant,
never merely “the parser did not crash.”

Transaction tests operate only on a temporary directory containing copies.
For each injected failure boundary—partial component write, file sync failure,
prepare-directory sync failure, `prepare -> commit` rename, each old-root
unlink, each component promotion, commit-directory removal, and root sync—the
oracle must enforce Apple's recovered direction: validated `prepare/` is
discarded; validated `commit/` is rolled forward; unexpected names, links,
special files, ownership, component sets, or journal IDs stop recovery without
changing evidence. After any roll-forward, the result is only **host-file
recovered** until a later read-only SEP reconciliation agrees; filesystem
recovery alone must never be labeled biometric transaction success.

Cross-OS synchronization has one additional acceptance gate: a copy of the
Linux-emitted archive must be decoded by the matching macOS secure decoder in a
disposable offline fixture directory. That decoder test may establish archive
compatibility, but it must not call load, confirm, save, delete, or any biometric
command. Until this succeeds, Linux-generated archives are suitable only for
Linux-local experimental storage and must never replace `/Library/Catacomb`
files.

## Startup reconciliation after incomplete persistence

Startup does not replay a journaled cross-domain transaction. `loadCatacomb`
first clears the in-memory TemplateList, reads SEP component state, and then
loads the master and each SEP-advertised user component from their corresponding
host Catacomb files. Each component is unarchived, its secure blob is supplied
back to SEP when required, state is reread, and only then are its host identity
objects added back to the cache.

If an advertised user component cannot be loaded, Apple sends the no-Catacomb
command for that user and rereads SEP state; successful users are followed by
TemplateList synchronization. After all users, it updates identity properties,
validates account/keybag bindings, and deletes unused host Catacomb files.

Error 269 has stronger repair semantics. A corrupt master deletes all Catacomb
files. A corrupt user component deletes that component file, removes the user
from SEP, and resaves the master component. Ordinary read/unarchive/load errors
clear that user's host TemplateList and propagate, but do not exhibit a general
rollback to a previous Catacomb generation.

This confirms that recovery is destructive reconciliation toward the current
SEP component-state view, not restoration of an atomic pre-enrollment snapshot.
A Linux manager needs its own durable operation journal containing the
pre-operation identity inventory and Catacomb hashes/UUIDs, plus post-reboot
read-back logic; it cannot rely on Apple's daemon to report that an enrollment
was only partially persisted.

## fprintd/libfprint integration contract

The current Linux service is intentionally a verification-only D-Bus facade:
it exposes one configured Linux user, one configured Apple numeric user ID, and
one configured finger label. Its enrollment methods return `Internal`, while
all deletion methods return `PermissionDenied`. Multi-user enrollment therefore
requires replacing the configuration model and backend lifecycle, not merely
unhiding existing methods.

The upstream interfaces fit a T2 device only if it is modeled as a
device-stored-template reader:

- `Claim(username)` establishes the Linux account whose operations follow;
  cross-user claims require the fprintd `setusername` PolicyKit permission.
- `EnrollStart(finger)` is asynchronous and reports `EnrollStatus`; progress can
  translate Apple's 100–355 status interval into `enroll-stage-passed`, while
  capture failures translate into the appropriate retry status. Only the
  separate Apple identity result may produce `enroll-completed`.
- libfprint drivers complete enrollment with an `FpPrint`; for on-device
  templates it must be marked `device-stored` and contain an opaque handle.
  For T2 that handle must include at least Apple user ID plus identity UUID;
  username and finger label are host metadata, not SEP template identity.
- The storage-list API enumerates every template stored on the device, whereas
  fprintd list/delete calls are scoped to the claiming Linux username. The
  backend must enumerate SEP identities globally, then filter them through an
  explicit Linux-user -> Apple-user mapping before returning `FpPrint` handles.
- Per-print deletion maps cleanly to Apple command `0x0d` only after resolving
  the claimed user's Apple ID and the selected identity UUID. fprintd's
  per-user delete-all must follow Apple's daemon behavior by journaling and
  individually deleting that user's UUIDs with `0x0d`, then persisting the
  component; it must **not** use command `0x48`. That command removes the entire
  Apple biometric user and belongs only to an explicit administrative teardown.
  libfprint clear-storage is device-wide again and would affect every mapped
  macOS user, so none of these three operations may share an authorization or
  implementation path.
- `EnrollStop`/cancellation must remain nonterminal until the SEP cancel reply
  or cancellation status is observed. Suspend is especially risky: libfprint
  permits a driver to finish, cancel, or resume an interactive action, but the
  known T2 transport loses RemoteXPC across suspend. A safe implementation must
  cancel enrollment before suspend and reconcile state after reconnect rather
  than attempting transparent continuation.

The key impedance mismatch is ownership. fprintd treats the claimed Linux
username as authoritative; T2 treats an Apple numeric user, stable account UUID,
AKS bag UUID, and Catacomb component as authoritative. The mapping database is
therefore security-critical state and must be validated against live Apple/SEP
metadata on every mutating operation. A username string inside `FpPrint` is not
sufficient proof of ownership.

### Current Linux bridge baseline versus multi-user requirements

A read-only audit of the working Linux service confirms that it is intentionally
single-user and must not be extended by merely accepting more usernames:

- `T2_TOUCHID_USER`, `T2_TOUCHID_MACOS_USER_ID`, and
  `T2_TOUCHID_ENROLLED_FINGER` are process-wide singleton environment values.
- D-Bus policy permits only root and that one Linux user to call the service.
  `Claim`, listing, and verification allow both names, but both resolve to the
  same Apple user ID and SEP identity list.
- `ListEnrolledFingers` always returns the configured cosmetic finger name; it
  does not enumerate or distinguish the underlying SEP identity UUIDs.
- Verification sends every identity record returned by command `0x42` for the
  configured Apple user. Selecting a finger name does not select one UUID, so
  the current label means "any enrolled identity for this Apple user".
- Boot provisioning loads one `/var/lib/t2-touchid/user.kb`, and the encrypted
  system credential unlocks one configured normal/special bag pair. There is no
  per-Linux-user bag set or credential isolation.

A real multi-user design therefore requires a root-owned mapping keyed by a
stable Linux account identifier (numeric UID plus account-generation/change
handling), with for each entry: Apple biometric user ID, normal and special AKS
bag handles/files, independently protected unlock material, permitted identity
UUIDs, and host finger labels. Claim authorization must resolve the authenticated
caller/target through that mapping before loading a bag or constructing the
selected-identity blob. Root authenticating *for* a target account must be
distinguished from root owning a separate fingerprint set. A process-wide
environment variable and caller-supplied username are not adequate authority.

## Read-only inventory transaction specification

The matching binary exposes enough non-mutating primitives to discover existing
SEP ownership before any enrollment-management implementation:

1. Query command `0x0f` (no input, exact 4-byte reply) for device maximum
   identity capacity.
2. On protocol v2, query command `0x51` for identity records. Its output is a
   multiple of 40 bytes. Each record is `userID:u32`, identity UUID (16 bytes),
   then the 20-byte accessory-group record (`type:u32 + UUID[16]`). On protocol
   v1 the macOS daemon synthesizes exactly this 40-byte representation from its
   host identity objects rather than issuing `0x51`. The v1 result is therefore
   host-cache evidence, not an independent global SEP enumeration, and cannot
   prove that no unrepresented SEP user exists.
3. Derive the set of **biometrically enrolled** Apple user IDs only from
   structurally valid `0x51` records (or explicitly labeled v1 host synthesis).
   For each discovered ID, query `0x42` with that 4-byte ID and require a reply
   divisible by 20; reconcile its identity UUIDs against the corresponding
   40-byte records. An absent user cannot be probed by guessing integers.
4. Query free capacity with `0x41` for each discovered ID, and require an exact
   4-byte result. Check that counts are internally plausible against `0x0f` and
   the reconciled identities; do not assume whether the maximum is global or
   per accessory when reporting discrepancies.
5. Query Catacomb UUID with `0x38` (`userID:u32` input, exact UUID[16] output).
   Query Catacomb hash with `0x3a` (same input, exact 33-byte output): byte 0 is
   a presence/validity flag and bytes 1..32 are the hash returned to the host.
6. Optionally read global Catacomb state with `0x3c`, requiring a reply divisible
   by 8 (`catacomb_state_v1_t`). Protocol v2 additionally provides group state
   with `0x50`, requiring a reply divisible by 28
   (`catacomb_group_state_v1_t`, consistent with a 20-byte group identity plus
   8-byte state). Treat the fields as opaque until their complete meanings are
   recovered, and never pass these buffers into a save/load command.
7. Compare the discovered Apple IDs and identity UUIDs with the root-owned
   Linux mapping. Report unmapped, stale, duplicate, and cross-user UUID entries
   without automatically repairing any of them.

This biometric command set is not a complete account enumerator. A provisioned
Apple user with zero enrolled identities has no `0x51` row and cannot be
discovered from biometric state alone. The complete diagnostic candidate set is
the typed union of directory-service users, top-level `AKSIdentityList` UUIDs,
known keybag records/aliases, validated Catacomb filenames and ownership fields,
and protected Linux mappings. Numeric Apple UIDs may enter a biometric query
only through a reconciled source that actually binds that number to the subject;
an unjoined top-level UUID is reported as such and never converted to a guessed
UID. Consequently the inventory reports two different completeness claims:
`enrolled-biometric-set-complete` is possible only with protocol-v2 `0x51` on a
stable connection, while `provisioned-account-set-complete` requires all
account/AKS/keybag sources and is never inferred from `0x51`.

The transaction must run under a single bridge connection with no match or
enrollment operation active, use bounded output capacities, reject partial
records, and preserve raw error codes. It has no rollback phase because every
listed command is read-only. This is the evidence-producing precursor to a
multi-user mapping database, not that database itself.

### Race-safe inventory snapshot protocol

Those commands are individually read-only but are not one atomic SEP snapshot.
No recovered request returns a shared generation token, and a match can update
identity counters/Catacomb persistence while enrollment or deletion can change
the identity set between two queries. A one-pass join can therefore fabricate
a mixed-generation mapping even when every reply is structurally valid.

A future broker must construct an inventory with a bounded double-collect:

1. Acquire an exclusive device-wide **inventory lease** that prevents this
   broker from starting verification, enrollment, deletion, Catacomb load/save,
   user switching, keybag rebinding, suspend teardown, or recovery. Reject the
   snapshot if another operation is already active; do not cancel it merely to
   satisfy inventory.
2. Pin the live transport connection generation, bridge boot-session UUID when
   available, negotiated protocol version, selected accessory/group context,
   and current UID/keybag-alias lease state. Any reconnect, bridge reboot,
   suspend transition, protocol renegotiation, or alias change aborts the
   collect.
3. Collect boundary set **A**: maximum capacity (`0x0f`), canonicalized identity
   records (`0x51` or the explicitly reported v1 synthesis), global/group
   Catacomb state (`0x3c`/`0x50`), and for every discovered user the component
   UUID/hash (`0x38`/`0x3a`) and free count (`0x41`). Preserve raw replies and
   parsed values separately.
4. Collect the detail set: per-user identities (`0x42`), validated host archive
   metadata/hashes, account and live AKS bag UUIDs, and root-owned Linux mapping
   candidates. A user discovered only in a detail source is a discrepancy, not
   permission to add it to the boundary set.
5. Repeat the full boundary collect as set **B**, on the same connection and
   lease. Compare canonical semantic records (sorted by user, identity UUID,
   group type, and group UUID) as well as component presence/UUID/hash, counts,
   protocol, connection generation, and boot UUID. Record raw-order differences
   diagnostically but do not treat order alone as identity.
6. Accept the inventory only when A and B agree and every detail row reconciles
   with that stable boundary. Otherwise discard the semantic snapshot, retain a
   redacted diagnostic record, and retry the *whole* collect after bounded
   backoff. After a small configured retry limit, return
   `inventory-unstable`; never spin indefinitely or publish the last partial
   pass.

The local lease excludes cooperating service activity, not arbitrary raw SEP
clients. The production design must make the broker the sole process permitted
to open the transport/control interfaces; filesystem permissions and service
policy are part of the consistency boundary. A==B also cannot theoretically
exclude an ABA mutation by an uncooperative client because Apple exposes no
monotonic generation here. Therefore a snapshot is authoritative only within
the broker's exclusive-access assumption, which must be reported in its
attestation rather than hidden.

Discrepancies remain typed and non-mutating: `appeared-during-scan`,
`disappeared-during-scan`, `cross-user-identity`, `duplicate-identity-uuid`,
`host-only-component`, `sep-only-component`, `catacomb-hash-divergent`,
`account-or-bag-binding-mismatch`, `capacity-inconsistent`,
`transport-generation-changed`, and `unsupported-protocol/schema`. None invokes
load, no-Catacomb, confirm, delete, archive rewrite, or mapping repair. This
stable snapshot plus its connection/lease attestation is the minimum evidence
that an administrator may later approve as a mapping update.

One matching-daemon warning sharpens the word “read-only.” While decoding or
restoring the legacy `CAT1` Catacomb format, Apple invokes its internal
`kReadCatacombSUCommand` (internal command 5) and explicitly logs that it “may
bump catacomb counter.” That internal command number is not the raw endpoint
operation `0x05`, and the warning does not prove that modern inventory commands
mutate. It does prove that a method named *read* can participate in migration
state. The Linux inventory path must therefore exclude legacy decode/restore
and every load/synchronization helper; only the separately recovered modern
query wrappers belong in the allowlist. Unexpected Catacomb hash/count change
during double-collect is treated as instability even if it follows a nominally
read-like call.

### Inventory evidence model and output contract

Every reported value must retain its source and confidence instead of being
collapsed into one convenient user record:

| Source | Authoritative for | Not authoritative for |
|---|---|---|
| protocol-v2 `0x51` plus per-user `0x42` | current enrolled SEP identity UUIDs and their numeric biometric user IDs within the pinned connection | existence of provisioned zero-print users, account UUID, bag UUID, labels, or durable host persistence |
| protocol-v1 host synthesis | the daemon's current host identity model | complete SEP enumeration or absence of unrepresented identities |
| `0x38` / `0x3a` | current SEP Catacomb component UUID/presence/hash response for the queried numeric UID | SHA-256 of a host file, account ownership, or archive freshness by itself |
| validated Catacomb archive | stored secure blob and typed host identity/account/bag metadata | current SEP acceptance, live bag state, or rollback freshness by itself |
| OpenDirectory record | numeric account UID and membership UUID recorded by directory services | AKS identity, loaded bag, biometric enrollment, or Linux mapping authority |
| `AKSIdentityList` | top-level AKS identity UUID membership on the selected volume | numeric UID, bag UUID, persona UUID, or biometric user identity |
| AKS keybag/alias query | live handle/alias state and bag UUID for the exact queried handle | account membership or biometric ownership without an independent join |
| root-owned Linux mapping | administrator-approved Linux-to-Apple association and policy | truth of any Apple/SEP object until independently reconciled |

The serialized snapshot needs a format/version, collection start/end monotonic
times, transport generation, bridge boot UUID when available, protocol version,
lease/exclusivity attestation, redaction level, raw-reply hashes, and the A/B
boundary hashes. Each typed namespace gets its own rows and edges; equality is
an observed edge, never license to merge identifiers. At minimum retain Linux
numeric UID/account generation, Apple numeric UID, OpenDirectory UUID,
top-level AKS identity UUID, bag UUID and handle/alias, AKS persona UUID,
UserPersona unique string, Darwin host UUID, Catacomb component UUID/hash, and
biometric identity UUID.

The public/self-service view may expose labels and identities only for the
caller's already-authorized mapping. Administrative output is redacted by
default: stable per-snapshot pseudonyms may show joins without disclosing raw
account, bag, Catacomb, or identity UUIDs. Raw replies and full identifiers are
root-only diagnostic evidence and must not enter ordinary logs. An unstable or
partially collected scan returns no authoritative semantic snapshot; its
diagnostic envelope may identify the failed source and raw error code but must
not leak password material, ACM external forms, secure blobs, or keybag bytes.

An accepted snapshot can classify a row as `reconciled`, `unmapped`,
`host-only`, `sep-only`, `binding-mismatch`, `legacy-missing-bag-binding`,
`unsupported`, or `unstable`. These are observations, not lifecycle actions.
In particular, `unmapped` never creates a mapping, `host-only` never loads a
Catacomb, `sep-only` never deletes an identity, and a mismatch never invokes
Apple's destructive error-269 cleanup.

## Authorization separation

Apple's daemon accepts an XPC connection only when its process has at least one
BiometricKit entitlement. It records fine-grained capability bits including:

- `com.apple.private.biometrickit.allow-enroll` -> bit 2 (`0x04`);
- `com.apple.private.biometrickit.allow-id-mgmt` -> bit 3 (`0x08`);
- separate default, match, configuration, and internal capabilities.

The legacy `com.apple.private.bmk.allow` grants the broad path but is explicitly
logged as deprecated. Enrollment, update, single deletion, and delete-all also
check the managed preference `allowFingerprintModification`; when the forced
preference is false, mutation is rejected independently of SEP command validity.

The Linux bridge client does not traverse macOS XPC, so a successful raw command
would bypass those host authorization decisions. A safe Linux design must
recreate them as distinct PolicyKit actions (at minimum enroll versus identity
management), require a valid claimed-user mapping, and apply a local mutation
disable policy. Granting fprintd verification permission must never imply either
mutation capability.

### Future Linux authorization matrix

Apple separates `allow-enroll` from `allow-id-mgmt`, gates keybag/persona work
again inside AppleKeyStore, and treats account identity creation as a separate
applekeystored service. fprintd's claim and `setusername` permissions cover only
which Linux username a caller may operate for; they do not confer any of those
Apple authorities. A future broker therefore needs distinct policy actions and
must evaluate both the authenticated caller and the target account.

| Operation | Minimum authorization and state preconditions | Explicitly does not imply |
|---|---|---|
| Verify for self | Active authenticated local session; fprintd verify permission; stable reconciled mapping; already-ready target bag lease | Keybag unlock, enrollment, metadata edit, deletion, global inventory |
| Verify for another user | fprintd cross-user/`setusername` permission plus explicit target mapping and session policy; root is acting *for* target, not using root's prints | Ownership of target identities or permission to alter them |
| Unlock/load target keybag | Separate privileged credential action; root broker; target password through a non-logging secret channel; expected bag/account UUIDs; rate limit and lockout checks | Biometric verification permission, permanent credential storage, alias rebinding for another active user |
| Inventory own mapped identities | Read-only inventory action; stable double-collect; labels may be returned only for the authorized mapped target | Global Apple UID/account/keybag disclosure or mapping changes |
| Inventory all users | Administrative diagnostic action; redacted by default; exclusive inventory lease | Unlock, repair, delete, or enrollment authority |
| Enroll one identity for self | Enrollment action analogous to Apple's `allow-enroll`; authenticated caller must own the protected Linux mapping to the exact Apple UID; fresh UID-bound ACM context, target-user password verification through AKS, policy-1007 success, modification policy, reconciled journal baseline, capacity preflight, and local physical interaction | Rename/delete, enrollment for another mapped user, user provisioning, raw SEP access, or reporting duplicate from generic status 67 |
| Enroll one identity for another user | Separate delegated-enrollment action, disabled by default; administrator authority plus the target user's explicit credential ceremony and immutable mapped Apple tuple. The broker still creates and verifies the context as the target Apple UID; it never substitutes the administrator's UID, password, bag, or ACM context | General impersonation, future unattended enrollment, ownership of the new print, or any account/keybag provisioning |
| Rename/label identity | Identity-management action; exact target UUID; reconciled archive; journaled Catacomb rewrite | SEP template replacement or permission to rename another mapped user's print |
| Delete one identity | Identity-management action; exact target UID+UUID; verified backup and journal; password recovery remains available | Delete-all, whole-user removal, keybag/account deletion |
| Delete all identities for one user | Stronger destructive identity-management confirmation; immutable pre-list; per-UUID milestones; target password/recovery path | Device-wide clear-storage or Apple biometric-user teardown |
| Remove Apple biometric user (`0x48`) | Dedicated administrative teardown action, disabled by default; no active sessions; full Catacomb/SEP/account/keybag inventory; explicit typed target and recovery approval | Account, keybag, persona, APFS unlock-record, or Linux-user deletion |
| Add/change Linux↔Apple mapping | Mapping-administrator action; stable numeric Linux UID identity; complete Apple UID/account UUID/bag UUID/Catacomb tuple; conflict scan; signed/journaled replacement | Creating missing Apple state or trusting a username/UUID-width coincidence |
| Create/delete AKS persona or top-level identity/bag | Separate provisioning-administrator domain; unsupported/disabled until its protocol and recovery are complete | fprintd enrollment or ordinary identity management |
| Backup/export Catacomb or keybag material | Sensitive-recovery action; root; encrypted destination; explicit scope and retention policy | Loading/restoring/promoting the material |
| Promote/reconcile recovery artifact | Dedicated recovery action; exact expected pre/post hashes and generation journal; interactive administrator approval | Automatic repair merely because a file parses or is newer |
| Raw SEP/AKS command | Internal research/diagnostic capability with a compiled operation allowlist; never a general D-Bus method | Any user-facing policy action above |

No positive authorization is transitive except where a row states it. In
particular, passwordless sudo, root caller identity, possession of an encrypted
credential file, successful fingerprint verification, or ownership of the
Linux username is not by itself authorization to mutate Apple biometric or
keybag state. Destructive operations require a fresh explicit policy decision
in their own administrative capability domain and cannot be approved by the
fingerprint currently being deleted or by another user's loaded special alias.
That policy decision is distinct from enrollment's device-consumed credential
set.

The broker must split APIs by capability rather than accepting an arbitrary raw
operation number. Each request binds an authenticated caller UID, target Linux
UID, mapped Apple UID, expected account/bag/component UUID tuple, operation ID,
connection generation, and policy decision before the first SEP message. The
same tuple is rechecked before every irreversible milestone. Mapping and policy
files are root-owned, versioned, atomically replaced, and rejected if writable
by mapped users.

Audit records contain the policy action, caller/target numeric UIDs, operation
ID, redacted or hashed identity/component identifiers, connection generation,
journal milestones, and exact result category. They must never contain
passwords, decrypted credentials/keybags, raw authorization tokens, secure
Catacomb blobs, fingerprint images, or unredacted recovery exports. A denied or
unstable request is audited without attempting a compensating mutation.

### Same-generation exported-object selector map

The missing `BiometricKitXPCExportedObject` implementation was recovered from
the same iPhone 18,3 / OS 26.1 decompilation corpus. This is stronger than an
inference from selector names, but it is still mobile/same-generation evidence,
not proof of the matching macOS x86_64 implementation.

Its permission-group dispatcher maps the connection bitmask as follows. The
exact 24G830 x86_64 implementation now confirms the mapping, but also confirms
that `isClient:entitled:forMethod:` is audit-only after connection acceptance:
it tests the indicated bit and may log a missing entitlement on internal
builds, yet returns true for every valid group. Linux should retain the
separation as enforceable local policy rather than copying that fail-open
behavior.

| Permission group | Required bit | Connection entitlement |
|---|---:|---|
| 1, common/default reads | any nonzero BiometricKit bitmask | any accepted BiometricKit entitlement |
| 2, enrollment | `0x04` | `allow-enroll` |
| 3, identity management | `0x08` | `allow-id-mgmt` |
| 4, matching | `0x10` | `allow-match` |
| 5, configuration writes | `0x20` | `allow-config` |
| 6, internal/debug | `0x40` | `allow-internal` |

The exact exported selectors relevant here are:

- `enroll:user:options:async:client:replyBlock:` and
  `suspendEnrollment:client:replyBlock:` request group 2;
- `updateIdentity:options:async:client:replyBlock:`,
  `removeIdentity:options:async:client:replyBlock:`, and
  `removeAllIdentitiesForUser:options:async:client:replyBlock:` request group 3;
- `identities:client:replyBlock:`, `getIdentityFromUUID:client:replyBlock:`,
  both capacity queries, database UUID/hash reads, and protected-configuration
  reads request group 1;
- protected-configuration writes request group 5.

The same-generation `BKDevice` wrapper makes the credential distinction
explicit. Its standard `updateIdentity:`, `removeIdentity:`, and
`removeAllIdentitiesForUser:` methods all call their XPC counterparts with
`withOptions:0`. The exported object checks identity-management permission
group 3 and forwards those nil options. By contrast, enrollment receives an
options dictionary and has the separately recovered credential-set/auth-token
parser. No LA externalized context, credential set, password, or mode-1 token
is constructed by the ordinary rename or deletion clients.

Thus Apple models these operations as privileged administration, not
per-operation user reauthentication. This does not make them unprotected: the
intended boundary is the BiometricKit connection plus `allow-id-mgmt`, followed
by daemon policy/state checks. Nor does the mobile fail-open fine-grained check
below justify copying that weakness. Linux must replace Apple's code-signing
entitlement boundary with an explicit root/PolicyKit management capability,
interactive confirmation of the immutable Apple UID+identity UUID target, and
the deletion journal. A successful keybag unlock or fingerprint match must not
implicitly grant identity management, and fprintd's ordinary verification
interface must never expose delete-all or whole-user removal.

There is a critical qualification: in this recovered 26.1 mobile implementation,
`isClient:entitled:forMethod:` returns true even after a requested fine-grained
bit is absent. On internal builds it logs and reports the missing permission,
but the final return is still true. Thus the listener's requirement for *some*
BiometricKit entitlement is an actual connection gate, while the selector-level
fine-grained checks in this artifact behave as auditing rather than enforcement.
The matching macOS implementation must be recovered before claiming that macOS
has the same fail-open behavior. Linux should not reproduce that behavior:
enrollment, identity management, and configuration must remain independently
enforced PolicyKit capabilities.

An independent iOS 18.2 BiometricSupport decompilation has the same switch and
the same unconditional final `return 1`: groups 2 through 6 test their expected
bits, group 7 enters the reporting path directly, and every missing-bit path
only reports on internal builds before succeeding. This cross-version agreement
makes a one-off 26.1 decompiler mistake unlikely and supports describing the
mobile fine-grained checks as telemetry/auditing. It still does not establish
the behavior of the unavailable matching macOS framework binary.

After forwarding, the server independently applies operational checks. All four
fingerprint mutations (enroll, update metadata, delete one, delete all) reject
ephemeral-multi-user mode and a forced-false `allowFingerprintModification`
policy, validate users/Catacombs, and then reach distinct SEP/Catacomb paths.
Those checks constrain state validity but do not establish caller authority.

Delete-all has an additional partial-failure window: Apple iterates identities,
deletes each from SEP, and removes each from the in-memory host list, then saves
the Catacomb once after the loop. If a later identity deletion fails, earlier
SEP deletions and in-memory removals have already occurred but the final host
save is skipped. There is no inverse operation. Linux must journal each target
UUID and reconcile after every partial failure rather than report the batch as
an atomic action.

Whole-user removal is a separate and more destructive transaction. In the
same-generation server, `removeUser:` first sends the SEP whole-user deletion
command (`0x48`). Only after SEP reports success does it remove that user from
the in-memory Catacomb, express-mode state, and cached Catacomb-user UUID map,
then delete the per-user Catacomb file. The file-deletion result is not checked
and there is no rollback or final Catacomb resave. This path is invoked
internally by account validation when an OS account disappears or when its live
AKS bag UUID no longer equals the UUID recorded in the Catacomb.

Consequently, Linux must not treat a stale or changed account mapping as license
to issue `0x48`. Read-only reconciliation should quarantine and report the
mapping. Whole-user SEP deletion needs its own explicit administrative action,
a verified backup, a target Apple UID and expected bag/Catacomb UUID assertion,
and post-command inventory. It must never run automatically during login,
account deletion, configuration reload, or doctor/repair processing.

### User deprovisioning is a dependency graph, not one delete operation

The recovered interfaces establish at least eight independently persistent or
runtime objects that may colloquially be called “the user”. They have different
owners, identifiers, authorization domains, and deletion semantics:

| Object | Owner / namespace | Known removal primitive | What that primitive does **not** prove |
|---|---|---|---|
| Linux account and numeric UID | Linux account database | Distribution/account-manager operation | No effect on Apple UID, SEP templates, Catacomb, keybag, persona, or APFS records |
| Linux-to-Apple mapping and encrypted credential reference | Future Linux broker | Journaled mapping retirement | No Apple-side deletion; the referenced state may remain fully usable from macOS |
| Active loaded bag handle and `-UID` special alias | AKS runtime | lock, unload, and session/alias operations | Runtime retirement is not durable keybag destruction and is invalidated by reconnect/reboot |
| Biometric identities for one Apple UID | BiometricKit / SEP | per-UUID delete or delete-all loop | Does not remove the biometric user container, account, Catacomb file, keybag, persona, or APFS record |
| Biometric user container | BiometricKit / SEP | whole-user command `0x48` | Does not remove the Apple account, keybag/personas, top-level AKS identity, APFS record, or Linux account |
| `user_%08x.cat` host component and daemon caches | macOS Catacomb coordinator | host-file/cache removal after `0x48` | File absence alone does not prove SEP absence; deletion failure is unchecked in Apple's path |
| Persona UUID inside an existing keybag | AppleKeyStore keybag store | selector `0x62` | Does not remove the containing bag, top-level identity, account, biometric user, or Catacomb |
| Top-level AKS identity file and APFS compatibility unlock record | `applekeystored` / APFS | XPC request 12, file unlink then `APFSVolumeRemoveUnlockRecord` | Does not issue a demonstrated SEP keybag-destruction command and does not remove biometric state |

The directory membership UUID, top-level AKS identity UUID, AKS bag UUID,
persona UUID, Catacomb user/account UUID, biometric numeric UID, and identity
UUID are therefore typed keys, not interchangeable aliases. A row disappearing
from one inventory is evidence only about that row. In particular:

- deleting a Linux account cannot safely trigger `0x48`;
- deleting or disabling the Linux mapping is a reversible *access retirement*
  and is the correct first response when the Apple tuple becomes stale;
- `0x48` followed by a missing Catacomb file still leaves AKS/APFS state unless
  separately inventoried and explicitly removed;
- successful `AKSIdentityDelete` leaves biometric templates and may leave the
  underlying SEP keybag; and
- persona deletion changes a subordinate map in a loaded bag and requires a
  reload/post-reboot check before durability can be claimed.

There is consequently no evidence-backed “delete user everywhere” primitive.
Any UI offering one button must present it as a multi-stage administrative
workflow with separately authorized scopes and a final report of retained
objects, not collapse the stages into a single success boolean.

#### Safe decommission ordering

The conservative default is **detach first, destroy only by later explicit
choice**. This preserves password login and macOS recovery while removing Linux
biometric access:

1. Acquire the machine-wide broker lease, reject new claims, cancel and observe
   completion of any active biometric operation, and require no open Catacomb
   prepare/complete transaction.
2. Double-collect the complete typed inventory and pin the exact target tuple:
   Linux numeric UID, Apple numeric UID, membership/top-level UUIDs, bag UUID,
   persona UUIDs, Catacomb UUIDs and hashes, and biometric identity UUIDs.
3. Write and durably flush a `MAPPING_RETIRE_INTENT`, disable new use of the
   mapping, then independently read it back. Preserve the Apple tuple as a
   quarantined tombstone; do not immediately erase the evidence required for
   reconciliation or accidentally allow numeric-UID reuse to claim it.
4. Lock and, where explicitly supported, unload only the target runtime bag and
   verify its alias/lock state. This is session cleanup, not destruction. A
   transport loss makes the runtime result unknown and requires post-reconnect
   inventory rather than a blind retry.
5. Stop here for ordinary Linux account removal. Retain all Apple-side state so
   macOS password login, reattachment, and recovery remain possible.

Destructive teardown is a second workflow requiring a fresh administrator
authorization, an exact immutable target set, restorable backups, and explicit
selection of each layer. Its safest known order is leaf-to-root:

1. Delete selected biometric identity UUIDs individually, recording and
   reconciling every result. “Delete all” is merely a convenience loop and must
   retain the same milestones.
2. If the operator explicitly requested destruction of the biometric user
   container, issue `0x48` only after stable absence of every selected identity
   (or after acknowledging any residuals), then reconcile the command result,
   identity emptiness, and per-user Catacomb/cache state independently. These
   signals do not currently prove that the empty biometric user container
   itself is absent; retain `container-removal-unverified` until an explicit
   presence query is recovered. A leftover Catacomb is preserved/quarantined
   pending that proof or removed under a separate host-file action; it is not
   proof that `0x48` failed.
3. Persona deletion, if requested at all, is a separate AKS-keybag transaction.
   Verify the target bag UUID and pre-list, record the UUID-specific intent,
   issue the operation once, then verify both the live list and a reloaded or
   post-reboot list. Never infer which persona to remove from a biometric UUID.
4. Top-level `AKSIdentityDelete`, if requested, is another separate transaction.
   Inventory the identity file and APFS unlock record before and after. Since
   the known order is file unlink followed by APFS removal, a missing file plus
   a present unlock record is a defined partial outcome, not permission to
   recreate or retry the whole delete blindly.
5. Underlying keybag destruction remains unsupported: no recovered top-level
   delete path proves it. Do not delete imported keybag bytes merely because
   the host identity/APFS record is gone. Quarantine them until a proven,
   authorized destroy primitive and recovery procedure exist.
6. Remove the Linux tombstone and encrypted credential only after the requested
   terminal inventory is stable and the retention policy has preserved the
   audit identifiers and hashes. Linux account deletion, if desired, belongs
   to the ordinary account manager and remains outside this biometric commit.

This order intentionally differs from macOS daemon account validation, which
can call `0x48` when its platform account disappears or its bag UUID changes.
That behavior assumes Apple's surrounding account lifecycle and is unsafe to
copy into a dual-boot Linux broker, where a temporarily unavailable APFS volume,
stale imported archive, changed mapping, or numeric-UID reuse can look like
account removal.

#### Decommission crash and restart classification

Each layer uses its own journal namespace and is advanced only by independent
read-back. A restart must classify, never guess:

| Last durable/observed state | Required restart behavior |
|---|---|
| Mapping-retire intent only | Re-read mapping; disable it if still active, preserve tombstone, perform no Apple mutation |
| Mapping retired; runtime cleanup unknown | Keep access disabled; inventory alias/lock state on a new connection generation |
| Per-identity delete intent, UUID still present | Report not deleted/unknown; require fresh authorization before another attempt |
| Per-identity delete return, UUID absent in two stable inventories | Mark that UUID deleted; continue only if the original batch authorization is still valid |
| Some batch UUIDs absent, others present | Report exact partial set; never restart delete-all automatically |
| `0x48` intent/return, biometric container presence unknown | Quarantine tuple and Catacomb; identity emptiness or file absence does not close the journal |
| Biometric container explicitly proven absent, per-user Catacomb present | Classify host orphan; do not reload it into SEP or silently unlink it |
| Biometric container explicitly proven present, per-user Catacomb absent | Classify persistence/recovery failure; disable mutation and preserve backups |
| Persona mutation returned, live/reloaded lists disagree | Quarantine the keybag; no retry or compensating create/delete without a new repair authorization |
| Top-level identity file absent, APFS record present | Defined partial `AKSIdentityDelete`; preserve evidence and authorize APFS cleanup separately |
| Top-level file present, APFS record absent | Divergent top-level identity; do not synthesize an unlock record or claim successful teardown |
| Host identity/APFS records absent, keybag status unknown | Report keybag retention unknown; never label the user cryptographically erased |
| Requested terminal inventory stable | Seal a final manifest of removed, retained, unknown, and recoverable objects; only then complete the workflow |

Neither a service exit code nor a filesystem absence closes a decommission
journal. The final statement must be scoped—for example, “Linux mapping
retired; three SEP identities absent; biometric user absent; Catacomb orphan
retained; AKS identity and keybag retained”—and must never use “user deleted”
without enumerating the namespaces to which that claim applies.

## Per-user keybag and credential lifecycle audit

The current Linux implementation is conclusively single-user. It has one
imported bag (`/var/lib/t2-touchid/user.kb`), one fixed AKS session (`1`), one
configured special-bag alias, one runtime tuple in
`/run/t2-touchid/keybag.env`, one configured Linux username, and one optional
systemd credential. The loader performs `load-keybag`, immediately calls
`set-system-keybag`, and only then publishes the tuple. Both the PAM helper and
boot helper unlock that same normal/special pair. The fprintd facade therefore
cannot select an independently provisioned keybag context for a second caller.

This is not merely a configuration limitation. The captured matching macOS
boot trace repeatedly reports `unexpected session uid: -1` for AppleKeyStore
requests made before a valid login session exists. After OpenDirectory and the
volume unlock complete, `applekeystored` emits exactly one observed binding:
`set handle 1 as special bag -501`, followed by first-unlock and unlocked-state
notifications for `-501`. This proves that session identity participates in
authorization/lifecycle and that the special alias is established at login.
It does **not** prove that several imported bags may share session `1`, that
`-501` is per-session rather than globally rebound, or that changing this
mapping is safe while biometric work is active.

The exact framework now establishes the public identity/session conversion.
`AKSIdentityLoad(uuid, uid, ...)` passes the numeric UID unchanged to
`applekeystored`; when `uuid` is null it first obtains the account UUID with
`mbr_uid_to_uuid(uid)`. `AKSIdentityLogin` likewise logs and transmits its
numeric `session` argument. The session variants of unlock, lock, and unload
then normalize that non-negative session number into an internal AKS handle as
follows:

| API session argument | internal handle |
|---:|---:|
| `0` | `-4` |
| `1` through `9` | `-1` |
| `10` or greater | `-session` |

The conversion is identical in `AKSIdentityUnlockSession`,
`AKSIdentityUnlockSessionWithACMCred`, `AKSIdentityLockSession`, and
`AKSIdentityUnload`. Thus an ordinary macOS account UID 501 addresses internal
handle `-501`; the negative handle is derived from the positive directory UID,
not supplied as a "session UID" by callers. Negative input to these session
wrappers collapses to `-1`, so passing `-501` to them would *not* address the
501 session. This also explains the boot trace's `unexpected session uid: -1`:
it denotes the pre-login fallback/special session rather than proof that a
normal user has UID -1.

The identity wrappers use distinct IOKit selectors after normalization:
unload `0x79`, lock `0x7a`, unlock `0x7b`, and ACM-credential unlock `0x9a`.
The non-session `AKSIdentityLock`/`Unlock` wrappers instead address `-3`.
These are higher-level identity selectors and must not be confused with either
the lower-level keybag user-client selectors (`0x04`, `0x0d`, `0x37`) or raw
SEP endpoint operation numbers. In particular, the project's successful raw
operations on loaded handle `1` and special handle `-501` do not show that its
configured value `1` has macOS session-API semantics; at that layer they are
literal handles.

The 24G830 AppleKeyStore kext closes the remaining ambiguity about these
identity selectors. All four ultimately operate on one effective bag handle,
not on every bag in a login session or on an alias namespace:

| Identity selector | Kernel operation | Recovered boundary |
|---:|---|---|
| `0x79` | `unload_keybag(effective_handle)` | requires device capability `0x08`; rejects an effective handle greater than `-10` |
| `0x7a` | `device_state_transition(effective_handle, 1, ...)` | requires device capability `0x08`; rejects an effective handle greater than `-10` |
| `0x7b` | `unlock_the_device(effective_handle, packed_credential, 5)` | requires device capability `0x08`; requires exactly one verified packed credential item; rejects an effective handle greater than `-10` |
| `0x9a` | `unlock_the_device(effective_handle, ACM_credential, client_flags)` | the concrete negative UID handle is subject to the same effective-handle device gate; accepts the separate ACM credential input form |

The rejection is the AKS-domain error `0xe007c010`, not a silent fallback.
`effective_bag_handle_actual` first applies `ImplicitHandleTranslate`. A literal
nonzero handle normally survives that translation. Only the special implicit
handle `-3` invokes `evaluate_session_keybag_handle`, which obtains the current
audit/login session UID and resolves UID >= 10 to `-UID`, UID 0 to `-4`, and
rejects other unexpected UIDs. The identity wrapper has already converted its
explicit session argument, however, and its 0/1--9/negative cases become
`-4`/`-1`; because both are greater than `-10`, the identity lock, unlock, and
unload cases reject them before changing state. Consequently the only normal
successful explicit identity-session target is a directory UID >= 10 mapped to
exactly one negative bag handle such as `501 -> -501`.

This materially narrows the multi-user lifecycle design. Switching users must
select and authenticate one concrete per-UID identity bag; it cannot use session
0, a low-numbered session, or `-3` as a documented broadcast shortcut. Lock and
unload are per-derived-handle operations. A broker must retain an explicit
UID-to-identity-UUID-to-loaded-handle record and independently manage any
special-bag binding used by the biometric path. It must also preserve the
distinction between password unlock (`0x7b`) and ACM-credential unlock (`0x9a`)
rather than treating the credential encodings as interchangeable.

The special-bag setter is a separate privileged operation. Its user-client
case requires both root (`0x01`) and device (`0x08`) capability bits, accepts a
positive loaded source handle plus a requested session designator, and logs
`set handle %d as special bag %d`. A requested `-3` is first replaced with the
caller's current session UID; a normal positive UID is then negated, so UID 501
becomes special handle `-501`. The setter forwards the concrete handle and the
derived negative special handle through `set_device_keybag` to
`ipc_make_system_keybag`, along with an optional credential. This confirms that
`-501` is an explicitly installed alias for a loaded bag, not merely arithmetic
performed by BiometricKit.

The matching kernel implementation also establishes its scope. Loaded bags are
kept in the single global `__store` list. `ipc_make_system_keybag` finds the
normal positive-handle source, then searches that global list for a system-owned
entry (owner/context field zero) with the same UUID. It accepts reloading the
same UUID over the same special handle, has a compatibility path that replaces
handle zero, but rejects assigning that UUID to a different nonzero special
handle (`Attempt to load bag in %d that is already in %d, fail`, internal error
`-27`). The operation serializes/deserializes the source and installs the result
as a separate global store entry under the negative special handle. Thus the
alias is kernel-global, not scoped to the requesting IPC client, and one bag UUID
cannot simultaneously occupy two nonzero special handles. Rebinding is a
globally visible replacement with collision rules, so concurrent login clients
must not attempt it independently.

Per-handle unload does not search by UUID and does not cascade from a normal
source handle to its special copy. `unload_keybag_internal` removes exactly the
resolved `__store` node, disassociates references and sessions that name that
handle, and frees that store. Therefore unloading normal handle `1` is not proof
that its separate `-501` special entry has been removed, and unloading `-501`
does not imply that handle `1` was removed. Correct logout cleanup must account
for both representations and verify their absence independently.

The matching `applekeystored` ACM login path shows the intended installation
transaction. It first calls `aks_get_system` for the requested UID/session and
refuses to continue if that special identity is already present (`OTI already
loaded for uid %u`). Otherwise it reads the saved identity, loads it as a normal
positive handle, calls `aks_set_system(normal_handle, uid)` to install the
negative UID alias, derives `-UID`, and sends selector `0x9a` to unlock that
special handle with the ACM credential. The temporary positive handle is then
unloaded on every exit. If the `0x9a` unlock fails, the daemon additionally
unloads the derived negative special handle; after successful unlock it leaves
that special handle resident. This explains why the project's two explicit
unlocks addressed both `1` and `-501`: Apple's identity-login transaction uses
the positive handle only as a temporary source and treats the negative alias as
the durable logged-in runtime identity.

The cleanup is still not fully transactional. A reported `aks_set_system`
failure takes the common path that unloads only the temporary positive handle;
it does not also probe/unload the negative alias. Therefore an error at the
alias-install boundary must be treated as outcome-unknown and reconciled with
`aks_get_system` before retry. Conversely, an unlock error attempts explicit
negative-alias cleanup, but that cleanup return value is discarded. A future
broker must journal `normal loaded`, `alias observed`, and `alias unlocked` as
separate states and verify cleanup rather than inferring it from the login
return code.

There is also a genuinely session-wide cleanup primitive, and it is distinct
from identity unload. User-client selector `0x37` requires device capability
`0x08`, resolves its session handle, and calls `unload_session_keybags`. Despite
the name, its recovered selection is *keep the named session*: the global-store
loop considers only system-owned entries, preserves handle zero and the handle
equal to the requested session, and calls `unload_keybag_internal` for every
other such entry. After a successful IPC reply, the kext's host-side tracking
loop applies the same inverse predicate, deleting records whose recorded session
is neither zero nor the requested session. This is a switch-to/retain-current-
session cleanup operation, not “unload this one user.” Selector `0x79` remains
the operation that unloads one derived identity handle. Selector `0x37` could
therefore remove other users' globally installed special bags and must never be
exposed as a generic per-user logout action.

The transport serializes individual AKS exchanges with one kernel mutex, but
that does not provide a higher-level transaction across load, special binding,
unlock, BiometricKit use, and relock. A future multi-user broker would need one
exclusive context lease spanning that entire sequence. The now-recovered
matching-host semantics of operation `0x0d` show that the special-bag binding is
a kernel-global mutable resource with UUID collision rules. It must not be
rebound merely because a new fprintd claim arrives; any future switch requires
quiescing biometric work, inventorying the old alias, journaled installation
and unlock of the new alias, and verified cleanup/recovery.

Ordinary loaded handles are not themselves a singleton. `_ipc_load_keybag`
walks the global store and counts entries owned by the requesting session. It
permits the load while that count is at most 19 and rejects the next one with
internal error `-17`; successful loads allocate another handle/store node.
Consequently one AKS session can hold up to 20 ordinary loaded bags, and bags
belonging to other sessions do not contribute to that per-session limit.

That does **not** imply that several ordinary positive identity handles can be
used unlocked in parallel. The recovered identity unlock/state selectors reject
effective handles greater than `-10`; `applekeystored` therefore uses a positive
load only as a temporary source, installs the UID-derived negative special
handle, unlocks that negative handle, and unloads the positive source. Multiple
different UUIDs can remain represented by distinct negative UID aliases in the
global store, but each such alias is independently addressable global state and
the keep-one-session cleanup may remove aliases outside its retained session.
The supported model is therefore “many ordinary bags may be staged/loaded,” not
“use their positive handles as concurrently unlocked biometric contexts.”

### Biometric operation context versus keybag context

The matching biometric wire protocol pins the *numeric Apple user/component*,
but does not carry an AKS bag handle or keybag UUID that could pin the
cryptographic context independently:

- enrollment command `0x03` includes the operation object's 32-bit `userID` in
  its initial 48/68-byte request;
- each `0x0e` continue request has no payload, so it advances the already-active
  SEP enrollment state rather than selecting a user again;
- the sole terminal enrollment-result envelope repeats the 32-bit user ID with
  the new identity UUID; and
- Catacomb prepare (`0x3d`), complete (`0x3e`), and confirm (`0x3f`) each rebuild
  their request from the same component object. Protocol v1 sends its 4-byte
  component/user identifier; protocol v2 sends the complete 24-byte component
  descriptor. Load (`0x40`) likewise sends the component descriptor separately
  from the secure Catacomb bytes.

Thus an enrollment/commit sequence is not governed merely by whichever Linux
user happens to be current when an event arrives. The SEP state machine and
each persistence phase retain or restate an explicit biometric user/component.
However, none of those biometric messages contains the corresponding AKS bag
handle, account UUID, or keybag UUID. The host validates those UUID bindings
around Catacomb load/save, while the low-level command must obtain any required
key material through SEP/AppleKeyStore state. Static host evidence therefore
does **not** prove that the `-UID` alias target is snapshotted when command
`0x03` begins. Rebinding or unloading the global alias between start, continue,
terminal result, prepare, complete, and confirm could still change availability
or make the explicit component fail cryptographic validation.

The safe concurrency rule is consequently stronger than “serialize each wire
exchange”: hold one exclusive per-machine biometric/keybag lease from before
alias verification through the terminal event and the final Catacomb confirm
(or cancellation plus reconciliation). The explicit user ID prevents accidental
cross-user attribution, but it does not make mid-operation alias switching safe.

The matching daemon's Secure Key Store state-event path strengthens that rule.
Raw envelope `0xe3ff800a` accepts wire version 1, decodes a 32-bit user ID and a
16-bit SKS lock state, and then makes only three notifications:

- `lockStateUpdated:forUser:` on the daemon's analytics recipient;
- `logSKSLockState:forUser:withTimestamp:` on its structured logger; and
- `logSKSLockState:userID:` on `BiometricKitDStatistics`.

There is no call in this envelope branch to cancel, end, continue, or reset an
active match/enrollment operation, and no Catacomb prepare/complete/confirm
call. The recovered `MesaCoreAnalytics lockStateUpdated:forUser:` implementation
forwards to its superclass, maps the state into an analytics property, and
queues an analytics event; it likewise contains no biometric-operation abort.
The statistics implementation only records/logs the state transition. Thus the
matching host treats an SKS lock-state transition as observability/telemetry,
not as an operation barrier. An alias unload or relock cannot be assumed to
cancel in-flight biometric work safely; the future broker must quiesce/cancel
and reconcile the operation itself before changing AKS context.

This still does not reveal whether SEP internally snapshots the relevant keybag
association or resolves AppleKeyStore state again during later Catacomb phases.
What it does establish is that the host daemon supplies no automatic abort that
would make either behavior safe to race.

### Numeric UID selection versus audit sessions

Matching `applekeystored` has two fields that are easy to conflate but have
different trust and lifecycle rules:

- Its 48-byte per-request context begins with `sid` and `suid`. When a request
  class permits the context to be omitted, the daemon allocates it itself,
  obtains `sid` from `xpc_connection_get_asid`, obtains `suid` from
  `xpc_connection_get_euid`, and copies the connection audit token into the
  remaining 32 bytes. Thus an ordinary caller does not invent the audit
  session or effective user identity. The request gate also applies the
  selector-specific root/entitlement policy; identity login selectors map to
  `com.apple.private.applekeystored.login`.
- Identity login requests separately contain a 32-bit unsigned `session`
  field. The decoder returns `-1` if it is absent or does not fit the accepted
  31-bit range. In both the ACM-credential and passcode login paths this value
  is passed as the UID selector: zero maps to legacy UID 4, while any nonzero
  value is passed to `aks_get_system`; after a load it is passed to
  `aks_set_system`, and the usable special handle is derived as `-session` only
  for values at least 10. There is no separate create-session call or daemon
  session object in this path. The value names a UID alias; AppleKeyStore's
  identity-operation validation supplies the final numeric range boundary.

The daemon therefore establishes provenance for the transport context but an
entitled identity-management caller explicitly chooses the target UID in the
login message. A Linux broker must recreate the security property, not merely
the wire shape: derive the target UID from its authenticated account mapping,
never accept an arbitrary PAM/client-supplied UID, require UID >= 10, and bind
that UID to the expected account UUID, bag UUID, and Catacomb tuple before any
mutation. The audit-session ID is useful for ownership and cleanup boundaries;
it is not the biometric user number and must not be negated into an alias.

### Reconciled multi-user alias activation protocol

The matching public AppleKeyStore framework exposes enough read-only state to
avoid guessing after most alias failures:

- `aks_get_system(uid, &handle)` uses selector `0x0e`. A present mapping returns
  its special handle; `0xe00002f0` is the expected not-present result used by
  `applekeystored` before loading an identity.
- `aks_get_bag_uuid(handle, uuid)` uses selector `0x17` and returns the live
  16-byte UUID of that handle. It can therefore distinguish “the requested
  alias exists” from “the alias names the expected bag.”
- `aks_get_lock_state(handle, &state)` uses selector `0x07` and returns the live
  state word. Matching `applekeystored` uses it after resolving the special
  handle and exposes bit 0 as `deviceLocked` and bit 1 as `passcodeLockout`.
  This is independently confirmed by the matching `biometrickitd` SKS-state
  formatter, which assigns the 16-bit event word as follows: bit 0
  `DeviceLocked`, bit 1 `PasscodeLockout`, bit 2 `BioLockout`, bit 3
  `UnlockTokenPresent`, bit 4 `BeforeFirstUnlock`, bit 5 `PasscodeValidated`,
  bit 6 `IdentificationLockout`, bit 7 `CatacombCorrupted`, bit 9
  `ApplePayTokenPresent`, and bit 10 `RemoteUnlocked`. Bit 8 is not named by
  this formatter and other bits must not be inferred. These names are
  build-specific evidence, not assumed cross-version ABI.
- `aks_lock_bag(handle)` uses selector `0x0d`; unload and unlock are separately
  addressable operations. Therefore relock does not require destroying the
  alias, and alias absence can be verified independently afterward if unload is
  deliberately used.

The safest host-side activation is not to reuse `-501` for every Linux user.
Each already-provisioned Apple user retains its Apple UID-derived alias
(`-UID`), so switching from UID 501 to 502 selects `-502` rather than rebinding
`-501`. Rebinding one UID to a different bag UUID is an identity replacement,
not a session switch, and the kernel's UUID/handle collision checks correctly
make it a quarantined recovery case.

A future broker should execute the following journaled state machine under one
machine-wide lease. This is a design result only, not authorization to run it:

1. **Quiesce.** Refuse new fprintd claims, cancel any active match/enrollment,
   wait for its terminal callback, and ensure no Catacomb transaction remains
   between prepare and confirm. An SKS state event is not proof of quiescence.
2. **Inventory.** Validate target UID (at least 10), account UUID, expected bag
   UUID, Catacomb ownership, credential availability, and current source/target
   alias records. For every present alias, resolve both its live handle and live
   bag UUID. Any UID-to-UUID mismatch enters quarantine; do not overwrite it.
3. **Stage target if absent.** Load the saved target bag into a temporary
   positive handle and verify that handle's UUID. Record the handle before
   attempting `aks_set_system(temporary, uid)`.
4. **Reconcile alias installation.** Whether `aks_set_system` reports success or
   failure, call `aks_get_system(uid)` and `aks_get_bag_uuid(returned_handle)`.
   Only the expected `-UID`/UUID tuple counts as installed. “Not present” permits
   cleanup of this transaction's temporary handle; a different UUID is a hard
   quarantine condition. Never retry `set_system` blindly.
5. **Preflight target.** Confirm that the verified special handle, encrypted or
   just-supplied target credential, account mapping, and Catacomb tuple are all
   available before disturbing the old user. This cannot prove the credential
   will unlock the bag, but it eliminates avoidable failures first.
6. **Retire the previous user before target activation by default.** Lock the
   old user's alias and verify
   `DeviceLocked`. Then unlock and verify the target. If target activation
   fails, fail closed: leave the old alias locked and require its user to
   authenticate normally when they return. This sacrifices transparent
   rollback but prevents two users' bags being unlocked concurrently, does not
   require escrow of the departing user's password, and fits a fingerprint
   broker's least-privilege boundary. A target-first sequence with a short,
   journaled dual-unlocked interval may exist only as an explicit recovery or
   availability policy; it must never be the default or happen accidentally.
7. **Unlock and verify target.** Unlock the verified special handle with the
   target credential, then read its lock state. At minimum, a match-ready state
   must have `DeviceLocked`, `PasscodeLockout`, `BioLockout`,
   `BeforeFirstUnlock`, `IdentificationLockout`, and `CatacombCorrupted`
   clear; `UnlockTokenPresent`, `PasscodeValidated`, and `RemoteUnlocked` are
   evidence about how/why access was enabled, not substitutes for those
   negative safety checks. An unlock error with a match-ready read-back is an
   outcome-unknown success requiring an audit flag, not another password
   attempt. An error with a locked read-back is a clean failure. If the
   transaction created the alias, cleanup may unload it and must verify both
   alias absence and temporary-handle removal. A pre-existing alias must not be
   unloaded merely because this unlock attempt failed.
8. **Release.** Unload only temporary positive handles, revalidate the target
   alias UUID/state and Catacomb UUID tuple, then permit biometric claims. Keep
   the lease through the complete biometric operation and any final Catacomb
   confirm. Never call keep-one-session cleanup as part of an ordinary switch.

Power loss or process death is handled by replaying observations, not replaying
mutations: inspect journal state, resolve every involved UID with
`aks_get_system`, verify each present handle using `aks_get_bag_uuid`, read lock
state, and compare the Catacomb/account tuple before choosing cleanup or resume.
The journal must distinguish aliases that predated the transaction from aliases
created by it; otherwise recovery could delete a legitimate working context.

### Password paths and their security properties

There are two materially different unlock modes:

1. The PAM hook receives the password already entered for a successful Linux
   authentication through `pam_exec expose_authtok`. It keeps the secret off
   argv, environment, logs, and persistent storage, and attempts the mapped AKS
   unlock opportunistically. This can scale per user *conceptually* if PAM UID,
   numeric account identity, and a prevalidated Apple mapping are resolved
   before the helper selects a bag. It cannot provide Touch ID for the first
   authentication after cold boot: the user's bag must already be unlocked to
   perform the biometric match, so password-first unlock is an unavoidable
   bootstrap unless another secret-unlock mechanism exists.
2. The boot service decrypts a stored systemd credential and makes biometric
   matching ready without interactive password entry. On the proven machine
   it uses host-key encryption because no usable TPM is available. Root, or an
   attacker who obtains the decrypted Linux filesystem and host key, can
   recover the credential. Replicating this per user would escrow every opted-in
   user's macOS password and multiply the compromise impact. It must therefore
   be optional per mapping, never the default requirement for multi-user
   support, and its readiness/failure state must be reported separately for
   each user.

Using a shared credential is invalid even where users happen to have equal
passwords: password rotation, mapping removal, or compromise must invalidate
only one mapping. Credential names and private files must be keyed by numeric
Linux UID plus an account-generation assertion, not by mutable usernames. A
future design must never infer that Linux and macOS passwords are equal; that
is a provisioning-time claim to verify for the selected Apple bag.

### Required per-user state model

For each already-provisioned Apple user, a protected mapping would minimally
need:

- numeric Linux UID and an account-generation/stable-account assertion;
- Apple biometric UID and stable Apple account UUID;
- imported normal keybag file, expected AKS bag UUID, and special-bag identity;
- boot-specific loaded handle and AKS session, stored only in `/run`;
- verified Catacomb component UUID/hash and permitted identity UUIDs;
- independent readiness states for imported, loaded, bound, unlocked,
  Catacomb-reconciled, and match-ready;
- optional per-user encrypted credential metadata, never plaintext or a shared
  secret; and
- a generation counter so a stale handle, password rotation, account change,
  or reboot invalidates only that user's runtime state.

The persistent database must not store boot handles as authority. Handles and
special bindings are volatile SEP results and must be regenerated and checked
against the expected bag/Catacomb UUIDs after every boot. Likewise, a global
`t2-biometric-ready.service` cannot truthfully represent multiple users: one
user may be match-ready while another has no credential, a locked bag, stale
Catacomb, or failed reconciliation.

### Missing lifecycle primitives

The exposed Linux AKS tool has load (`0x03`), change-lock-state used only for
unlock (`0x04` with state zero), special/system binding (`0x0d`), and read-only
state (`0x19`). It has no statically validated unload command, no safe relock
path, no session-creation/destruction operation, and no query that establishes
the current owner/scope of a special-bag alias. The kernel allow-list correctly
prevents experimenting with unknown AKS operations.

The exact macOS 26.1 RecoveryOS AppleKeyStore framework now proves that the
host API surface contains the missing lifecycle concepts:

- `aks_lock_bag` dispatches AppleKeyStore user-client selector `0x0d` with one
  sign-extended bag handle;
- `aks_unload_bag` dispatches selector `0x04` with one bag handle;
- `aks_unload_session_bags` dispatches selector `0x37` with one session value;
- `aks_load_bag` dispatches selector `0x06` with serialized bag input and a
  returned handle; and
- the framework exports identity-level load/unload/lock/session APIs as well
  as `aks_reset_session`.

These selector numbers belong to the macOS AppleKeyStore IOKit client ABI. They
must not be confused with endpoint-7 SEP operation numbers used by the Linux
transport: for example, macOS user-client selector `0x04` means unload, while
the currently recovered raw SEP operation `0x04` is change-lock-state. The
kernel/daemon translation, input validation, entitlement checks, and exact raw
requests remain unrecovered, so these findings authorize no live call and no
transport allow-list expansion.

The 24G830 x86_64 AppleKeyStore kext (SHA-256
`de5621c1bf6d266ac80cde3024f3d14a8a96be937a0d8beb52bbec767b829c8c`)
closes part of that translation gap. Its generated IPC wrappers send:

- raw endpoint operation `0x05` for unload-one-keybag;
- raw endpoint operation `0x30` for unload-session-keybags; and
- raw endpoint operation `0x0d` for make-system-keybag, agreeing with the
  existing Linux request and captured macOS behavior.

The unload wrappers carry a context/session qword and a signed handle/session
word in the same negotiated AKS IPC envelope family, but their complete
authorization and record-selection semantics must still be typed before use.
Kernel post-processing is substantial: unload persists peer records, locks
keyrings, disassociates authentication tokens, frees session records, removes
the keybag from the global store, may emit state changes, and may lock related
volume bags. It is therefore not a harmless handle-table cleanup and cannot be
used as an ad-hoc user switch.

`ipc_make_system_keybag` proves that the special binding is replacement-like,
not an independent map chosen by fprintd. It requires a positive loaded handle
and a special handle below `-2`, explicitly rejects `-5`, locates the loaded
bag, scans existing keybag records with the same bag UUID, and can unload an
older conflicting record before serializing/cloning the store and calling
`replace_system_keybag_internal`. The internal path checks both source and
special stores and can invalidate a special store whose UUID differs. This
supports treating `-501` as a singleton mutable alias/resource unless later
evidence establishes a narrower session namespace. Rebinding it during another
user's match, enrollment, or Catacomb save is unsafe.

The same exact framework also exports `aks_create_bag`,
`aks_keybag_persona_create`, `aks_keybag_persona_create_with_flags`,
`aks_keybag_persona_list`, and `aks_keybag_persona_delete`. Static disassembly
shows persona create and delete using user-client selectors `0x60` and `0x62`
respectively. This refines the earlier boundary: no create-user operation exists
in the BiometricKit command surface or current Linux transport, but macOS does
have a separate AppleKeyStore persona/keybag management protocol. Recovering
that privileged protocol, its account-service coordination, and its rollback
behavior is the prerequisite for genuinely Linux-native user provisioning.
An exported symbol is evidence of capability, not evidence that an arbitrary
caller may safely use it or that it creates the Apple account identity required
by Catacomb validation.

### Exact AppleKeyStore user-client authorization gates

The 24G830 x86_64 `com.apple.driver.AppleKeyStore` kext also makes the host
authorization boundary explicit. `AppleKeyStoreUserClient::initWithTask`
records whether the client has the IOKit `root` privilege. Its `start` method
then builds a capability bitmap from AMFI boolean entitlements. The recovered
bits relevant to this research are:

| Capability bit | Source privilege or entitlement |
|---|---|
| `0x01` | IOKit client privilege `root` |
| `0x02` | `com.apple.keystore.sik.access` |
| `0x04` | `com.apple.keystore.access-keychain-keys` |
| `0x08` | `com.apple.keystore.device`, or the kext's `secureRoot()` path |
| `0x20` | `com.apple.keystore.lockassertion` |
| `0x40` | `com.apple.keystore.lockassertion.restore_from_backup` |
| `0x80` | `com.apple.keystore.lockassertion.global_assertion` |
| secondary `0x01` | `com.apple.keystore.lockunlock` |
| secondary `0x10` | `com.apple.keystore.lockassertion.time_machine` |
| secondary `0x20` | `com.apple.keystore.stash.access` |
| `0x800` | `com.apple.keystore.se.secret_drop` |

`callingProcHasEntitlement` calls `AMFIEntitlementGetBool`; a missing
entitlement or lookup error evaluates false. Unlike the surprising fail-open
behavior found in the same-generation mobile BiometricKit exported-object
dispatcher, these kext checks feed real permission-error branches. They are an
enforceable security boundary, not just logging or API documentation.

The exact external-method jump-table targets establish these gates:

| User-client selector | Operation | Recovered authorization |
|---:|---|---|
| `0x04` | unload one keybag | Ordinary non-special handles are permitted; handle `0` or a special handle at or below `-10` requires device capability `0x08` |
| `0x0d` | lock one keybag | Same effective-handle rule; special/system handles require device capability `0x08` |
| `0x37` | unload all bags for a session | Unconditionally requires device capability `0x08` |
| `0x60` | create persona in an existing keybag | Requires both root `0x01` and device `0x08`; a special target also follows the device-capability rule |
| `0x61` | list personas in an existing keybag | Requires both root `0x01` and device `0x08`; special/system handles are additionally rejected without device capability |
| `0x62` | delete persona from an existing keybag | Requires both root `0x01` and device `0x08` |

Selector `0x60` resolves an already-existing bag handle, validates a supplied
secret and packed persona data (including a 16-byte persona UUID), and invokes
`keybag_persona_create_with_flags`. Selector `0x62` likewise resolves an
existing bag and requires exactly one packed persona UUID before invoking
`keybag_persona_delete`. Thus an AKS *persona* is a subordinate identity/map
entry within an existing keybag. It is not evidence of an operation that
creates a top-level macOS account, a new independent keybag, or its Catacomb.
The separately exported `aks_create_bag` establishes that bag creation exists,
but the account-to-bag authorization material and Catacomb coordination remain
distinct missing protocols.

The Linux transport talks directly to the raw SEP AKS endpoint and therefore
does not inherit these macOS IOKit user-client checks. Any future Linux design
must recreate at least the same separation locally: PAM/fprintd may request a
bounded match against an already-selected user, while load, bind, lock, unload,
bag creation, and persona mutation remain root-only broker operations with
PolicyKit (or an equivalent explicit policy), audit logging, and no general
raw-operation escape hatch. Persona management must never be exposed through
the ordinary fprintd device interface.

The exact list implementation is suitable for a narrowly brokered read-only
primitive, but not for direct desktop access. It walks the keybag's persona
linked list and returns only a flat concatenation of 16-byte persona UUIDs;
there is no count or account name in the payload, so the byte length must be a
multiple of 16 and `length / 16` is the count. It exposes no password, wrapped
seed, or other persona record fields. The API copies the result into an
`OSData`, zeroes the temporary kernel buffer, and frees it. A Linux inventory
broker should preserve those invariants: reject a non-multiple-of-16 response,
return UUIDs/count only, attach the already-verified bag UUID and numeric Linux
UID in the broker's own response, and never infer a human account name from the
persona UUID itself.

At the user-client boundary, selector `0x61` has no hidden join metadata to
recover. Its request identifies the already-loaded keybag handle; its reply is
only the packed UUID byte vector described above. It does not return the
OpenDirectory UUID, numeric UID, UserPersona ID, UserPersona unique string,
account name, or a mapping table. Therefore disassembling the list reply more
deeply cannot establish the UserPersona-to-AKS relationship. The only static
route that could do so is a concrete caller that obtains a
`UserPersonaUniqueString` (or another typed UserPersona field) and passes that
same 16-byte value as `AKSIdentityAddPersona[WithACM]`'s caller-supplied
`CFUUID`. No such caller exists in the captured local corpus.

There is also a zero-entry edge requiring verification before implementation:
`copy_persona_uuid_list` computes a zero-byte allocation for an empty linked
list and treats a null allocation result as an allocation error. Static code
alone does not establish whether this kernel allocator returns a non-null
sentinel for size zero. Therefore an error from list on a genuinely empty bag
must not yet be interpreted as corruption, and the eventual inventory command
needs an independently known empty-bag fixture or matching-macOS observation.

The exact lower `ipc_keybag_persona_create_v1` implementation further rules
out treating persona creation as an atomic provisioning primitive. It requires
a 16-byte persona UUID and an existing store of the expected type, verifies
the supplied passcode/secret path, rejects an already-present UUID, generates
fresh random key material, derives a persona class-B key, and then calls
`modify_persona_map_entry` to insert the new record. Only *after that insertion*
does it call `wrap_persona_seed_entries`. If seed wrapping fails, the function
logs `Error: persona wrap failed!` and returns the error; no compensating call
to remove the newly inserted map entry is visible on that branch. Successful
create emits a UUID-scoped device-state change. Delete validates the same
16-byte UUID, removes it through `modify_persona_map_entry`, and then emits a
device-state change.

Therefore persona creation has a recoverable-but-potentially-partial failure
window inside AppleKeyStore itself. A future broker would need a pre-operation
persona list, post-error list/read-back, and an explicit repair decision; it
must not retry blindly or report failure as proof that no persona was created.
This mirrors the already-recovered Catacomb transaction problem and reinforces
that top-level user provisioning needs a cross-layer journal spanning account,
bag, persona, biometric identity, and host-file state.

The matching macOS 26.1 high-level identity API adds another transaction layer
that the raw selector analysis alone misses. `AKSIdentityAddPersona` and
`AKSIdentityAddPersonaWithACM` converge on an internal wrapper with these typed
inputs: numeric session/UID, secret or ACM credential, a `secret_is_acm` flag,
and a caller-supplied `CFUUID` persona identifier. With the OTI feature enabled,
the wrapper sends `applekeystored` XPC request `28` containing `session`,
`secret`, `secret_is_acm`, and `persona_uuid`.

The matching `applekeystored` handler normalizes the session to its special
handle (`-UID` for UID >= 10) and executes this material order:

1. call `aks_keybag_persona_create` or
   `aks_keybag_persona_create_with_flags(..., 1)` on that existing identity;
2. only after successful create, call `AKSIdentityCopyUserUUIDBytes` for the
   numeric session;
3. serialize the now-modified identity/keybag through the same internal
   identity-save routine used elsewhere;
4. write a temporary identity file, optionally update the APFS unlock record,
   and rename the temporary file into place.

This proves that Apple's supported OTI add-persona operation tries to bridge
the in-memory keybag mutation to durable top-level identity storage. It is
still non-atomic. If persona create succeeds but copying the user UUID or any
subsequent serialization, temporary-file write, APFS update, or rename fails,
the handler returns an error without a visible call to delete the newly created
persona. Its result must therefore be classified as `PERSONA_ADD_OUTCOME_UNKNOWN`
until the live selector-`0x61` list, identity file, APFS record (when relevant),
and reloaded/post-reboot list agree.

The matching public `AKSIdentityDeletePersona` path is asymmetric: it converts
the supplied `CFUUID` to 16 bytes and directly calls
`aks_keybag_persona_delete` on the normalized special handle. No call to XPC
request 28, the identity-save routine, or another durable identity-file writer
is visible in that wrapper. The lower delete changes the loaded persona map and
emits a device-state event, but static evidence does not establish when or
whether the modified identity is persisted afterward. A successful delete is
therefore only `LIVE_PERSONA_ABSENCE_OBSERVED`; durable absence requires an
identity reload and post-reboot selector-`0x61` inventory.

Finally, the captured `/private/var/db/keybags/persona.kb` belongs to the
UserPersona manifest subsystem and is not the top-level identity file written
by this `applekeystored` routine. Although it contains a
`UserPersonaUniqueString`, no recovered call site yet proves that this string
was supplied as request 28's `persona_uuid`. Linux inventory must keep
`userpersona_unique_string` and `aks_keybag_persona_uuid` as separate optional
columns until an observed request, supported API join, or selector result
establishes equality for the target user.

The strengthened negative boundary is now: the manifest and user-manager logs
prove `UserPersonaUniqueString -> Darwin kernel persona name`; the AKS wrapper
proves `caller-supplied CFUUID -> applekeystored request 28 persona_uuid ->
selector 0x60 keybag-persona UUID`; but no recovered edge connects those two
chains. They must remain separate typed identifiers even when both happen to
have UUID syntax.

The minimum evidence that would close this join is narrowly defined and can be
collected read-only on macOS later: for the same quiescent UID and boot, record
the directory UID/ODUUID, parse the UserPersona manifest, call the supported
top-level identity list/load APIs, obtain the loaded identity's bag UUID, and
list its AKS keybag-persona UUIDs. Record only UUIDs, lengths, return codes,
file hashes, and connection/boot generation—never the keybag bytes, password,
credential, or wrapped seeds. A UserPersona unique string appearing in the
selector-`0x61` list would prove equality for that observed tuple; absence would
prove only non-membership in that snapshot. Neither result alone establishes a
cross-version derivation rule. The current captures lack the selector-`0x61`
result and the corresponding top-level identity file, so static analysis must
leave this relationship unresolved.

`modify_persona_map_entry` itself only edits the loaded keybag's in-memory
linked list: it unlinks and securely zeroes/frees an existing 160-byte record,
then optionally allocates and prepends a replacement record. It does not call a
store serializer or durable-save routine. Persona encoding is instead used by
the broader key-store serialization/deserialization path. Accordingly, a
successful create/delete return proves that the loaded in-memory store changed
and that a device-state notification was issued; it does not, by itself, prove
that durable keybag bytes were committed. Future recovery logic must separately
verify both the live persona list and the reloaded/post-reboot persona list.

Consequently, multi-user switching and logout cleanup are unresolved security
requirements, not implementation details. A safe service cannot promise that
logging out removes another user's unlocked SEP state, cannot assume that
overwriting `/run` unloads a bag, and cannot solve the problem by restarting the
transport: SEP retains registered DMA addresses and the module deliberately
pins itself until reboot. Suspend/reconnect adds another invalidation boundary.

One internal boundary remains unanswered by matching-host static evidence:

1. whether SEP snapshots the keybag/alias association behind the explicitly
   pinned Catacomb user component, or consults current AppleKeyStore state on
   each prepare/complete/confirm command.

The host command builders cannot settle that SEP-internal behavior: they carry
the biometric component on every Catacomb phase but no bag handle or bag UUID.
Until matching SEP firmware analysis or a deliberately isolated fault-injection
experiment proves otherwise, the protocol must be correct under the more
adversarial interpretation—association or availability may be re-evaluated on
every phase. Consequently the UID lease, verified alias, and lock state must
remain unchanged from biometric operation start through the terminal event and
final Catacomb confirmation. This unknown is bounded by the protocol and is not
a reason to weaken that invariant.

Until that SEP-internal behavior is resolved, the defensible implementation
sequence for multiple already-provisioned Apple users is read-only inventory,
then serialized per-user mapping/unlock/match, then separately authorized
enrollment with an operation-wide UID/keybag lease. Concurrent biometric
operations and alias rebinding remain unsafe; unattended unlock requires a
separate secret decision per user. Linux-native creation of new AppleKeyStore
users remains disabled because its OD/AKS/APFS/registry transaction is
non-atomic and lacks proven complete compensation.

### Matching `applekeystored` create/delete transaction boundaries

Static analysis of the matching macOS 26.1 x86_64 `applekeystored` (UUID
`080CDAC0-BCE7-3998-A68C-FA6D2BB92049`, SHA-256
`e9f3ae005c581cb0f8083f91f0e0c0e8155c9c31fcc322ff2d5701cc4fdd1211`)
shows that top-level AKS identity creation is not an atomic transaction.

In `service_identity_create_internal`, the material order is:

1. validate the UUID, disk, existing-identity state, and access-token state;
2. construct the AKS create request and issue selector `0x76` through
   `IOConnectCallMethod`;
3. require the returned bag handle to differ from `-1`;
4. construct the returned keybag/credential data objects;
5. either save the new identity file immediately or first bind the new KEK to
   the APFS VEK, depending on the selected creation path;
6. after a successful APFS bind, save the identity file; and
7. for the first-user path, perform an additional access-token operation before
   unloading the newly created bag handle.

The error branches establish several partial-commit windows:

- A failure from `identity_save_to_disk` is logged as
  `WARNING: Failed to save identity (%d)`, copied into the service return code,
  and followed by bag unload/cleanup. There is no call that deletes the AKS
  identity created by selector `0x76`.
- A failure from `APFSVolumeBindNewKEKToVEKWithOptions` is returned after the
  AKS identity already exists. No identity-delete compensation is visible.
- If the APFS bind succeeds but the following disk save fails, both the AKS
  identity and APFS binding can remain without a usable identity file.
- Failures in the later first-user/access-token step are likewise returned
  after the earlier AKS and persistence work; no general rollback path is
  visible.

Thus the word `WARNING` does not mean the operation succeeds: the save error is
returned to the caller. It does mean cleanup is non-transactional. A future
Linux provisioner must treat any create error after the selector call as
"outcome unknown/possibly committed", inventory every layer, and reconcile it;
retrying create blindly is unsafe.

The matching server also resolves the apparent distinction between framework
`Create`, `Add`, and `Reset`. Requests carrying `existing_user_uuid` enter the
wrapper at `0x100014176`. If that UUID is non-null, the wrapper loads the
existing user's saved identity into an AKS bag handle, passes that handle plus
the existing credential and `replace` flag into the same
`service_identity_create_internal` routine at `0x100002f5b`, and unloads the
existing handle afterward. With no existing UUID it passes handle `-1` into
that same routine. Consequently Add/Reset are not separate transactional
backends: they are authorized/parented variants of the same selector-`0x76`
creation path and inherit all of its partial-commit windows. They also require
the existing host identity file to be loadable before the mutation starts;
knowing an account UUID alone is insufficient.

Request 12's matching delete entry tail-calls `identity_delete_from_disk`; this
path does not issue an AKS/SEP identity-delete selector. Its order is:

1. validate the user UUID and resolve the identity directory;
2. test independently for the identity file and APFS unlock record;
3. reject the request if neither exists;
4. if the identity file exists, unlink it first; and
5. if the APFS unlock record exists, call `APFSVolumeRemoveUnlockRecord`.

Deletion is also non-atomic. An identity-file unlink failure prevents the APFS
removal attempt. Conversely, APFS removal can fail after the identity file was
successfully deleted, leaving an orphaned unlock record. The function reports
that APFS error (`Could not delete compat KEK blob`) but has no file restore.
Most importantly, successful top-level `AKSIdentityDelete` means removal of the
host identity file/APFS compatibility record, not demonstrated destruction of
the underlying SEP keybag or of BiometricKit templates. Those must be separate,
explicitly inventoried operations in any future management design.

### Version-qualified macOS enrollment credential producer

The Intel/T2 build identity inside the preserved software-update payload is
macOS 15.7.9 build `24G830` (although the enclosing multi-platform asset was
locally named for 26.1). It contains the settings extension
`System/Library/ExtensionKit/Extensions/Touch ID & Password.appex/Contents/MacOS/Touch ID & Password`
(source version `317.0.0.0.0`, x86_64 UUID
`D7A8BF70-9DB3-32D1-BDC7-A975B65C6221`). Static analysis of its x86_64 slice
closes an important host-side gap without exercising the sensor.

The extension is signed with all five relevant BiometricKit capabilities:
`allow-connect`, `allow-match`, `allow-enroll`, `allow-id-mgmt`, and
`allow-config`. It separately carries
`com.apple.private.LocalAuthentication.ExtractCredential`. The latter is real
and operationally distinct from the BiometricKit enrollment permission; an
unentitled future Linux UI cannot reproduce this macOS flow merely by reaching
the raw enrollment command.

The active settings flow is:

1. `PasswordManager getAuthContextWithCompletionHandler:` creates an
   `LAContext`, installs its UI delegate, and invokes
   `evaluatePolicy:options:reply:` with numeric policy `0x3ef` (the binary's
   diagnostic names this `LAPolicyTouchIDEnrollment`) and nil options.
2. In the password-entry delegate path, the extension asks that context for
   `credentialOfType:-5`. On success it feeds the returned data back to the
   same context with `setCredential:type:` using type `-1`. Errors are reported
   as `Could not obtain credentials` and do not proceed as successful
   authorization.
3. After successful policy evaluation, the extension obtains
   `LAContext.externalizedContext` and returns that data to the enrollment
   caller.
4. `presentEnrollmentSheetInWindow:withData:completionHandler:` obtains a
   `BiometricKitUI` enrollment view controller and sets two properties on it:
   the supplied data under the literal key `credset`, and an
   `NSNumber(getuid())` under the literal key `userid`. The enrollment UI is
   therefore explicitly bound to both an externalized LocalAuthentication
   context and the calling numeric user.

This is stronger than the earlier string-only inference: the producer and the
consumer of the `credset` value are now joined in one matching executable. It
also refines terminology. The value handed to BiometricKitUI is an
**externalized LA/ACM context**, not demonstrated to be the 16-byte authorization
token and not demonstrated to be the final 40-byte wire wrapper observed at the
daemon boundary. BiometricKitUI and/or BiometricKit still performs a private
translation between these layers.

The matching LocalAuthenticationCore constants resolve those two signed
credential numbers. `-5` is `LACCredentialExtractablePasscode`, whereas `-1`
is the ordinary `LACCredentialPasscode`. The current Settings sequence is
therefore a protected extraction followed by installation of a normal passcode
credential into the same LA context. It is not evidence that the client sends
raw password bytes in the policy request or directly creates ACM credential
type `2`. This also explains why the extension's
`com.apple.private.LocalAuthentication.ExtractCredential` entitlement is a
material part of the enrollment ceremony rather than incidental signing
metadata.

Nor is the extracted `-5` value demonstrated to be reusable plaintext.
`LACContextCredentialCoder.checkCredentialRequiresEncoding:` explicitly marks
`LACCredentialExtractablePasscode` (`-5`),
`LACCredentialExtractablePassword` (`-9`), and
`LACCredentialSecurePassphrase` (`-8`) as credentials requiring encoding. Its
encoder/decoder calls the framework data coder with three binding inputs: the
credential data, a credential-encoding seed, and the externalized ACM context.
This makes the `-5` to `-1` handoff context-bound encoded credential handling,
not evidence for a stable password blob that Linux can extract once and replay.

The matching bridgeOS ACM module now identifies where the second binding input
comes from. `ContextPluginACM.credentialEncodingSeedWithReply:` asks its
`LACACMHelper` for ACM context-data type `13`, unwraps the returned
`LACSecureData`, and returns those bytes. The plugin contains no corresponding
setter for type `13`. By contrast, `credentialsUUIDWithOriginator:reply:` reads
context-data type `10`, and `setCredentialsUUID:originator:reply:` converts an
authorized `NSUUID` to exactly 16 bytes and explicitly writes context-data type
`10`. The encoding seed and credentials UUID are therefore distinct ACM data
items with different mutability contracts; neither may be inferred from the
other.

The type-13 fetch crosses the ordinary AppleCredentialManager storage path.
`LACACMHelper dataWithType:error:` reaches `ACMContextGetData`, which constructs
the storage-get request and sends command `0x29` through the ACM transport. The
plugin does not synthesize, cache, rotate, or replace the seed in host code.
This proves that a valid encoder must obtain the seed from the same live or
legitimately reconstructed ACM context. It does not yet prove the seed's byte
length, generation point, rotation rule, or persistence across external-form
reconstruction; those remain backend properties.

The ACMLib reconstruction contract narrows that last point without resolving
it completely. `ACMContextCreateWithExternalForm` rejects any external form
whose length is not exactly `16` bytes, asks the backend to reconstruct it with
current command `0x25` (falling back to legacy command `0x12`), and receives a
`20`-byte local `ACMHandleWithPayload`. The first `16` bytes are the context
handle and the remaining four bytes are local response/tracking payload; no
seed bytes are carried in either direction. A later type-13 read is therefore
an independent command-`0x29` lookup through the reconstructed handle. This
rules out both "the seed is embedded in the external form" and "the client
library regenerates the seed while reconstructing." It is still static
evidence only: whether the backend stores type 13 for the context, derives it
deterministically, or creates it lazily on the first read remains unresolved.

The available 24G830 AppleCredentialManager kext cannot answer that
bridgeOS backend question by analogy. Its `CoreStorage` implementation does
show the general ACM design: typed slots carry caller permissions, maximum
sizes, sensitivity flags, and overwrite policy, and a write-once slot rejects
replacement with differing bytes. However, that host generation's slot table
contains only data types `0` through `9`; the type-13 seed request was recovered
from the bridgeOS `ModuleACM` and is serviced by bridgeOS's own ACM backend.
Consequently no host slot flag, size, or lifecycle rule may be assigned to
bridgeOS type 13 from this kext.

The same-generation `LocalAuthentication` client framework closes the complete
decode ordering. `LAContext.credentialOfType:reply:` first asks its daemon
client for the requested credential type. If nonempty data returns and
`LACContextCredentialCoder.checkCredentialRequiresEncoding:` is true, it then
asks that *same* client/context for `credentialEncodingSeedWithReply:`. Only
after both values succeed does it call
`[credentialCoder decode:credential seed:seed error:]`; the coder is lazily
constructed from that `LAContext`'s own `externalizedContext`. The public reply
receives the decoded secure-data payload, while a seed-fetch or decode error
returns no credential. This is a three-way context join—encoded credential,
backend seed, and externalized context—not a server reply that directly
contains reusable passcode bytes.

The bundled ACMLib implementation makes that binding cryptographically
concrete. For the mode `2` used by `LACContextCredentialCoder`,
`ACMEncryptDataEx` derives a 32-byte key with HKDF-SHA-256. The encoding seed is
the input key material, the externalized ACM context is the salt, and the ASCII
label `acm_transport` is the HKDF info. It then encrypts with AES-GCM. The wire
envelope is exactly one version byte (`2`), a freshly generated 16-byte IV, the
ciphertext, and a 16-byte authentication tag, so encoded length is plaintext
length plus `33`. Decryption requires that minimum overhead, checks the version
byte, derives the same key, authenticates the tag with a constant-time compare,
and returns no plaintext on failure. The temporary 32-byte derived key is
explicitly zeroed after either operation.

This is host-side authenticated encryption, but it does not weaken the backend
dependency: the host can derive the key only after ACM supplies the type-13
seed for the relevant context. Copying an encrypted credential into a context
with a different external form or seed changes the derived key and fails GCM
authentication. Conversely, knowing this format does not reveal or predict the
backend seed.

The bridgeOS module also places a useful limit on the available evidence about
credential type `-5`. Its generic `credentialOfType:originator:reply:` path
accepts only `LACCredentialExtractablePassword` (`-9`), checks the dedicated
extractable-password read authorizer, and decodes ACM context-data type `7`
using the type-`-9` context coder. Its generic setter has special cases for
types `0`, `-3`, `-8`, `-9`, `-11`, and `-12`, but not `-5` or ordinary
passcode `-1`. This does not contradict the matching macOS Settings call:
ordinary passcode injection also travels through processed-event handling, and
the host macOS module need not expose the same bridgeOS generic-read cases.
It does mean the `-9` authorizer cannot safely be promoted to proof of the exact
server-side `-5` entitlement gate.

The bridgeOS client framework confirms that limitation independently:
`LAContext._checkCredentialRequiresExtractionEntitlements:` compares only
against type `-9`, while its generic decode stage covers every type named by
`checkCredentialRequiresEncoding:`. Thus encoding support for `-5` is shared
client machinery, but the observed bridgeOS entitlement precheck and server
read implementation are specifically `-9` machinery.

The exact matching macOS `ModuleACM` has now been recovered from the same
`24G830` update payload, and it resolves that host-side question. Its
`ContextPluginACM.credentialOfType:originator:reply:` supports exactly `-9` and
`-5`. For `-5` it requires the originator entitlement
`com.apple.private.LocalAuthentication.ExtractCredential`; after authorization
it returns the plugin instance's `_extractablePasscode` ivar directly, or
returns the explicit `No extractable credential set` error when that ivar is
empty. This path does not read ACM context-data type `13` and does not fetch a
persistent credential from the T2 backend.

The corresponding `setCredential:type:options:originator:reply:` case for `-5`
requires the distinct entitlement
`com.apple.private.LocalAuthentication.SaveExtractableCredential`. A nonnil
input is secure-unarchived with an allow-list containing `NSDictionary`,
`NSString`, `NSData`, and `NSNumber`. The archive is a dictionary with literal
keys `Credential` and optional `UserId`: the `Credential` value becomes the
same `_extractablePasscode` ivar returned by the getter, while `UserId`, when
present, is merged into the context's result information beneath its `Result`
metadata. Supplying nil clears `_extractablePasscode`. The ivar has no observed
backend write or durable-store operation in this case.

Consequently type `-5` is a privileged, context-local handoff between a
SaveExtractableCredential-authorized producer and the
ExtractCredential-authorized Settings consumer. The later client-side decoder
still binds the returned encoded value to the ACM seed and external form, but
the plugin slot holding that encoded value is transient host state. This also
separates two previously adjacent facts: bridgeOS context-data type `13` is an
encoding-key input, whereas macOS credential type `-5` is the encoded payload
slot. Their shared number is not a shared storage type.

Static tracing of the matching `MechPasscode` bundle further shows that normal
passcode entry obtains `UserId` from mechanism options and calls
`LAPasscodeHelper verifyPasswordUsingAKS:acmContext:userId:policy:options:bioLockoutRecovery:`.
Its generic credential setter routes ordinary passcode and recovery credential
types rather than directly constructing type `-5`.

The initial type-`-5` producer is instead the matching
`LocalAuthenticationRemoteService` XPC executable inside
`LocalAuthenticationUI.framework`. It is signed with
`com.apple.private.LocalAuthentication.SaveExtractableCredential` (as well as
the private CoreAuthentication SPI and AppleKeyStore verification
entitlements), links both LocalAuthentication and LocalAuthenticationCore, and
implements the explicit method
`_makePasswordExtractableFromContext:password:userID:reply:`. That method:

1. takes the submitted secure password object's `data` value;
2. builds an `NSDictionary` whose two ordered entries are the supplied
   `UserId` and password data under the literal keys `UserId` and `Credential`;
3. invokes
   `NSKeyedArchiver archivedDataWithRootObject:requiringSecureCoding:error:`
   with secure coding required;
4. calls `LAContext setCredential:type:reply:` on the context reconstructed
   from the supplied externalized context, using credential type `-5`.

The surrounding `_verifyPassword:externalizedContext:userID:` flow constructs
that `LAContext` with `initWithExternalizedContext:`, attaches it to analytics,
and verifies the submitted password through `LAPasscodeHelper` using either the
AKS or PAM branch before reporting the passcode event. A separate completion
block writes nil with type `-5`, proving explicit cleanup of the transient
extractable slot. Thus the complete host handoff is now joined: privileged UI
verifies a password, packages password data plus numeric user ID into a secure
archive, temporarily installs it in the externalized context, Settings extracts
and decodes it under its distinct read entitlement, converts it to ordinary
credential type `-1`, and hands the resulting externalized context to
BiometricKitUI.

The same class contains a legacy-looking
`+[PSBiometricIdentity getCredentialsData:ctp:]` helper. It creates an ACM
context, verifies a supplied password through the embedded AppleKeyStore
`aks_verify_password` path using handle `-3`, then returns
`ACMContextGetExternalForm` as `NSData`. No selector-reference call to this
helper was found inside this executable, whereas the LA policy path above has
concrete call sites. It is therefore evidence for the older direct-password
construction of an ACM external form, but not evidence that current Settings
uses that helper for enrollment.

That legacy helper nevertheless exposes the lower AKS bridge contract. Its
worker bounds the password with `strnlen(..., 0x80)`, then calls
`_aks_verify_password(-3, password, length, acmContextBytes,
acmContextLength, 0)`. The superficially ambiguous `ctp` name is not a UID:
the asynchronous ACM-create callback supplies a context pointer and its byte
length as the fourth and fifth C arguments. The apparent serializer value `2`
is a blob count, not a credential or request type. The resulting buffer is
`uint32 count = 2`, followed for each item by a `uint32` byte length, the bytes,
and zero padding to a four-byte boundary. Its two items are the password and
ACM-context blobs, in that order. The AKS client then invokes the AppleKeyStore
user client with
selector `0x2a`/`42`. The four scalar inputs are the signed keybag handle, a
one-byte mode flag widened to a word, the serialized-request pointer, and its
length; there are no scalar or structure outputs. The caller treats a zero
return as authorization, exports the now-authorized ACM context, and deletes
the context on failure. This is strong structural precedent for the current
`verifyPasswordUsingAKS` bridge, but it carries no explicit user field. The
current helper's separate `userId:` argument is therefore a newer extension;
its serializer and binding semantics require a same-version join before reuse.

The newer macOS dyld-cache AppleKeyStore implementation
(`CoreAuthentication-2005.40.35` generation) now makes that extension more
precise. Its hidden common worker backs four exported variants:
`aks_verify_password`, `aks_verify_password_memento`,
`aks_verify_password_with_acm`, and
`aks_verify_password_memento_with_acm`. All four still pack exactly two blobs
with `aks_pack_data`: the password followed by the ACM context. All invoke
AppleKeyStore user-client selector `42` and request no scalar or structure
output. The current selector call has five scalar inputs: signed keybag handle,
memento flag, packed-buffer pointer, packed-buffer length, and a final
`with_acm` Boolean. The ordinary wrapper supplies zero for that last flag;
`aks_verify_password_with_acm` supplies one (and zero for memento), while the
memento variants independently set the memento flag.

Accordingly, `with_acm` does **not** add a UID-bearing record to the packed
request. It changes selector-42 behavior through a fifth scalar while retaining
the password-plus-context body. ModuleACM's explicit `userId:` cannot therefore
be copied into this buffer or substituted for the legacy callback's context
length. It must participate outside the packed body: most plausibly in
resolving/selecting the signed AKS keybag/persona handle passed as scalar zero,
or in preparing/validating the already audited ACM context. This is
cross-version structural corroboration rather than a same-build join to the
1656 ModuleACM; the outstanding proof is the `LAPasscodeHelper` call chain from
numeric UID to keybag handle and the exact `_with_acm` invocation.

The same 2005-generation **macOS x86_64** `LocalAuthenticationCore` closes the
first half of that call chain. `LACPasscodeHelper` owns both an `LACKeyBagProvider` and an
`LACAKSIdentityHelper`, and its private `_keybagHandleForUserId:` implements an
explicit numeric mapping. Nil user ID, or a user ID equal to
`_currentUserID`, returns special handle `-3`. A nonzero different UID returns
the negated UID. UID zero falls through to special handle `-4`. Its
`_verifyPasscodeUsingMKB:acmContext:userId:options:` caller obtains that handle,
negates it for the `DeviceHandle` value placed in the MobileKeyBag options
dictionary, and calls `MKBVerifyPasswordWithContext` with the submitted
password and ACM context. This proves that, in the current architecture, the
separate numeric user argument selects the keybag handle outside the serialized
password/context body; it is not embedded as a third blob.

This resolver is platform-specific, not a portable 2005-generation rule. A
public decompilation of the iOS 26.1 implementation of the same private method
instead returns `-3` when `LACMobileGestalt.isSharedIPad` is true and `0`
otherwise. That does not contradict the macOS disassembly; it shows that Apple
compiles different keybag-selection policy into the helper on iOS/iPadOS and
macOS. Consequently the macOS `nil/current -> -3`, `other nonzero -> -UID`, and
`zero -> -4` mapping must remain explicitly platform- and version-qualified.
It strengthens, rather than relaxes, the requirement to recover the exact
target-macOS helper and route before reproducing the enrollment ceremony on
Linux; an iOS rule must never be imported as a fallback.

A macOS 15.3.2-to-15.4 dyld symbol/import diff independently confirms the
provenance of the newer helper rather than merely matching its class name. In
15.3.2, `LAPasscodeHelper` lived in `SharedUtils` together with
`_keybagHandleForUserId:`, `_verifyPasswordUsingMKB:acmContext:userId:options:log:`,
`MKBVerifyPasswordWithContext`, the `DeviceHandle` option string, the
`LACKeyBagProvider` ivar, and its OD/PAM verifier fallbacks. In 15.4 those
members disappear from `SharedUtils` and appear in `LocalAuthenticationCore`,
with the password/passcode spelling modernized (`_verifyPasscodeUsingMKB` and
`verifyPasscodeUsingAKS`). This is strong evidence that the decoded 2005
implementation is the direct successor of the older macOS helper family and
that per-user keybag selection was already part of that family. A symbol diff
does not expose the old instructions, however, so it cannot by itself prove
that the exact numeric handle mapping was unchanged across the migration.

An independently acquired macOS 14.4 (`23E214`) x86_64 shared cache now adds
an older exact instruction-level checkpoint. Its `SharedUtils` image has
Mach-O UUID `CCD37414-2E3F-3EA1-B21D-3948D7ED326F` and source version
`1394.100.151.0.1`; the extracted image's SHA-256 is
`fee082313f9c1fa9b4069b2d1c0c423fc07823da584b43aec8eb6b541168bbed`.
Its `_keybagHandleForUserId:` implements the same macOS mapping as the newer
2005 code: initialize the result to `-3`; retain that value for nil or current
user; otherwise negate `unsignedIntValue`, selecting that negative value when
the UID is nonzero and `-4` when it is zero. Thus the mapping is instruction-
verified on both sides of the `SharedUtils` to `LocalAuthenticationCore`
migration. This still does not turn the iOS resolver into compatible code, and
an uninspected intermediate build could in principle differ, but it removes
the earlier dependence on migration-symbol continuity alone.

The same 14.4 `_verifyPasswordUsingMKB` worker resolves that handle, negates it
for the `DeviceHandle` option, and calls `MKBVerifyPasswordWithContext` with
the passcode data and ACM context. Its outer five-argument
`verifyPasswordUsingAKS:acmContext:userId:policy:options:` method requires a
nonempty context, performs failed-attempt/backoff accounting, and routes
verification between MKB and its OD/PAM alternatives according to platform,
policy, keybag-lock, and option state. Therefore the public method name is not
evidence that every request directly invokes the AppleKeyStore selector: the
normal MKB route is a policy-bearing wrapper, and some states deliberately use
other account verifiers. A Linux implementation must reproduce the accepted
enrollment route for the actual target state, not merely call selector 42 with
the right two blobs.

The 14.4 branch selectors make that routing concrete. Policy `1014` takes the
private `_verifyPasswordUsingOD:acmContext:userId:options:log:` route directly.
Every other policy—including enrollment policy `1007`—normally calls
`_verifyPasswordUsingMKB`. For a nonnil target user, however, the helper first
queries `MKBGetDeviceLockState` for that user's `DeviceHandle`; when the bag is
not unlocked and numeric option `1043` is false or absent, it logs
that it will verify the user with PAM and invokes
`verifyPasswordUsingPAM:userID:pamService:pamUser:pamToken:` instead. Thus an
already unlocked target keybag is not merely setup convenience: it selects the
MKB/ACM-bearing path that can authorize the supplied context. A successful PAM
password check in the locked-bag fallback must not be assumed to mint
equivalent `TouchIdEnrollment` authority without an explicit downstream proof.
When option `1043` is true, a locked bag remains on the MKB route and the MKB
worker calls `MKBUnlockDevice` after password verification. The literal option
value and both branches are instruction-decoded, not inferred from the log
text.

This also explains the legacy helper's hard-coded `-3`: it authorizes against
the current user's special AKS keybag, whereas a multi-user-capable helper must
first map the requested UID. It does not yet prove that the `24G830` runtime
join between source-version 1656 `ModuleACM` and its actual helper uses
byte-for-byte the same `-UID`/`-4` rule, nor that the newer MKB wrapper and the
direct `aks_verify_password_with_acm` call have identical option semantics.
Framework source-version numbers need not match across that runtime boundary,
so the required proof is the helper shipped in the same OS build, not a
hypothetical "1656 helper." Those remain version-sensitive joins. It does,
however, rule out treating UID as an absent wire field and establishes a
concrete Linux-native requirement: user management needs a validated
UID-to-AKS-identity/keybag mapping and must never silently collapse every user
to handle `-3`.

The matching `24G830` helper has now been recovered directly from that build's
Intel System Cryptex dyld cache, closing the version-sensitive join above. The
cache identifies itself as macOS 15.7 and contains source-version
`1656.140.4.700.1` copies of `SharedUtils` and `LocalAuthenticationCore`.
`SharedUtils`'s
`-[LAPasscodeHelper verifyPasswordUsingAKS:acmContext:userId:policy:options:
bioLockoutRecovery:]` is only a compatibility forwarding shim: it obtains
`+[LACPasscodeHelper sharedInstance]` and passes all six arguments unchanged to
the same-named `verifyPasscodeUsingAKS` implementation in
`LocalAuthenticationCore`.

That exact implementation executes a deterministic verifier cascade. Its
inner block first calls `_shouldUseODVerifierForUserId:policy:options:` and, if
true, `_verifyPasscodeUsingOD:acmContext:userId:options:`. Otherwise it calls
`_shouldUsePAMVerifierForUserId:policy:options:` and, if true,
`verifyPasscodeUsingPAM:userID:pamService:pamUser:pamToken:`. Only when both
predicates are false does it call
`_verifyPasscodeUsingMKB:acmContext:userId:options:`. Thus the previously
recovered branch ordering is now same-build instruction evidence, rather than
an inference from neighboring releases.

The exact `_keybagHandleForUserId:` also preserves the macOS mapping byte for
byte in substance: initialize the result to `-3`; retain `-3` for nil or a user
ID equal to `_currentUserID`; otherwise read `intValue`, return its negation
when nonzero, and return `-4` for zero. Consequently Apple UID 501 selects AKS
handle `-501`, while the current-user special route remains `-3`. The matching
MKB worker negates that signed handle for the `DeviceHandle` value, constructs
the MobileKeyBag options dictionary, and calls
`MKBVerifyPasswordWithContext(password, context, options)`. When the
`LACPolicyOptionMatchForUnlock` option is true after successful verification,
it additionally obtains the password bytes and calls `MKBUnlockDevice` for the
same options/keybag. This is the exact 24G830 explanation for why the tested
`unlock-keybag 1 -501` and current-user routes can both succeed without making
their handles interchangeable.

The same-build proof changes the remaining boundary: UID-to-handle selection,
OD/PAM/MKB ordering, the MKB password/context call, and optional post-verify
unlock are no longer open questions. Later exact ACMLib/kext analysis joins the
authorized context to policy 1007 and the host enrollment transaction. Neither
the UID nor a third user record is inserted into the password/context blob;
UID is bound at ACM context creation and keybag selection.

A later audit of the privately transferred macOS cache prevents a tempting
provenance error. Files
`~/.local/share/t2-touchid/macos-system/dyld_shared_cache_x86_64{,.01}`
form cache UUID `E0F2B6DB-51BF-359C-90DC-331DE06552E8`; their dyld header says
macOS **26.1**, not 15.7.9/24G830. They are valid evidence for the newer
2005-generation helper analysis above, but cannot be relabeled as the missing
matching helper. Conversely, `ipsw ota info` identifies the preserved
15,630,394,567-byte OTA as version 15.7.9 build 24G830, while that archive
contains its x86_64 System Cryptex only as the 1,353,927,934-byte
`payloadv2/image_patches/cryptex-system-x86_64` raw-image patch. Applying it
requires Apple's private `RawImagePatch` implementation from
`libParallelCompression.dylib`; the available Linux tooling deliberately
rejects the operation. Exact closure therefore requires either a full
materialized 24G830 Intel shared cache or running the patch/extraction step on
macOS. The newer cache and the older 23E214 checkpoint bracket behavior but do
not replace that proof.

Further format recovery narrows that boundary substantially. The x86_64
payload begins with `RIDIFF10`, declares exactly one input variant, and embeds
a PBZX stream. Its first decompressed member begins with a 32-byte digest, an
apparent `0x80800000`-byte output size, and 2,698 ordered offset/length extents;
the extent table ends exactly at `0x40 + 2698 * 16`, after which a second
control/operation encoding begins. The macOS 26.1 cache contains the actual
`libParallelCompression.dylib`; disassembly of its matching
`RawImagePatchInternal` identifies a one-variant RIDIFF as
`*full replacement*`, opens no required input variant, creates/preallocates the
output to the encoded raw-image size, decompresses the metadata/control and
per-variant streams, applies controls through segmented/forked output streams,
and verifies the resulting 32-byte digest. Therefore the 24G830 artifact does
**not** require a compatible base Cryptex image. It is self-contained, but it
does require the proprietary RIDIFF control interpreter (or a faithful
reimplementation); ordinary PBZX/XZ decompression alone is insufficient.
Running `RawImagePatch` on macOS remains the shortest evidence-preserving
materialization route, while the recovered format and engine disassembly make
a future Linux reader technically possible.

Upstream `ipsw/pkg/ota/ridiff/raw.go` independently supplies the packed
structure definitions and fixes every header field for this artifact. In
little-endian order it has `Variants=1`, `Flags=1`, `ControlCount=1`,
`ExcessSpace=0x0348f5c2` (55,113,154 bytes), `MetaDataOffset=0x3e`,
`ControlsOffset=0x5fd06`, `PatchDataOffset[0]=0x5fd32`, and
`PatchSize=0x50b34cfe` (1,353,927,934 bytes). The metadata decoder names its
fields as a 32-byte digest, `TotalBytes`, `UnknownCount`, `ExtentCount`, and
`ForkCount`; this payload yields `TotalBytes=0x80800000`, `UnknownCount=24`,
`ExtentCount=2698`, and `ForkCount=2694`. Its sole decompressed 16-byte control
is `(Offset=0, Size=0x139cc4eab)`. That large size is consistent with the
expanded per-fork patch stream rather than the sparse output length.

Crucially, upstream stops at the same boundary as this analysis: its `Fork`
definition labels the extent index tentatively and leaves fork-chunk parsing as
a `FIXME`; it does not apply controls or reconstruct an image. Thus no dormant
portable decoder was overlooked in the Linux build. The remaining work is the
fork/chunk/control interpreter already visible in Apple's disassembly, not
header parsing, decompression, or variant selection.

Apple's `rawimg_save_to_stream` and `rawimg_create_with_stream` close that
fork-layout `FIXME`. After the 64-byte raw-image header and packed 16-byte
extent array, each fork begins with an unpadded 41-byte record:

```
uint64 size;
uint64 compressed_size;
uint64 flags;
uint64 first_extent_index;
uint64 extent_count;
uint8  algorithm;
```

This naming is instruction-backed rather than guessed from the unfinished Go
structure. `rawimg_show` prints the first two fields as `size` and
`compressed`; verification uses the fourth and fifth fields to walk the extent
array, and displays flag bits zero and one as `V` and `C`. When flags bit zero
is set, the serialized record is followed by `ceil(size / 65536)` packed
12-byte chunk records. Verification establishes each chunk as a little-endian
`{ uint64 compressed_offset; uint32 compressed_size; }`, requires monotonically
ordered offsets, and bounds `compressed_offset + compressed_size` by the
fork's `compressed_size`. Flags bit two instead/additionally requires a
264-byte fork header and a 50-byte footer. The writer and reader perform the
same exact byte counts, so compiler padding is not part of the wire format.

The preserved 24G830 metadata PBZX expands from 392,392 to 1,118,678 bytes and
parses exactly to end-of-stream with this grammar. All 2,694 forks have
`flags=1` and `algorithm=14`; together they contain 80,416 chunk records, and
none carries the optional header/footer pair. Fork zero is
`(size=19,726,336, compressed_size=7,487,678, first_extent_index=0,
extent_count=2)` and therefore has 301 chunk records. Fork one is
`(size=14,965, compressed_size=6,997, first_extent_index=2,
extent_count=1)` and has one. Every observed chunk passes Apple's order and
bounds invariants. This resolves metadata framing and the previously unknown
fork/chunk grammar for the exact artifact; it does not yet implement the
algorithm-14 fork expansion or the higher-level control application.

The algorithm mapping is now exact as well. `rawimg_verify` accepts the sparse
raw-image algorithm values through a constant table; value `14` maps to
Compression.framework ID `0x702`, Apple's LZBITMAP codec. The library's own
private wrappers are named `PCompressLZBITMAPEncode` and
`PCompressLZBITMAPDecode`, and delegate to `compression_encode_buffer` and
`compression_decode_buffer` with `0x702`. This algorithm describes how
`aaForkOutputStream` materializes the output filesystem forks. It is **not** an
extra compression layer around the RIDIFF patch-data PBZX stream. A compatible
open-source LZBITMAP codec is already present in the preserved NeoAppleArchive
sources, so this particular codec is no longer a proprietary-only boundary;
its correct integration with Apple's fork-output framing remains to be proved.

The sole control and patch-data relationship is also byte-exact. Scanning the
patch-data PBZX framing without materializing it finds 5,021 PBZX chunks whose
declared expanded sizes sum to `0x139cc4eab` (5,264,658,091 bytes), exactly the
`Size` in the only 16-byte control `(Offset=0, Size=0x139cc4eab)`. The first
expanded patch bytes are the literal ASCII dyld-cache header
`dyld_v1  x86_64h`, agreeing with full-replacement data rather than a
LZBITMAP-compressed fork. In `patch_apply`, each control consists of one signed
input/variant displacement followed by one signed patch-data length per patch
stream; it reads the selected source only for the former and reads the
decompressed patch stream for the latter, adding source bytes only in the
binary-difference path before writing through `aaForkOutputStream`. For this
one-variant full replacement, the zero first field selects no input bytes and
the second field consumes the entire expanded patch stream. Thus the control
language needed by this exact artifact collapses to one zero-input/full-patch
operation. The remaining Linux materialization boundary is the segmented raw
image plus fork-output writer (including LZBITMAP framing and sparse extent
placement), not PBZX decoding, base-image selection, or a complex sequence of
diff controls.

The apparent difference between the expanded patch length and the sum of fork
sizes is intentional stream structure, not unexplained trailing data. The
2,694 fork `size` fields sum to 5,119,409,835 bytes; subtracting that from the
5,264,658,091-byte patch stream leaves 145,248,256 bytes. In
`aaForkOutputStreamOpen`, Apple constructs a logical segment table from the
fork payloads and the raw/unforked segments previously synthesized by
`aaSegmentStreamOpen`; it records the final logical boundary in the raw-image
object and `patch_apply` writes against that unified address space. The two
classes sum exactly to the sole control length for this artifact.

The writer's transformation is now structurally bounded. Fork payloads are
accepted in at most 64-KiB logical units. For a compressed fork it invokes
`compression_encode_buffer` with the algorithm selected from the fork's
algorithm byte (`14 -> 0x702`), records each encoded chunk's offset and size,
pads when required by the predeclared chunk/extent capacity, and writes via
the segmented stream's positional interface. The segment stream maps logical
segments onto the packed raw-image extents; raw/unforked segments bypass fork
compression but share the same unified logical stream. This explains both why
the expanded patch begins with an ordinary dyld header and why the resulting
raw image is much smaller than the patch stream. Exact Linux materialization
still requires reproducing the writer's edge cases and final digest, but its
data classes, codec, unit size, extent destination, and complete input length
are no longer unknown.

The current `ipsw` source fixes the exact invocation rather than leaving it to
operator interpretation: its dyld extractor calls
`ridiff.RawImagePatch("", patchPath, outputDMGPath, 0)`. The empty first path is
the no-input/full-replacement case. On macOS the reproducible high-level command
for this preserved asset is therefore:

```
ipsw ota extract 9d95c64142a9a426f56d3265d4f8a6fa31585333.zip \
  --dyld --dyld-arch x86_64 --json --output <empty-output-directory>
```

The JSON report, generated cache UUID, `ipsw dyld info` OS/build metadata, and
hashes of every cache-family file are the acceptance evidence. Extraction must
not be accepted merely because a DMG or one main cache file appears: the
RIDIFF engine's final digest check must succeed and all declared subcaches must
be present before disassembling the 24G830 helper.

Selector 42's lack of every output channel also constrains the authorization
state transition. ModuleACM invokes password verification and only afterwards
externalizes its ACM context; the AKS call does not return a replacement
credential set, context buffer, token, or scalar result beyond its status code.
Therefore successful verification must authorize or mutate backend state
associated with the supplied ACM context/reference (or make that context's
subsequent external form resolve to authorized state). It cannot be reproduced
by a host-side password/context concatenation or by parsing a returned blob.
This is consistent with bridgeOS coreauthd's live external-context registry and
ACM reconstruction path: the short external form is a reference into a real
credential-manager lifecycle, not a self-contained proof minted by selector
42 and returned to its caller.

The newer iOS request-object implementation gives a useful, but deliberately
platform-qualified, audit-boundary cross-check. Its convenience entry point
constructs an `LACMutablePasscodeVerificationRequest` with the passcode, ACM
context, and the caller's raw audit token. The later low-level MKB worker still
receives only passcode data, externalized ACM context, the resolved
`DeviceHandle`, and options; it calls `MKBVerifyPasswordWithContext` without an
additional audit-token blob. This is consistent with subject identity being
captured by the surrounding LocalAuthentication request/context lifecycle
rather than appended to selector 42's two-blob password body. It does not show
where bridgeOS finally validates that identity, and the iOS keybag resolver is
known to differ from macOS, so it is corroboration rather than a wire-level
macOS proof.

The matching bridgeOS `coreauthd` artifact closes another part of this
boundary. The inspected executable is from bridgeOS build `23P1072`
(`CoreAuthentication-2005.40.35`, SHA-256
`6c4a63d87462bab20a79721102cdb3b543749b8568374c9475ef40c275d0e80a`). Its
Objective-C method metadata and arm64 code show that externalization is backed
by live daemon state:

- `Context.externalizedContextWithReply:` first requires its plugin to expose
  a `cachedExternalizedContext`, then delegates to the plugin's
  `externalizedContextWithReply:`; otherwise it returns the explicit
  `No externalized context` error path;
- `Context.contextWasExternalized:` calls
  `[[ContextManager sharedInstance]
  registerExternalizedContext:token forContext:self]`;
- `ContextManager.registerExternalizedContext:forContext:` stores the context
  under the externalized value with `setObject:forKey:` in its private map;
  and
- `ContextManager.findContextForExternalizedContext:` is a direct
  `objectForKey:` lookup in that map.

The daemon's `_connectToExistingContext:...` path consumes the value in two
stages. It first asks the singleton `ContextManager` for the live mapped
context and returns that object immediately on a hit. On a miss it calls
`managedContextWithExternalizedContext:processId:userId:auditSessionId:flags:
checkEntitlementBlock:reply:`. The recovery path therefore carries the
requesting PID, numeric UID, audit session, flags, and an entitlement-check
closure alongside the externalized bytes. Cross-process restoration is an
audited LocalAuthentication operation, not a context-free deserialization
primitive.

The extracted matching `LocalAuthenticationCore` framework refines this
interpretation. `LACACMHelper.externalizedContext` calls
`ACMContextGetExternalForm`, while
`LACACMHelper.initWithExternalizedContext:` passes the bytes to
`ACMContextCreateWithExternalForm` and records the reconstructed context's
tracking number. The value is therefore an ACM external form, not merely an
opaque dictionary key; the live map is a fast-path/lifecycle binding and a map
miss can reconstruct an ACM context. However, current reconstruction still
runs inside the authenticated LocalAuthentication/AppleCredentialManager
stack and the daemon recovery call explicitly supplies PID, UID, audit session,
flags, and an entitlement check. Later exact kext recovery narrows this boundary:
those task/audit/entitlement facts are host checks and are not serialized to SEP;
only the effective numeric UID is appended to context-create commands. A Linux
port therefore needs a trusted subject-authenticating broker, not a forged Mach
audit identity.

Credential access is bound to an originator before it reaches that plugin
layer. Matching `coreauthd`'s `ContextProxy` constructs each request originator
with `Request.requestFromCurrentConnection`, then forwards
`setCredential:type:options:originator:reply:` or
`credentialOfType:originator:reply:` to the managed context/plugin. The proxy
itself was initialized with PID, numeric UID, audit-session ID, and the full
audit token. Thus an unprivileged endpoint-10 byte stream cannot safely
substitute for the daemon call. A privileged Linux broker can provide the
equivalent host boundary if it authenticates the subject, binds the intended
Apple numeric UID, and owns the complete context lifecycle.

The same extracted framework also locates the policy decision itself. The
exported constant `LACPolicyTouchIDEnrollment` has value `0x3ef`/`1007`.
The newer CoreAuthentication `2005.40.35` macOS dyld-cache implementation of
`+[LACACMHelper acmPolicyForPolicy:]` removes the remaining ambiguity in that
number. Its private-policy jump table covers LA policies `1003` through `1027`;
entry `1007` returns the literal ACM policy name `TouchIdEnrollment`, while the
adjacent entry `1008` returns `UserIdentificationWithBiometrics`. This is an
exact table decode and cross-version corroboration, not a name inferred only
from caller diagnostics. The standalone enrollment components recovered from
the update payload are CoreAuthentication `1656.140.4.700.1`, so this table is
not claimed as a same-build binary join until the corresponding 1656 cache is
recovered. The stable numeric policy, the 1656 ModuleACM branch selecting
`0x3ef`, and its own `LAPolicyTouchIDEnrollment` diagnostic still independently
identify the enrollment policy. The newer table also
explains a previously odd asymmetry in ModuleACM's parameter builder:
`_acmParamForPolicy:options:userId:secondPass:` adds an explicit ACM user-ID
parameter for policy `1008` (only on its second pass), but does not do so for
policy `1007`. Enrollment's target user therefore is not conveyed to ACM by
that visible managed-user parameter. Any subject binding for
`TouchIdEnrollment` must instead reside in the credential/context, the audited
LocalAuthentication request lifecycle, or backend policy state; simply adding
an arbitrary UID parameter would not reproduce Apple's transaction.

`LACACMHelper.verifyPolicy:preflight:parameters:maxGlobalCredentialAge:
processRequirement:` routes through its context-verification worker, and the
underlying `LibCall_ACMContextVerifyPolicyAndCopyRequirementEx` serializes a
VerifyPolicy request, invokes ACM context command `3`, then deserializes the
backend's returned requirement. The host framework therefore does not embed a
simple static rule such as “knowledge of the account password authorizes
enrollment.” AppleCredentialManager/ACM supplies the actual policy result and
requirement for the current context and device state. A Linux-compatible path
would need the legitimate ACM transport and context lifecycle, not merely a
locally reimplemented policy-number table.

The matching ACMLib serializer makes the policy boundary more exact without
revealing the backend rule. A context-policy command-3 request is:

1. the 16-byte ACM context handle;
2. the NUL-terminated policy name, bounded to at most 128 bytes;
3. one preflight byte;
4. a four-byte maximum-global-credential-age value; and
5. the serialized ACM parameter array.

There is no fixed UID, PID, audit token, timestamp, nonce, or credential blob
field outside that parameter array. The command allocates at most `0x1000`
bytes for its response. A valid response begins with a four-byte Boolean policy
result and may then carry a recursively serialized ACM requirement. The client
accepts simple requirement types `1`, `2`, `3`, `6`, `8`-`15`, and `18`-`28`,
plus composite types `4`, `5`, and `7`; composites contain subrequirements and
type `7` additionally carries a k-of-n count. Host-side conversion exposes
only requirement `type`, `state`, `flags`, subrequirements, and (for type `7`)
`kofn`. This proves that success and any unmet/supplemental requirement are
backend outputs rather than a host-constructed Touch ID rule. The serializer
alone does not show which tree `TouchIdEnrollment` returns in each device
state.

The allocation jump table does assign the security-relevant subset of those
numeric types. Type `1` is `PasscodeValidated`, `2` is
`PassphraseEntered`, `3` is `BiometryMatched`, `4` is `Or`, `5` is `And`,
`7` is `KofN`, `8` is `AccessGroups`, `11` is `PushButton`, `13` is
`UserOutputDisplayed`, `20` is `SecureIntent`, `21` is
`BiometryMatchAttempted`, `24` is `AP`, `25` is `KeyRef`, and `26` is
`Ratchet`. Attribute-bearing types `1000` through `1004` are respectively
`KofNWithAttributes`, `BiometryMatchedWithAttributes`,
`PushButtonWithAttributes`, `SecureStateWithAttributes`, and
`PasscodeValidatedWithAttributes`. Types whose allocator uses only the common
16-byte header remain deliberately unnamed here. This mapping means a later
read-only policy observation can distinguish a password-validation requirement
from a biometric, physical-button, secure-intent, ratchet, or compound rule
without guessing from success/failure alone. That mapping by itself does
**not** prove which one policy 1007 will return, and
`maxGlobalCredentialAge` remains a separate request input rather than a visible
fixed timestamp field in the outer requirement header.

The 24G830 Intel AppleCredentialManager credential engine resolves that
last policy-specific uncertainty. Its policy-name dispatcher compares the
literal `TouchIdEnrollment` and takes a dedicated branch. That branch:

1. builds `VerifyPolicyPasscodeOptional`'s requirement;
2. evaluates it against credential type `1` in the current ACM context;
3. requires `findCredentialSet` to resolve the current non-null 16-byte handle
   to an existing backend credential-set object; and
4. on success, ORs bit `0x0002` into that credential set's flags.

`VerifyPolicyPasscodeOptional` constructs an exact one-of-two (`KofN`, `k=1`)
tree containing two type-`1` `PasscodeValidated` requirements. The second is
distinguished by requirement flag bit `1`; the function's retained assertion
names identify the two alternatives as `passcode` and `noPasscode`. When a
valid type-1 credential is found, credential property bit `1` selects which
branch is marked satisfied. Thus `TouchIdEnrollment` does not mean “password
bytes were supplied.” It means the backend has validated the appropriate
passcode-or-no-passcode state in this context, the live credential set still
exists, and policy evaluation has marked that credential set with enrollment
authorization bit `0x0002`. This also explains why the enrollment client's
credential-set option is a 16-byte opaque handle: BiometricKit transports a
reference to the backend object whose flag was changed, not the password or a
host-authored bearer token.

The same engine exposes this authorization bit through context property `1`:
`queryContextProperty` resolves the credential set, reads its flags word at
offset `0x58`, shifts right once, masks with `1`, and returns that Boolean.
The neighboring lifecycle code identifies flag bit `0x0001` separately as the
“externalized/live handle” marker: externalization sets bit 0 and handle lookup
requires it. Across the matching host engine, the only static write of bit 1
is the successful `TouchIdEnrollment` policy branch; no instruction clears
bit 1 in place. Credential-set creation initializes the whole flags word, and
credential-set deletion destroys the object. Consequently this build's host
side treats enrollment authorization as a property of the live credential-set
lifetime, not as a host-side one-shot token consumed by querying it. A secure
biometry/SEP consumer could still enforce additional one-shot or transaction
state beyond this kext, so Linux must not infer replayability merely from the
absence of a host-side clear.

The policy function increments credential-use state only on the non-preflight
path. Therefore preflight may reveal the same requirement tree without
consuming/committing the validating credential, while the retry after the
passcode mechanism is the state-changing evaluation. A Linux implementation
must preserve that distinction and must not treat a successful preflight,
knowledge of an empty-password account, or possession of an arbitrary 16-byte
handle as enrollment authority. The remaining limitation is architectural:
the copied engine establishes the policy algorithm and object mutation, while
the T2 path still requires the legitimate endpoint-10/SEP context lifecycle
already described below.

Same-generation ModuleACM control flow also shows that `evaluatePolicy:` is a
requirement-driven two-stage evaluation, not one command that consumes the
password. It first derives the ACM policy string and calls
`preflightPolicy:parameters:maxGlobalCredentialAge:processRequirement:`. An
unsatisfied returned requirement is handed to `MechanismManagerACM`; the
passcode mechanism later supplies ordinary credential type `-1`, whose
separate AKS/MKB bridge authorizes the existing ACM context, after which policy
evaluation can be retried against that changed backend state. For policy `1007`,
the visible `_acmParamForPolicy` builder adds neither its user-ID parameter
(reserved here for policy `1` and second-pass `1008`) nor the Apple Pay
time-offset parameter. With nil Settings options it produces no parameter
array, and the separately supplied maximum-global-credential-age value is zero
because it is read from an absent option and converted from seconds to
milliseconds. Zero's backend meaning must not be guessed as either “fresh
only” or “unlimited” from ModuleACM alone; the important result at this layer is
that target UID and wall-clock freshness are not explicit fixed fields in this
observed outer policy-1007 request. Subject and freshness can still be encoded
in ACM context state and the backend's credential timestamps.

The same-generation `LACACMHelper` recovers the clock behind those timestamps.
`ageForDataWithType:error:` reads ACM context-data property `1`, identified by
its own error diagnostics as the data's `ModificationTimestamp`, then reads ACM
environment variable `71`, identified as `SEPTimeSinceBootInMs`, and returns
the unsigned difference `SEPTimeSinceBootInMs - ModificationTimestamp`. Both
values are eight bytes and the result is expressed in milliseconds. Thus ACM
credential/data freshness is based on a SEP-maintained monotonic boot clock,
not the host's wall clock. Changing Linux time cannot make an old credential
fresh, and copying bytes into a newly fabricated context is not equivalent to
preserving the backend timestamp. This still does not resolve what a
The matching credential engine resolves zero's ordinary-context meaning.
`adjustMaxCredentialAge` returns the credential set's configured maximum age
when nonzero, otherwise `0x927c0` milliseconds: exactly **600,000 ms (ten
minutes)**. An optional override is copied into the credential set only when it
is at least `0x927c1`, so an absent/zero option does not select unlimited age or
fresh-only behavior. `findValidCredential` uses the adjusted value to compute
the oldest acceptable credential timestamp. A few explicitly enumerated
global-context credential types bypass that default, but `TouchIdEnrollment`
checks type `1` in the current non-global context and then requires that same
context's credential set. The evidence-backed default enrollment-authority
window is therefore ten minutes, measured against the backend/SEP monotonic
clock, subject to any already configured larger credential-set maximum.

The “externalized context” passed between LocalAuthentication components is
also narrower and stronger than a serialized credential container. ACMLib
exports exactly the 16-byte ACM handle after command `19` accepts it; it does
not serialize the context's credentials, timestamps, user identity, or policy
state into the host-visible blob. Import requires exactly 16 bytes and asks the
AppleCredentialManager backend to reacquire that existing handle, first with
command `37` and, on a bad-parameter compatibility fallback, command `18`.
Only a successful backend response produces a local handle object and tracking
value. Therefore the `credset` cannot be minted by reproducing an archive
layout or by concatenating a password with user metadata: it is an opaque
reference to live ACM/SEP-maintained state. The previously recovered audited
originator and per-user passcode-verification path determine who may cause that
state transition, while the 16-byte external form lets later components refer
back to it without exposing its contents.

Requirement resolution nevertheless restores an explicit host-side subject
join that is absent from the serialized command-3 body. ModuleACM's internal
evaluation information must contain `UserId`; `MechanismManagerACM` copies that
value together with the `ACMContextRecord` into every passcode mechanism's
initialization parameters. `MechPasscode` then creates a
`LACMutablePasscodeVerificationRequest` from the entered passcode, the same
context's external form, and the original client's raw audit token; it
separately sets the LA policy, policy options, biolockout-recovery flag, and
the mechanism's numeric `UserId`. Thus a policy-1007 passcode requirement is
resolved for a concrete host user and audited originator even though UID is not
an ACM policy parameter. The lower MKB/AKS worker later reduces this to the
resolved per-user keybag handle plus passcode/context input, so the audit token
belongs to the LocalAuthentication request/mechanism boundary rather than the
selector-42 body.

Biometric requirements can be still more specific. For requirement type `3`,
the mechanism manager reads property `304` as an identity count and property
`303` as exactly `count * 16` bytes of identity UUIDs; when constraint binding
is enabled, those UUIDs are installed on the biometric mechanism. This is
direct evidence that ACM requirements can bind permitted biometric identities,
not merely request “some fingerprint.” It does not show policy 1007 returning
type `3`—the demonstrated enrollment ceremony uses the passcode mechanism—but
it rules out representing every biometric requirement as a
user-wide Boolean in future diagnostics.

ACMLib also exposes a biometric-provider-state protocol outside an individual
policy command or credential. The same-generation implementation exports
`LibCall_ACMSecCredentialProviderEnrollmentStateChangedForUser`, which sends
AppleCredentialManager command `0x0e`. Its request has this exact wire shape:

1. a four-byte user identifier;
2. the required 16-byte keybag UUID;
3. the required 16-byte Catacomb UUID; and
4. the optional enrollment-state byte string, one through 112 bytes.

The enrollment-state string may instead be absent only as the exact pair `(NULL,
0)`; a non-NULL zero-length value, a NULL nonzero-length value, or 113 bytes
and above is rejected before transport. No reply body is requested.

This mapping is no longer inferred from the export name. The matching Intel
AppleCredentialManager build retains the source assertions
`keybagUuid && keybagUuidLength == sizeof(uuid_t)`,
`catacombUuid && catacombUuidLength == sizeof(uuid_t)`, and the complete
`enrollmentState` length predicate. Register and stack tracking through the
serializer fixes the function argument and wire order: the stack integer is
written at request offset `0`, the stack keybag UUID at offset `4`, the
register-passed Catacomb UUID at offset `20`, and `enrollmentState` at offset
`36`. The integer is the function's `ForUser` selector, not an enrollment-state
enum. The command is named `kCmdSbioEnrollmentStateChanged` in the same binary.
The internal structure of the zero-to-112-byte enrollment-state value remains
unknown until a real producer or non-stub consumer is recovered.

Two adjacent APIs prove this protocol is distinct from device-wide
capability state. `LibCall_ACMSecSetBuiltinBiometry` sends command `0x1e` with
a one-byte body. `LibCall_ACMSecSetBiometryAvailability` first reads ACM
environment variable `6` as a one-byte bitmask, sets or clears the caller's
selected mask according to a Boolean, and writes the resulting one-byte value
back as environment variable `6`.

The matching Intel credential engine adds an essential platform boundary. It
registers `userBioEnrollmentStateDataProvider` for environment variable `36`,
but that provider returns success with a zero-length value. Its exported
`CredentialProviderAvailableForType` implementation is a hard stub that logs
an assertion and returns `-1` for every type. Therefore the presence of the
ACMLib command does **not** yet prove that T2 Touch ID enrollment uses it, that
the matching host engine persists a per-user/provider record, or that Linux
must update it after every Catacomb mutation. The required ordering and
rollback rule remain unknown until a non-stub backend implementation or a real
producer call site is found. Issuing command `0x0e` speculatively could create
state the demonstrated T2 enrollment path never uses—or make backend policy
state disagree with the biometric database—and is outside the current
research-only scope.

The same-generation `BiometricKitXPCServer` implementation rules out one
tempting but incorrect join: its `updateEnrollmentChangedNotification:` is not
an ACM call. It writes the current identity count into the registered Darwin
notification token, optionally posts
`com.apple.BiometricKit.enrollmentChanged`, updates express-mode state, and
clears the published lockout state when the count becomes zero. Call sites
invoke it after a successful single-identity Catacomb save, after a successful
remove-all save, after restore/synchronization on Catacomb unlock, and after
reconciling externally changed Catacomb state. The matching Intel
`biometrickitd` also invokes it from the enrollment-result path before starting
the high-priority presence-detection interval between enrollment phases.
Therefore ACM command `0x0e` is not hidden inside BiometricKit's
enrollment-change notification or Catacomb commit. Whether ACM consumes that
Darwin notification and derives its own per-user/provider record, or a
different daemon explicitly sends command `0x0e`, remains to be established.
Linux must reproduce neither mechanism until that direction and ordering are
observed.

A captured-artifact-wide call-site audit sharpens this negative result. The
command name or export appears in the 24G830 macOS AppleCredentialManager
kext and AppleSEPManager, bridgeOS LocalAuthenticationCore, and bridgeOS
`LASecureIOd`; disassembly shows these are copies/imports of the ACMLib
serializer itself. `LASecureIOd` contains the complete argument validator and
command-`0x0e` wrapper at its named symbol, but has no direct branch or call
back to that wrapper from the rest of the executable. The extracted bridgeOS
LocalAuthenticationCore likewise exports the serializer but contains no call
site, and no captured BiometricKit/biometrickitd artifact references the
symbol. This is stronger than merely failing to find the API by name: among
the captured host and bridgeOS components, there is still no producer of its
36-to-148-byte request. The command may be reserved SPI, used by an uncaptured
component, or invoked only on another platform; it cannot presently be placed
in the T2 enrollment commit or rollback sequence.

That transport is also identifiable in the matching bridgeOS framework.
LocalAuthenticationCore contains Apple's `ACMLib` and command serializers;
its `_init` resolves the local IOKit service named
`AppleCredentialManager`, opens its user client, and `_ioKitTransport` routes
the serialized ACM request through that connection. The recovered RemoteXPC
BiometricKit and LASecureIO endpoints do not expose this API. Consequently the
remaining Linux authorization research has two technically coherent branches:

1. discover a legitimate, authenticated bridgeOS broker for coreauthd/ACM
   operations that is not present in the currently advertised Remote Service
   Discovery catalogue; or
2. recover and port the AppleCredentialManager user-client selectors and ACM
   serialization over the T2 SEP transport, preserving real context creation,
   policy-1007 verification, passcode credential handling, externalization,
   audit-equivalent subject binding, and destruction.

The exact Intel AppleCredentialManager kext narrows branch 2 further. Its SEP
driver asserts endpoint `10` (the current Linux transport implements only
AppleKeyStore endpoint `7`). The synchronous message header is packed as
endpoint byte, request byte, 16-bit OOL payload length, and 32-bit info value;
the reply handler requires endpoint 10, checks the declared length against the
caller's output capacity, copies that many bytes from the SEP OOL buffer, and
only then completes the waiting command. At the user-client boundary, selector
`0` is the structured `extPerformCommand` entry used by ACMLib, and the Apple
driver requires `com.apple.private.applecredentialmanager.allow` (or its
internal variant). A future Linux endpoint-10 driver therefore needs its own
OOL registration, reply correlation, strict length validation, secret wiping,
and an explicit privileged authorization model; widening the endpoint-7
`/dev/aks` allowlist would be both structurally wrong and a security regression.

Exact endpoint registration and correlation are now recovered from matching
symbols `getSEPEndpoint`, `resetOOLBuffers`, `sendSEPCommand`,
`sendSEPMessage`, and `handleSEPMessage`. The driver waits indefinitely for
`AppleSEPManager`, asks it for endpoint `10` with `handleSEPMessage` as the
callback, enables the returned endpoint, and allocates two independent
`IOSlaveMemory` objects through the manager: each is `0x4000` bytes with
`0x1000` alignment. It installs the first through `setSendOOLBuffer` and the
second through `setReceiveOOLBuffer`. Failure to allocate/register either
prevents initialization. Once the receive descriptor is installed, the driver
maps it and retains a host virtual pointer plus its exact descriptor length;
that mapping is replaced and freed if the descriptor's mapped address
changes.

The ordinary synchronous path is deliberately single-flight under the ACM
command gate. It writes the payload into the send OOL buffer, clears the shared
completion status to `kIOReturnNotReady`, sends one eight-byte inline header,
and sleeps on that completion object. The callback decodes
`{ endpoint:u8, request:u8, length:u16, info:u32 }`, rejects any endpoint other
than `10`, bounds `length` against the caller's registered response capacity,
copies exactly that amount from the receive OOL buffer, stores the returned
request byte, and wakes the gate. After wake, `sendSEPCommand` requires that
returned request byte to equal the command it sent. Thus ordinary commands do
not need a second transaction identifier because serialization permits only
one outstanding request. SCRD request code `4` adds its own 32-bit request ID
inside the OOL payload; the driver increments that ID, skips zero on wrap, and
logs a mismatched response ID. Standard response wait is 5,000 ms; the path
whose input command byte at offset 4 is `0x26` waits 10,000 ms. Timeout is an
ambiguous completion (`kIOReturnTimeout`), not evidence that SEP did not act.

OOL reset is not mere memory clearing. When reset is requested, the driver
reenables a disabled endpoint, then calls `setReceiveOOLBuffer` and
`setSendOOLBuffer` again with the existing descriptors; either registration
failure panics the matching macOS kernel. During endpoint reacquisition it also
notices a changed receive mapping, frees the stale host mapping, remaps the
descriptor, and only then marks initialization complete. Power-state handling
can mark the buffers for this reset and disable the endpoint before sleep or
shutdown. A Linux port therefore needs a transport generation number: cancel
and classify every in-flight authorization as outcome-unknown on reset, repeat
both OOL registrations after every endpoint generation change, remap the
receive descriptor, and never accept a late reply from the previous generation.

The exact user-client-to-SEP boundary also separates host authorization from
the data the ACM backend actually sees. Opening the macOS user client first
requires `com.apple.private.applecredentialmanager.allow` (or the internal
variant). For every submitted command, `_checkRequiredCommandEntitlements`
then evaluates any command-specific entitlement against the opening Mach task.
Those checks happen before `_performCommand`; neither the entitlement result,
task pointer, audit token, PID, nor macOS code-signing identity is serialized
to endpoint 10.

The packed `ACMPerformCommandContextV2` constructed by `externalMethod` is
exactly a 32-bit session UID, an unaligned 64-bit opening-task pointer, and a
one-byte command code. The user-client `start` method obtains the UID from the
effective credential of its opening process. `performCommandGated` appends that
UID as four little-endian bytes only to `kCmdContextCreate` (`1`) and
`kCmdContextCreateWithTracking` (`0x24`/36). All later commands operate on the
returned 20-byte context handle. On T2, `_performCommand` sends the resulting
command bytes unchanged through endpoint-10 request code `1`; the packed host
context is not an additional SEP parameter. (The non-SEP software fallback
does consume the host context separately, but that is not this machine's path.)

This materially changes the Linux feasibility boundary. macOS entitlement and
audit-token enforcement are host policy, so Linux need not forge Apple code
signing or a Mach audit token. It must replace that policy boundary with a
root-only kernel interface plus explicit PolicyKit/session checks. The one
subject value that *does* cross into the ACM credential-set lifecycle is the
32-bit UID appended at context creation; later policy evaluation's ordinary
SUID comparison binds credentials to that created context. A Linux producer
must therefore resolve the authenticated Linux account to the already proven
Apple numeric UID mapping, create the ACM context under exactly that UID, and
reject arbitrary caller-supplied UIDs. This proves transport-level legitimacy
is reproducible in principle. Later exact ACMLib and AppleKeyStore analysis
closes command serialization and the passcode bridge. Type-13 seed internals
are unnecessary for the active password-verification path; final biometric-
consumer acceptance/replay remains the device-side uncertainty.

The kext's endpoint initialization now supplies concrete buffer requirements.
It obtains an `AppleSEPEndpoint` for endpoint `10`, allocates distinct send and
receive OOL memory descriptors with capacity `0x4000` bytes and alignment
`0x1000`, and registers them through separate endpoint methods. It then derives
the CPU mapping and length of the receive descriptor for reply copying. Reset
unregisters the receive descriptor first and the send descriptor second; a
registration failure is not treated as a usable partial setup. This is a
two-buffer, endpoint-owned transport lifecycle, not an inline 16 KiB message
allowance that can be grafted onto the endpoint-7 device.

The matching ACMLib client also exposes the minimum command skeleton needed to
study enrollment authorization without guessing. `ACMContextCreate` creates a
20-byte client handle through a version-dependent create command. Direct
extraction of the 24G830 x86_64 `LocalAuthenticationCore` resolves the earlier
cross-generation ambiguity: when tracking is requested it sends command `0x24`
with a 21-byte reply capacity, and otherwise (or when `0x24` returns unsupported)
uses legacy command `1` with a 17-byte reply capacity. It never selects `0x34`.
The tracking reply places the 20-byte client handle first: a 16-byte context
identifier followed by its four-byte little-endian tracking payload. The final
byte is the Boolean response flag. A live Linux endpoint-10 test on the proven
24G830 machine confirmed that 21-byte layout, accepted creation for configured
UID 501, and successfully deleted the returned context immediately afterward;
the public tool reports only typed/Boolean outcomes and never the identifier or
payload.
The 24G830 x86_64 AppleCredentialManager kext appends effective UID for exactly
`1` and `0x24`, so the host client and kext agree. Command `0x34` belongs only to
the newer bridgeOS client artifact and is not part of the target macOS ABI.
`ACMContextAddCredentialWithScope` serializes the credential and invokes
context command `5`; policy verification serializes its parameter array and
invokes context command `3`; `ACMContextGetExternalForm` invokes command
`0x13`, passing the 16-byte handle as both request payload and output source;
and context destruction invokes command `2` before freeing and wiping the
20-byte handle. Reconstruction from an external form similarly has a current
command `0x25` and legacy command `0x12` path. These command numbers and sizes
originally defined the bounded static-recovery target. The exact command-3
serializer and endpoint-7 AKS password bridge below subsequently close the
passcode/policy-1007 host path; only final secure-biometry consumption remains
outside the plaintext corpus.

The command-3 serializer and reply contract are now exact in the directly
extracted 24G830 x86_64 ACMLib client (and match the bridgeOS corroboration).
The request is the 16-byte context identifier, followed by a
NUL-terminated policy string limited to 128 bytes, one Boolean control byte,
one unaligned little-endian 32-bit control value, and the serialized parameter
array. Its total size is `policyLength + parameterBytes + 0x1a`, where
`policyLength` excludes the terminator. The transport allocates at most a
0x1000-byte reply. A successful reply must contain at least four bytes: the
first little-endian 32-bit value is reduced to the policy-success Boolean; any
remaining bytes begin a serialized ACM requirement and are decoded only when
the caller requested that requirement. This removes any hypothetical daemon
object or audit-token field from the endpoint-10 policy reply.

The password-binding boundary is now confirmed against the AppleKeyStore kext
from the **running macOS 26.1 build 25B77**, rather than inferred only from the
older 24G830 installer payload. The live kext has Mach-O UUID
`014567BF-63F6-3391-A782-AF69FE030A04`; the executable extracted from the
manifest-verified Boot Kernel Collection has SHA-256
`af311e668b7480c699e7ba98a5402aa544e668e4211dcc51d806af445135e76c`.

Its exact C++ symbol is
`AppleKeyStore::verify_password(unsigned long long, int, OSData *, OSData *,
bool, bool, bool)`. The generated operation-`0x21` wrapper places the first
argument in the owning-session field and the second in the signed-handle field,
followed by password and ACM external-context blob descriptors. An
instruction-level re-audit of `_code_ipc_verify_secret` corrected an earlier
branch-direction error: codec v1 serializes the version word, 64-bit session,
32-bit handle, password blob, ACM-context blob, **and one final 64-bit device
options value**. In the in-memory codec structure the request value is at
`+0x88`; the response value at `+0x90` is selected only for the opposite
direction. The server passes the first two request values directly to
`keybag_for_handle(session, handle)`, which compares the handle against each
stored bag record and then accepts only a matching, wildcard, or zero owning
session. Linux loads the private bag as session `1` and uses special handle
`-501`. Read-only operation-`0x19` controls accepted sessions `1`, `2`, and
`UINT64_MAX-1` for that alias on the current runtime, proving the stored bag's
owner is wildcard or zero and excluding the host session value as the observed
operation-`0x21` blocker. Session zero is rejected locally by the diagnostic
encoder and was not sent.

The three host-side Boolean arguments do map to local option bits `0x80`,
`0x100`, and `0x200`. Exact
`_fv_init_cred_from_secret` disassembly proves that bit `0x100` selects a
serialized ACM credential decoder; when it is clear, the supplied bytes are
copied as a plain secret. A subsequent x86-64 ABI audit corrected the Boolean
call-site ordering: selector `0x2a` unconditionally supplies the third Boolean,
therefore setting local bit `0x200`, while its memento form also sets `0x80`.
Both the running 25B77 kext and the independent 24G830 kext have the same
encoder control flow. The canonical Linux reproduction must therefore append
exactly `0x200` and preserve the endpoint-10 context lifetime.

Live tests on 2026-08-30 with complete codec-v1 bodies returned SEP status
`-1` for `0x200`, `-12` for `0x280`, and `-1` for zero. A subsequent body that
stopped after the context blob returned `-13`; that request was eight bytes
short and is now known malformed. Later canonical `0x200` tests with the
correct full body returned `-1` for the special and positive handles, both
context-create variants, both tested 32-bit platform values, both tested process
values, and the five evidence-derived CodeDirectory hashes. The kernel
allowlist permits only the exact selector-42 option rather than exposing the
memento or zero-option variants. These negatives bound the tested matrix but
do not prove that platform data is ignored.

The running kext's `ipc_verify_secret_v1` implementation narrows `-1` further.
It is returned before normal secret unwrap when `keybag_for_handle` cannot
resolve the supplied owner/handle, or when the unlock helper fails at function
level; a normal wrong plaintext password becomes status `-5`. The raw-secret
initializer itself cannot produce `-1` for a non-empty valid request.

The exact v1 operation-`0x19` state-query codec was then recovered and tested.
Its 24-byte body is codec version `1`, owning session, signed handle, an empty
PFK-parameters blob, and selector. Session `1` with both the positive loaded
handle and special alias `-501` returned a valid state dictionary; current-user
alias `-3` failed. A private, UUID-redacted decode of the positive handle
reported bag handle `9`, maximum attempts `11`, backoff `0`, failed attempts
`0`, lock state `0`, generation state `0`, and state word `0x06000004`. The raw
state files were removed after decoding. This proves that the positive handle
and `-501` both pass keybag lookup and keystore verification, and that neither
policy backoff nor a locked bag explains operation `0x21`'s `-1`.

The successful boot sequence supplies an additional control. It unlocks the
positive handle and then its `-501` alias with operation `0x04`. Because both
refer to the same now-unlocked bag, the second call enters
`_unlock_keybag_with_opts` in verify-only mode: null destination, raw password,
and no device options. That succeeds. Consequently the shared keybag lookup,
raw-secret initialization, policy/backoff, KDF, unwrap, already-unlocked state,
and verify-only path are all known-good for the same password. Because the
full canonical request and caller matrix still return `-1`, the next bounded
test is the same codec with a zero-length ACM external-form blob. The exact
running-kext implementation skips `ACMSecContextCreateWithExternalForm` when
that descriptor is absent; success would isolate the failure to ACM-context
attachment, while another `-1` would keep it in keybag/password/header handling.

The exact branch contract makes this diagnostic stronger than a generic retry.
After successful keybag lookup, `_unlock_keybag_with_opts` receives the same
raw password and `0x200` options whether or not an ACM blob exists. It returns
function success while placing ordinary policy/unwrap outcomes in an output
status; a wrong plaintext secret becomes `-5`. Only after a zero function and
zero output status does `ipc_verify_secret_v1` inspect the ACM pointer/length.
When either is absent it skips `ACMSecContextCreateWithExternalForm`, all ACM
credential construction/property calls, and context credential attachment.
Thus password-only success identifies the ACM half as the blocker; `-5`
identifies ordinary password rejection; and another `-1` remains in keybag
lookup, raw-secret initialization, or another pre-ACM function-level failure.

The legacy operation-`0x04` control is closer still than initially documented.
Its wrapper clears the device-options argument before calling
`_change_lock_state_with_opts`; the already-unlocked alias then calls the same
`_unlock_keybag_with_opts` helper with a null destination. Operation `0x21`
passes `0x200`, but exact 25B77 disassembly shows that the helper observes only
option bits `0x20`, `0x80`, and `0x100`. Bit `0x200` passes
`_valid_device_options` but does not alter raw-secret initialization, policy
operation, derivation, or unwrap inside this helper. Therefore the successful
operation-`0x04` alias verification is an almost identical password-only
control. If the staged zero-context operation-`0x21` probe still returns `-1`,
the next work should instrument operation-specific framing and dispatch rather
than repeat password, KDF, or ACM guesses; that result would falsify part of
the current host-side model.

A fresh manifest-verified capture from that same running 25B77 installation now
bounds the caller-platform matrix without relying on another macOS release. The
five candidate CodeDirectory hashes are `coreauthd`
`620afcb94070430680b6aada2419400c1dd7b255`, `authd`
`45bd55f93f3f65a59a4b5faa92468a94e781a4dc`,
`LocalAuthenticationRemoteService`
`22b2c0a027a115893cec3aebca6365c226b2f27c`, `applekeystored`
`5990fc3b4106fedbfdd780aaadce411fc64efc22`, and `biometrickitd`
`1da1f25b69074f4346a8db5083ab85518056d900`. The process snapshot contained
both root and per-user `coreauthd` instances plus root `applekeystored` and
`biometrickitd`. This is a candidate set, not proof of the selector-42 caller;
the matrix must remain fail-closed and must not permanently trust any hash on
the strength of process presence alone.

The first reboot after the canonical-body correction exposed an installation
boundary rather than a new protocol result. The pinned live module had GNU
build ID `10c190cfa6e1ec46d383925283dde1c30b2ec6aa`, while the corrected signed
DKMS module on disk had build ID `ade422d1bbed10839885937cc21539c6203b11e2`.
The early operation-`0x21` attempt, made while the matching intermediate helper
was still installed, sent the truncated body and logged SEP `-13`. The public
doctor now compares the live and installed GNU build IDs and reports
`module-build ... reboot required` for such a state. A later reboot did load
the matching canonical module, after which the full-body `-1` matrix above was
observed; the historical `-13` is not evidence about the canonical request.

An instruction-level trace of the exact 25B77 user client also corrects two
platform-header assumptions. `AppleKeyStoreUserClient::start` assigns its
session value from a per-boot random instance base plus
`proc_uniqueid(current_proc)` and passes that value directly to
`verify_password`; there is no separate client-registration request to SEP.
`_get_platform_proc_stuff` writes `proc_uniqueid` and then reads
`cr_audit.as_aia_p->ai_asid`. The adjacent 32-bit v2 field is therefore the
macOS **audit-session ID**, not a Unix UID. The Linux parameter and public
configuration now call it `aks_platform_asid` accordingly.

A private historical audit-session value was tried with the canonical body,
first with an empty caller hash and then with all five current 25B77 candidate
hashes; every case returned `-1`. The value is intentionally redacted and is
not stable across audit sessions or boots. This rules out that stale value as
a standalone fix, not the current audit-session/process-unique pair. The
read-only macOS collector now records current candidate pairs together with a
boot UUID, while explicitly treating them as non-replayable private evidence.

One framework helper recovers a generic passphrase credential envelope, but
the matching ModuleACM dispatch now proves that it is **not** the enrollment
path. `LACACMHelper.replacePassphraseCredentialWithPurpose:
passphrase:scope:error:` creates credential type `2`, sets property `0xc9` to a
four-byte purpose value, sets property `0xc8` to the passphrase byte string,
and calls `ACMContextReplacePassphraseCredentialsWithScope`. The scope is kept
as a distinct argument; the replacement serializer is then sent as context
command `0x0f`. This proves that ACM's generic passphrase object separates
credential type, scope, purpose, and secret data, but it must not be treated as
the enrollment credential schema.

The actual type-`-1` setter branch is direct and materially different. After
the entitled UI has extracted the transient type-`-5` archive and supplied its
`Credential` bytes as ordinary credential type `-1`, ModuleACM wraps those
bytes in `LACSecureData`, obtains the cached ACM context's externalized form,
and invokes `LAPasscodeHelper.verifyPasswordUsingAKS:acmContext:userId:policy:
options:bioLockoutRecovery:`. For type `-1` it selects policy `0x3ef`/`1007`;
the sibling branch selects `0x3f6`. It passes a concrete user ID (from the
request originator when present, otherwise the context's user ID), the
externalized ACM context, and the policy together with the password. A zero
return is accepted, nonzero returns become `Password rejected (%d)`, and the
successful path records a true result before the caller externalizes the
context. Thus enrollment authorization is an AKS password-verification bridge
that updates or verifies the real ACM context for `TouchIdEnrollment`, not an
ACM type-2 passphrase replacement with an unknown purpose/scope. The exact
24G830 helper, two-blob selector-42 body, UID-to-keybag resolver, and MKB/PAM
routing are all recovered above; this is no longer a version-sensitive gap.

For completeness, the unrelated generic replacement/add serializer's outer
layout is also recoverable. It writes
the 16-byte ACM context handle first, copies a serialized credential of
`0x20 + credential.payloadLength` bytes immediately after it, and appends the
four-byte scope after that credential. Total request size is therefore
`0x34 + credential.payloadLength`. The credential serializer is deliberately
type-restricted and copies its fixed 0x20-byte header plus the validated
type-specific payload verbatim. Its remaining unknown is consequently narrow
but no longer blocks enrollment: the in-memory/property serializer layout for
credential type `2`, rather than the outer ACM request framing.

Exporting one external form from macOS and replaying it on Linux is not a safe
third architecture. The recovered flow has backend context tracking,
invalidation, UID/session lifetime, and returned policy requirements whose
cross-boot replay behavior is not established. Mach audit state is a host-side
macOS gate and does not cross endpoint 10; its absence is not the reason replay
is unsafe.

One decisive boundary remains unrecovered: the final secure-biometry consumer
of the registered/reconstructable ACM external form, particularly replay,
one-shot consumption, and zero-length-authorized-state rules. The matching ACM
credential engine now establishes the host/backend policy name, live
credential-set lookup, enrollment-authorized context property, ten-minute
default freshness, and passcode/no-passcode requirement; those facts should no
longer be listed as wholly unknown. The host-side BiometricKitUI
transformation is now version-qualified but structurally joined below:
`credset` becomes an operation credential set, is emitted under
`BKOptionAuthWithCredentialSet`, and is parsed into the 40-byte mode-0
authorization container while `userid` remains a separate command field.

That host join is now exact matching-macOS evidence, not merely cross-platform
corroboration. The materialized 24G830 `dyld_v1 x86_64h` cache is present with
cache UUID `FDD97301-9818-3865-A1D2-FEC1D3914796`, reports macOS 15.7, contains
3,258 images and six subcaches, and yields exact extracted x86_64
`LocalAuthenticationCore`, `BiometricKit`, and `BiometricKitUI` images. The
earlier zero-byte on-disk framework placeholders and RIDIFF10 extraction
difficulty describe acquisition history only; they are no longer an evidence
gap.

The exact full `24G830` OTA is now preserved locally rather than inferred from
the enclosing installer. It was extracted read-only from the installer's HFS+
`SharedSupport` image as
`apple-artifacts/macos-15.7.9-24G830/9d95c64142a9a426f56d3265d4f8a6fa31585333.zip`
(15,630,394,567 bytes). The HFS+ reader's source and destination SHA-256 checks
both produced
`1c76ee0ffbc8bcb4ec74e94d2b68fe31032f90a9a52f39847ae7fa946fa36d45`.
The initial Linux extraction attempts correctly rejected unsupported
RawImagePatch/AppleArchive forms rather than silently mis-decoding them. A
subsequent preserved materialization produced the exact cache family above,
closing both acquisition and materialization. Public symbol-server images with
different UUIDs remain inadmissible as substitutes.

The exact macOS Settings client is not an auth-refresh producer.
`SecurityShared` implements the enrollment-result delegate but does not
implement the protocol's optional `generateAuthToken` selector; its
demonstrated initial path supplies `credset` instead.
The externalized-context `NSData` is released by the client after being set as
a BiometricKitUI controller property, but no explicit byte wipe is visible.
The now-extracted exact framework confirms ordinary retained-property/operation
ownership rather than an explicit secure wipe contract. Future Linux code must
bound the lifetime itself and wipe every host copy on completion or uncertainty.

A same-generation iOS 26.1 (`23B85`) binary-derived framework corpus originally
provided corroboration for this layer. The exact 24G830 macOS BiometricKitUI
now supplies the authoritative class and event paths; the iOS corpus remains a
cross-platform consistency check. Its
`BKUIFingerprintEnrollViewController._startEnrollOperation` does the following
in order:

1. creates a fresh `BKEnrollTouchIDOperation` and assigns its delegate;
2. reads the UI property `credset`; if present, calls
   `setCredentialSet:` on that operation;
3. calls `setUserID:` with the controller's selected numeric user; and
4. calls `startWithError:`.

The same controller's appearance path reads the `userid` property and otherwise
defaults to `getuid()`. This exactly matches the property names and types set by
the recovered macOS Settings client. The next same-generation layer,
`BKEnrollOperation.optionsDictionaryWithError:`, places its `_credentialSet`
under **`BKOptionAuthWithCredentialSet`** (not the more specifically named
`BKOptionEnrollWithCredentialSet`), then invokes
`enroll:forUser:withOptions:`. The previously recovered authorization parser
checks this general key first and converts it to mode `0`. The joined likely
path is therefore:

`LAContext.externalizedContext` -> UI `credset` -> operation
`credentialSet` -> `BKOptionAuthWithCredentialSet` -> 40-byte mode-0 container.

This path was first joined with iOS 26.1 corroboration. The subsequently
materialized exact 24G830 macOS dyld cache supplies the matching x86_64
BiometricKit, BiometricKitUI, and LocalAuthenticationCore images, so the normal
mode-0 host join is now target-build evidence rather than a missing-middle
inference.

The same corpus clarifies refresh and cancellation behavior:

- retry/second-finger UI paths call `_requestNewAuthToken`, which merely invokes
  the enrollment-result delegate's optional `generateAuthToken` method. It does
  not create a token inside BiometricKitUI. A client that implements the method
  must update controller state out of band; the recovered macOS Settings
  delegate does not implement it;
- ordinary and extended enrollment both reuse the controller's `credset`; the
  extended path sets it on `BKExtendEnrollTouchIDOperation` before selecting the
  existing identity;
- UI cancellation calls `BKOperation.cancel`, which sets `cancelPending` and
  sends the XPC `cancel` request unless the operation is already terminal. It
  is asynchronous; returning from `cancel` is not proof that SEP stopped or
  rolled back;
- a successful initial enrollment sends UI result `1`, retains the returned
  identity, and may immediately start extended enrollment. Failure reason `1`
  is presented as cancellation, `2` as failure, and `3` as timeout. Operation
  terminal handling changes state to `4`, notifies the delegate, detaches the
  XPC delegate, and invalidates the connection; and
- neither UI cancel, operation terminal handling, nor deallocation visibly
  zeroes the retained credential-set object. Deallocation releases components
  and disconnects clients, but ordinary release is not secret erasure.

For Linux, cancellation must consequently be modelled as `cancel-requested`
until a terminal event and post-cancel identity inventory agree. Credentials
must be operation-local and explicitly wiped by Linux even though Apple's
Objective-C objects are not. A restart must use a fresh authorization object
and fresh operation/connection; it must not infer that the prior asynchronous
cancel made replay safe.

### What `generateAuthToken` actually refreshes

The same-generation Setup Assistant client
`BuddyMesaEnrollmentController` supplies the missing concrete delegate
implementation. Despite its selector name, `generateAuthToken` does **not**
produce or install a raw mode-1 authentication token. It discards its current
`LAContext`, constructs or fetches a newly authorized context, obtains
`LAContext.externalizedContext`, and replaces the enrollment controller's
`credset` property with that `NSData`. Its initial `beginEnrollment`, explicit
`restartEnrollment`, and delegated `generateAuthToken` paths therefore converge
on the same externalized-context -> `credset` mechanism. In this demonstrated
client, the selector refreshes the mode-0 credential set.

Setup Assistant has two context-authorization branches. If a passcode exists
and Setup Assistant has a cached passcode, it creates a new `LAContext`, assigns
itself as UI delegate, evaluates numeric policy `1007`, and supplies the cached
passcode bytes to the processed LA event as credential type `-1`. If there is
no cached passcode, it asks `BYBuddyDaemonGeneralClient` for a previously stored
biometric authentication context and assigns the same UI delegate. If no
passcode exists, `resetAuthContext` leaves no demonstrated context. These are
Setup Assistant provisioning mechanisms, not evidence that an arbitrary Linux
process can mint the same credential set merely by knowing a password.

The refresh call is synchronous and has no return value or completion block.
BiometricKitUI requests it immediately before starting a fresh enrollment
operation in at least two paths: accepting the second-finger upsell and
continuing after the skip/cancel alert. `_startEnrollOperation` then rereads
the controller's `credset` property and copies it into the new operation.
Consequently:

- refresh scope is per newly started operation, not per touch sample;
- the credential is not transformed into a mode-1 token by this UI;
- the target remains the controller's separate numeric `userid`, so credential
  and target UID are distinct inputs; and
- if context construction or `externalizedContext` fails, this client does not
  clear the previous `credset` or report refresh failure to the UI. The retained
  value may be reused, leaving only the daemon/SEP to reject it as stale or
  unauthorized.

Linux must improve on this contract: clear prior authorization before refresh,
require an explicit successful result, bind the fresh object to the intended
Apple UID and operation identifier in local state, and fail closed rather than
falling back to a retained credential. Nothing in this flow creates an Apple
user, persona, keybag, numeric-UID alias, or Catacomb namespace; it authorizes
enrollment for a separately selected, already provisioned user.

### Credential-set and target-user binding boundary

The recovered host stack preserves the authorization object and target user as
parallel inputs rather than joining them on the host:

- BiometricKitUI stores `credset` and `userid` as separate controller
  properties;
- each new enrollment operation independently receives `setCredentialSet:` and
  `setUserID:`;
- `BKEnrollOperation` puts the credential under
  `BKOptionAuthWithCredentialSet` while passing the numeric user through the
  separate `enroll:forUser:withOptions:` argument; and
- the matching daemon's enrollment-command builder copies the numeric user and
  the parsed 40-byte authorization container into separate command fields.

No recovered BiometricKit host layer verifies that the externalized LA/ACM
context was created for, or is entitled to act upon, the separately supplied
UID. The same
BiometricKit API pattern is also used by protected-configuration operations:
`BKDevice setProtectedConfiguration:forUser:credentialSet:` sends the user and
`BKOptionAuthWithCredentialSet` independently. This is evidence that the
credential-set key represents general operation authorization, not evidence
that it is portable between users.

The 24G830 AppleCredentialManager engine now proves that the opaque
credential-set lifecycle supplies at least part of that missing binding. Its
`_findValidCredential` rejects a candidate when the credential's stored
session identifier does not equal the requested credential-set session
identifier; the retained diagnostic reports the two values as `SUID` and
`credSetSUID`. A distinct, explicitly enabled override path compares against
`SUIDOverride` instead. The same validator independently rejects a credential
whose monotonic timestamp is older than `oldestAcceptable`, and one whose use
count has reached the supplied limit. These comparisons happen while resolving
credentials inside the live credential set, below BiometricKit's separate
`userid`/`credset` wrapper.

This closes the broad claim that session binding, freshness, and use limits are
wholly absent: they are real backend credential-selection gates. It does not
yet prove that the BiometricKit enrollment consumer requests a particular use
limit or how its separate numeric target UID is converted into the
credential-set session identifier. The policy-1007 call itself does settle the
override question: immediately before `VerifyPolicyPasscodeOptional`, the
`TouchIdEnrollment` branch writes little-endian `0x0100` to the adjacent
credential-selection flags at offsets `0xe0`/`0xe1`. In `_findValidCredential`,
that selects ordinary credential-set SUID comparison while leaving the
SUID-override selector clear. Enrollment policy evaluation therefore cannot
silently accept a credential from another credential-set session through the
engine's explicit override path.

This still does not prove
one-shot consumption after command `0x03`; `_findValidCredential` is general
ACM policy machinery, and the secure-biometry consumer may add stricter state.

Any remaining target-UID join, enrollment-specific replay prevention, or
keybag-state check can therefore reside in LocalAuthentication validation,
bridgeOS, or SEP. The only safe
multi-user rule is to treat the credential as bound to the Apple user for whom
the authorization ceremony was performed, even though that binding is not
visible in the host wrapper. A Linux authorization cache must key entries by at
least Apple UID, operation class, boot/session epoch, and a one-use local
operation identifier; a UID mismatch must destroy the credential and require a
new ceremony. Cross-user replay must never be an automatic fallback or a
diagnostic probe on the live identity store.

### Current-user enrollment versus cross-user management

The framework-level `userid` property permits a custom numeric target, but all
recovered current enrollment clients bind to their own OS user:

- matching macOS Settings explicitly stores `NSNumber(getuid())` as `userid`;
- same-generation Passcode & Biometrics Settings does not set `userid`, so the
  enrollment controller uses its `getuid()` default; and
- same-generation Setup Assistant likewise omits `userid` and receives the same
  current-process-user default.

No recovered client pairs one user's LA/passcode authorization ceremony with a
different arbitrary enrollment UID. The existence of `setUserID:` and a custom
property is protocol flexibility, not evidence of administrator-delegated
cross-user enrollment. This matters because the opaque credential may bind its
subject even though the host wrapper carries UID separately.

The management APIs have a different scope. Matching macOS Settings can query
`identitiesForUID:` and capacity for an explicit already-existing numeric user,
and the privileged server accepts identity objects or explicit UIDs for rename
and deletion. Thus cross-user **inventory and administration** are real host API
capabilities; cross-user **enrollment authorization** is not demonstrated.

A future Linux design must preserve that split. Self-enrollment may target only
the Apple UID mapped to the authenticated Linux session, after a fresh
authorization ceremony proven for that subject. Administrative enrollment for
another user remains disabled unless Apple-style delegated authorization is
recovered. An administrator may eventually inventory, rename, or delete another
mapped user's identities only through the separate identity-management policy,
immutable UID+UUID targeting, and transaction journal. Switching the raw UID in
an enrollment request is never impersonation support.

### Setup Assistant authorization-broker audit

Static tracing corrects an important possible over-interpretation of
`BYBuddyDaemonGeneralClient`. Its biometric-context method is a broker/cache,
not a credential issuer:

- the client connects to `com.apple.purplebuddy.budd.xpc`;
- `budd` accepts the connection only if its audit identity has the private
  entitlement `com.apple.purplebuddy.budd.access`;
- `storeAuthenticationContextforBiometric:` assigns the supplied `LAContext`
  into the daemon's shared `BYDaemonContext`; and
- `fetchAuthenticationContextForBiometric:` returns that stored object. The
  server method performs no policy evaluation, password verification, user
  lookup, or credential generation.

`BYDaemonContext` serializes access on a private dispatch queue. It has a
300-second delayed timeout path and explicitly calls `invalidate` before
dropping cached Apple Pay and biometric contexts in `_destroyContexts`; it also
registers for Setup Assistant state completion and destroys the contexts at
that lifecycle boundary. The recovered getter is not consume-on-fetch: it
returns the retained context. Reuse within the bounded Setup flow therefore
exists at the object level, although the externalized credential may still have
opaque freshness or replay restrictions.

The store-side producer is not present as a concrete selector call in the
available corpus, so its initial authorization ceremony remains unjoined. A
separate Setup Assistant path demonstrates that, when no cached context is
available, it creates an `LAContext`, checks and evaluates policy `1007`, and
only then uses `externalizedContext`. That corroborates policy-authorized
production, but does not prove it is the exact producer of the object stored in
`budd`.

| Component | Linux reproducibility | Security meaning |
|---|---|---|
| Serialized per-user cache, timeout, invalidation, explicit wiping | Reproducible and desirable | Local secret hygiene only |
| Numeric UID carried separately with enrollment | Already protocol-visible | Selects target; does not itself authorize it |
| Password input and keybag unlock | Existing endpoint-7 tooling covers unlock; the corrected root-only canonical codec-v1 path reaches SEP but returns `-1` across the bounded handle/context/platform matrix; a zero-context stage-isolation diagnostic is ready for the next module boot | The endpoint request is session, handle, raw password blob, optional ACM-context blob, and the exact selector-42 `0x200` option qword |
| `LAContext` policy `1007` and externalization | Exact 24G830 endpoint-10 commands and serializers are recovered; no Linux implementation yet | Produces the demonstrated mode-0 credential-set reference after backend policy success |
| `budd` service and private entitlement | Apple-only host IPC policy | Restricts sharing of an already-created context |
| SEP subject binding and freshness | UID-bound context create, password/context binding, ten-minute credential selection, and enrollment-authority flag are recovered | Backend authorization is reproducible in protocol, subject to strict broker ownership |
| Final biometric-consumer replay/one-shot behavior | Unrecovered because the matching SEP image remains device-key wrapped | Ultimate remaining device-acceptance uncertainty |

Cloning `budd`'s cache on Linux would add lifecycle safety but no enrollment
authority. The separate exact ACM/AKS path now provides a protocol-feasible
authority producer for the mapped Apple user; it does not require cloning
`budd`. Existing-user inventory is safe to expose read-only; deletion and
rename can eventually use their separately recovered authorization and
transaction gates. Enrollment must remain disabled until that path is
implemented non-mutating-first and then proves device acceptance under an
explicitly approved, journaled enrollment experiment.
New-user provisioning additionally requires the AKS identity/persona, keybag
alias, account UUID, and Catacomb namespace transactions described above.

### Mode-1 token producer search and match-authorized enrollment

A corpus-wide same-generation search found no concrete producer of either
ordinary enrollment token key, `BKOptionAuthWithAuthToken` or
`BKOptionEnrollWithAuthToken`. The parser accepts those keys, but acceptance is
not evidence that a current client generates them. Likewise, no client was
found converting a successful fingerprint match result into an enrollment
authorization token.

The one concrete BiometricKit mode-1 producer is deliberately different.
`PABSTouchIDPasscodeController` obtains `PSAuthorizationTokenForPasscode()` via
its superclass and supplies it under
`BKOptionMatchAuthTokenToBypassPasscodeBiolockout` when starting a highlight
match. This token authorizes a particular match/bio-lockout bypass path. It is
not placed under either enrollment key and is not handed to the enrollment UI.

The same current Settings client makes the contrast explicit when the user
chooses Add Fingerprint:

1. an optional stolen-device-protection ratchet gates operation number 5;
2. `authContext` creates an `LAContext`, sets the UI delegate, and evaluates
   policy `1007` using the passcode carried by the Settings specifier;
3. its event delegate supplies those passcode bytes as credential type `-1`;
4. the add-fingerprint path calls `externalizedContext`; and
5. it installs that data as enrollment-controller property `credset`.

Therefore the Settings authorization token used for match bypass and the LA
externalized credential set used for enrollment coexist in one client but are
not interchangeable. The optional ratchet is an additional UI/policy gate; it
does not replace the credential-set path. This also independently corroborates
the recovered macOS Settings and Setup Assistant behavior.

The mode-1 enrollment format must remain documented because it is statically
accepted and may serve private/legacy clients, but it is not presently a viable
Linux design path. In particular, Linux must not treat a successful match, a
passcode authorization token, or the 16-byte length alone as permission to
relabel bytes with an enrollment option key. Only a producer/consumer trace
showing intended enrollment use plus device-side binding/freshness semantics
could promote mode 1 from protocol capability to supported authorization.

Until those are recovered, a Linux implementation must not synthesize an empty
authorization, copy an externalized context between users or boots, or treat
possession of the macOS account password as sufficient enrollment authority.

## Linux-native management roadmap after host-credential recovery

Recovering the complete host type-`-5` handoff changes the order of work, but
not the mutation safety boundary. It eliminates the need to guess how macOS
packages the entered password and user ID. It does **not** make an externalized
LA context, ACM type-13 seed, policy-1007 decision, or SEP enrollment authority
available to Linux. The implementation roadmap must therefore remain split by
capability rather than presenting one generic `enroll`/`delete user` surface.

The recovered fallibility points require five separately journaled transaction
domains. They must not be collapsed into a single rollback promise:

| Domain | Commit evidence | Recoverable compensation | Outcome-unknown rule |
|---|---|---|---|
| Session/keybag activation | Expected `-UID` alias resolves to the expected live bag UUID and reports the required unlocked state | Lock; unload only a temporary handle or an alias created by this transaction | Re-read alias, UUID, and lock state; never retry password verification or `set_system` from the error alone |
| Enrollment authorization | Fresh policy-1007 context was created for the mapped subject, backend returned success, and the exact operation owns its external form | Invalidate/destroy the context and wipe every host copy; there is no safe way to “undo” a possibly accepted authorization | Discard it on timeout, reconnect, UID mismatch, process death, or uncertain consumption; never replay it |
| Biometric identity mutation | Terminal operation event and stable before/after identity inventory agree on the exact UID+identity UUID | Delete only a newly observed identity whose creation is unambiguous and separately authorized; otherwise leave state for recovery | If the event and inventory disagree, freeze mutation and reconcile; do not start another enrollment or deletion |
| Catacomb metadata/save | Prepare/save/confirm milestones complete and stable component UUID/hash/read-back matches the intended archive | Restore only from a verified preimage when the SEP transaction state proves restoration is admissible | A prepared or saved-but-unconfirmed transaction requires observation-led recovery, never blind confirm or file replacement |
| Account/persona/top-level identity provisioning | Kernel identity result, OD/APFS records, identity file, persona, bag/account UUID bindings, alias, and first Catacomb all reconcile | Compensate each artifact in reverse dependency order only when ownership by this operation is proven | Any selector-`0x76`, OD token, APFS record, identity-file, or rename ambiguity becomes `TOP_LEVEL_IDENTITY_CREATE_OUTCOME_UNKNOWN`; do not rerun Create/Add/Reset |

An end-user workflow may orchestrate several domains, but each domain retains
its own operation ID, preimage, irreversible milestone, read-back, and recovery
decision. “Enrollment failed” is therefore not a sufficient rollback trigger:
the authorization may have been consumed, a SEP identity may exist, and the
Catacomb save may be at a different milestone. Recovery first freezes all
mutation, reacquires the machine-wide lease, performs the stable double
inventory, and classifies each domain independently. Password login remains
the mandatory escape path throughout.

1. **Read-only identity inventory.** Enumerate explicit Apple numeric UIDs,
   identity UUIDs, template counts/free capacity, Catacomb/account/bag UUIDs,
   active alias state, and Linux mapping records. This is the prerequisite for
   every later operation and must work without unlocking unrelated users.
2. **Existing-user mapping and lifecycle.** Permit a root-authorized mapping
   from one Linux account to one already-provisioned Apple identity/keybag tuple.
   Unlock and alias activation remain session-scoped leases; logout, suspend,
   user switch, daemon restart, or T2 reconnect invalidates them. Multiple
   mapped users may coexist on disk, but concurrent active biometric subjects
   remain unsupported until SEP lookup timing and alias isolation are proved.
3. **Existing-user administration.** Add rename, single-identity deletion, and
   per-user delete-all only after read-back, backups, immutable target snapshots,
   per-component journaling, and a separate PolicyKit action for each operation
   class. A delete-all operation is a journaled loop, never an atomic primitive.
   Whole-user deprovisioning remains a distinct dependency-ordered workflow.
4. **Self-enrollment for an existing Apple user.** Reproduce a fresh
   subject-bound policy-1007 authorization only for the Apple UID mapped to the
   authenticated Linux session. macOS uses the temporary type-`-5` secure
   archive to carry `{UserId, Credential}` across its privileged UI/LA process
   boundary, then converts it to the type-`-1` AKS verification path. Linux does
   not need to emulate that interprocess archive when one privileged broker owns
   the secret from prompt through verification. Its minimal recovered path is:
   create the ACM context for the protected mapped Apple UID; export its 16-byte
   reference; pass the target password and that reference through endpoint-7
   selector-42 verification as the canonical codec-v1 session, handle, plain
   secret blob, ACM-context blob, and trailing option qword `0x200`;
   evaluate policy
   `TouchIdEnrollment`/1007 through endpoint 10; re-export the authorized
   context reference and place it in BiometricKit mode 0; then destroy the
   context and wipe host buffers on every exit. Exact 24G830 ACMLib evidence
   plus the running 25B77 AppleKeyStore kext have closed purpose, numeric-UID
   subject binding, command framing,
   host audit boundary, and default freshness; type-13 seed internals are not
   required by this active path. Exposure still waits for the privileged broker,
   strict context lifetime, archive/journal gates, and a controlled validation
   of final T2 mode-0 consumption/replay behavior.
5. **Linux-only user provisioning.** Treat top-level AKS identity creation,
   persona creation, account UUID and keybag binding, numeric alias creation,
   first Catacomb commit, and first enrollment as separate fallible milestones.
   This may not be exposed through fprintd enrollment until restart recovery is
   proven for every partial state. Password equality between Linux and macOS is
   convenient input, not evidence that these Apple-side records already exist.
6. **Deprovisioning.** Remove biometric identities first, then Catacomb/account
   material, persona, alias/keybag mappings, APFS protection records, and finally
   the top-level AKS identity, with inventory reconciliation after each stage.
   No missing file is sufficient proof that a deeper record was removed.

The resulting Linux API should expose the Apple subject explicitly. A request
must carry a stable mapping identifier and resolve it to immutable Apple UID,
account UUID, bag UUID, and Catacomb UUID values before authorization. The
caller may never supply an arbitrary raw UID as a substitute for that mapping.
Authorization objects are single-operation, boot/session-scoped secrets keyed
to that resolved subject and are wiped on mismatch, cancellation, timeout,
reconnect, suspend, or any ambiguous completion.

## Safety boundary for future experiments

Before any mutating probe, require all of the following:

1. A verified restorable backup of every relevant Catacomb/keybag component.
2. A disposable enrolled identity or test user, never the sole working finger.
3. Exact statically recovered request and event structures.
4. Read-only before/after commands for identity lists, counts, validity, and
   Catacomb state.
5. A macOS recovery path and proof that password login remains available.
6. One-command cancellation and a power-loss/reboot recovery plan.
7. Explicit user approval for the exact mutating command and target identity.

## Next research steps

### Remaining-unknown classification

The unresolved items do not all have equal weight:

- **Required before any mutation implementation:** independent captured-fixture
  read-back for the strict known-schema archive encoder; a privileged broker
  above the endpoint-10 transport that binds the Linux session and PolicyKit
  decision to the protected Apple-user mapping; a stable non-mutating
  cross-layer identity inventory; a per-component intent/result journal; and
  explicit approval for the exact target and operation. The staged kernel
  transport now supplies the lower-level single-owner context lease,
  process-exit cleanup, and generation-safe late-reply rejection, but those new
  guarantees still require activation and live conformance on the next module
  boot.
- **Requires controlled device validation:** the final T2 consumer's replay,
  one-shot, expiry, and ambiguous-completion treatment of a mode-0 ACM external
  form. The J132 SEP payload is device-key-wrapped, so the plaintext host corpus
  cannot settle this. This is the only remaining enrollment-authority question
  that directly requires hardware observation.
- **Conservative invariant is sufficient:** whether SEP snapshots the UID/bag
  association at enrollment start or re-evaluates it later. Holding one verified
  UID/keybag/ACM/Catacomb lease through terminal confirmation is safe under
  either behavior, so static resolution is useful but not an implementation
  prerequisite.
- **Optional/non-blocking reverse engineering:** mode-1 token production,
  context-data type-13 seed generation details, the command-`0x0e` enrollment-
  state producer, generic type-2 credential serializer internals, and any
  duplicate-specific cause discarded behind generic status 67. None is needed
  for the recovered normal mode-0 enrollment path or conservative result
  mapping.
- **Deliberately disabled scope:** creating new top-level AppleKeyStore users
  from Linux. Selector `0x76` and the surrounding OD/APFS/identity/persona steps
  do not form an atomic transaction with proven compensation; ambiguous failure
  remains `TOP_LEVEL_IDENTITY_CREATE_OUTCOME_UNKNOWN`. Whole-biometric-user
  removal with `0x48` is also disabled: the recovered identity queries prove an
  empty identity set but do not yet distinguish an empty container from an
  absent container, so terminal container deletion cannot be verified.

Accordingly, further broad binary searching has sharply diminishing value. The
next evidence-producing work should be the read-only inventory and strict
archive compatibility tests; final ACM consumption belongs in a separately
approved disposable-finger hardware experiment.

- Join the now-recovered policy-1007 backend decision to its final secure-
  biometry consumer. The host rule is no longer unknown: `TouchIdEnrollment`
  evaluates the exact passcode/no-passcode `KofN(1,2)` requirement, requires a
  live credential set, and sets enrollment-authority flag `0x0002`; the exact
  24G830 helper supplies the per-user MKB/ACM authorization first. What remains
  is how the T2 consumer validates the directly copied mode-0 externalized
  credential set and its enrollment-authority property, including replay,
  one-shot, expiry, cancellation, and ambiguous-completion behavior. Exact
  24G830 host code rules out a mode-0-to-mode-1 transformation.
- Recover ACM context-data type `13` generation, size, rotation, and
  external-form reconstruction behavior. It is now proven to be the
  backend-provided credential-encoding seed, distinct from explicitly settable
  16-byte credentials UUID data type `10`.
- Complete the remaining ACMLib response and lifecycle contracts around the
  now-exact authorization sequence. Context create/import/export/destroy,
  command-3 request framing, selector-42 password/context framing, the 24G830
  OD/PAM/MKB cascade, and UID-to-handle mapping are recovered. The kernel now
  restricts endpoint 10 to one open owner and one exact live context, deletes
  that context on owner exit, and makes timeout/ambiguous-create generations
  terminal until reboot. The outstanding host work is complete ACM response
  serialization, a dedicated PolicyKit action above that kernel lease, and the
  final consumer's handling of the credential-set authorization bit. The
  current research wrapper already rejects direct-root and cross-user callers:
  its sudo/pkexec origin must match the Linux account in the protected mapping,
  and the Apple UID is never accepted from the caller. Endpoint-10 correlation
  and the host-versus-SEP subject boundary are exact.
- The endpoint-10 registration, ordinary single-flight correlation, SCRD
  request-ID exception, timeout, and reset/re-registration contracts are now
  exact. The staged Linux driver now represents each registration as a nonzero
  generation, rejects stale generations, prevents multiple owners/contexts,
  and permanently poisons the current generation after a timeout, excess
  unrelated replies, or a successful create whose context handle is too short
  to clean up. This conservative implementation awaits live validation after
  the next normal reboot. It remains a separate privileged transport and does
  not widen the endpoint-7 `/dev/aks` interface.
- Turn the now-recovered endpoint-10/ACM policy-1007 issuance sequence into a
  future read-only-capable broker design: create `0x24`/fallback `1` for the
  authenticated Apple numeric UID, export the 16-byte reference, bind it through
  endpoint-7 selector-42 verify-secret with the canonical raw-secret/context
  codec-v1 body, retry command `3` for
  `TouchIdEnrollment`, and destroy on every failure or uncertain handoff. The
  remaining static uncertainty is the T2 biometric consumer's replay/one-shot
  semantics for the resulting mode-0 externalized credential set. A mode-1
  producer is optional historical/API research, not a blocker for this path.
- Recover the initial producer/store call for Setup Assistant's cached biometric
  `LAContext`; `budd` is now proven to be only an entitlement-gated cache.
- Treat producer-side decomposition of generic enrollment failure 67 as
  optional firmware research, not an API blocker. Exact 24G830 BiometricKit and
  BiometricKitUI prove that the host transports no duplicate subtype and has no
  duplicate terminal result. The encrypted J132 SEP image is preserved, but its
  device-wrapped KBAG prevents static inspection; Linux must map 67 to generic
  failure regardless of any finer cause discarded inside SEP.
- Complete the now-exact matching-macOS Catacomb writer proof. The 24G830
  `prepare/`/`commit/` transaction, `F_FULLFSYNC` points, forward recovery,
  per-file mixed-generation crash window, and server lock scope are recovered.
  For Linux-local persistence, the remaining gate is a strict known-schema
  keyed-archive encoder plus independent read-back; APFS protection/xattrs are
  not serialized protocol inputs. Inherited APFS metadata remains a separate
  gate only for later synchronization back into macOS `/Library/Catacomb`.
- Join the now-recovered OpenDirectory membership UUID, top-level AKS identity
  UUID, bag UUID, numeric UID alias, and Catacomb UUID namespaces using a
  read-only inventory. Do not infer equality merely from matching width.
- Treat matching SEP firmware analysis of Catacomb/keybag lookup timing as an
  optional proof-strengthening task; meanwhile retain the conservative
  operation-wide UID lease that is safe under either timing model.
- Do not implement enrollment or deletion until the non-mutating inventory,
  per-component journal, writer compatibility, and explicit mutation approval
  gates are all satisfied.

## Evidence-coverage audit (2026-08-28)

This audit treats every objective domain independently and does not promote a
plausible design to a proven result:

| Domain | Strongest current evidence | Static-research disposition | Evidence still required |
|---|---|---|---|
| Existing-user enrollment wire protocol | Exact 24G830 command `0x03`, mode-0 authorization wrapper, continue/status/result events, exact target host frameworks | Host side complete enough for a protocol design | Controlled disposable-finger validation of final T2 acceptance, replay/one-shot behavior, and ambiguous completion |
| Enrollment authorization producer | Exact UID-bound ACM create/export/destroy, endpoint-7 raw-versus-structured credential distinction, policy-1007 command/reply, no Mach audit data crossing endpoint 10; staged one-owner/one-context kernel lease with exit cleanup and poisoned generations | Protocol-feasible in outline; live password-binding and new lease validation remain in progress | Linux-session/PolicyKit broker conformance tests, followed by the same controlled T2 validation |
| Enrollment event flow | Exact envelope/status mappings, progress/continue range, terminal identity record, cancellation and conservative fprintd mappings | Static mapping complete for built-in enrollment; duplicate-specific reporting intentionally unavailable | Hardware traces only to validate timing/repetition behavior, not to invent unsupported result classes |
| Single and per-user identity deletion | Exact `0x0d` target, Apple loop ordering, Catacomb-save failure windows, nil credential options | Protocol and non-atomic outcome model recovered | Future explicitly approved deletion test with before/after stable inventory; no static blocker remains |
| Whole biometric-user removal | Exact `0x48` request and host cleanup ordering | Destructive command known, terminal proof incomplete; disabled | An explicit container-presence primitive or validated equivalent that distinguishes empty from absent |
| Multi-user existing-account mapping | Exact numeric UID, ODUUID, bag UUID, alias, Catacomb, ACM subject joins; captured UID-501 tuple; serialized lease model | Multiple stored mappings and serialized per-user operations are protocol-feasible | Read-only multi-user inventory fixtures; optional selector-`0x61` capture to join UserPersona unique string to AKS persona UUID |
| Linux-only Apple user provisioning | Exact top-level identity/persona request surfaces and non-atomic OD/APFS/file/registry milestones | Unsafe by construction with current evidence; disabled | A complete compensating protocol proven by disposable-volume fault injection, not a live-user experiment |
| Catacomb archive semantics | Exact version-3 keys/classes, observed graphs, secure-decoder types, 24G830 writer and recovery code | Semantic codec specification complete; byte-identical Foundation output not required | Raw read-only master/user/biolockout fixtures for executable independent round-trip tests |
| Catacomb transaction/rollback | Exact prepare/complete/stage/commit/confirm ordering, per-file forward recovery, fsync points and mixed-generation windows | Recovery direction and journaling invariants statically complete | Offline crash-injection tests on copied fixtures; later controlled device reconciliation |
| macOS resynchronization | Exact serialized schema; APFS attributes shown not to be SEP inputs | Separate from Linux-local persistence and not needed for its codec | macOS decoder-only fixture acceptance plus destination xattr/protection preservation if cross-OS copying is pursued |
| Suspend/reconnect | Observed RemoteXPC loss plus exact endpoint/OOL reset behavior | Transparent resume is unsupported; cancel, invalidate, reconnect, and inventory is the safe contract | Hardware validation of the conservative lifecycle, not session continuation |

No current conclusion depends on decrypting the device-wrapped J132 SEP image.
A legitimate plaintext image could answer optional internal questions, but the
only blocking fact it might replace is final mode-0 consumer behavior, which a
controlled hardware experiment can test more directly. Likewise, more broad
searches for mode-1 producers, type-13 seed generation, duplicate internals, or
the unused enrollment-state command cannot close the codec fixture, container-
presence, or device-acceptance gates.

The static corpus is therefore exhausted for the present safety-critical
questions. Further evidence-producing work requires at least one external state
change or artifact: supply exact read-only `.cat` fixtures; capture the optional
read-only multi-user/persona inventories on macOS; recover a container-presence
query; or explicitly authorize a disposable-finger T2 experiment after the
non-mutating broker and journal exist. Until one of those occurs, additional
static prose refinement is not progress toward the remaining unknowns.

## Research conclusion (2026-08-28)

| Capability | Evidence status | Feasibility decision |
|---|---|---|
| Inventory existing SEP identities | Request/reply and user/UUID scope known | Safe candidate for read-only implementation |
| Enroll for the currently provisioned Apple user | Start/continue/result and request structures known; the version-qualified macOS password UI, `{UserId, Credential}` secure archive, temporary type-`-5` slot, entitled extraction, type-`-1` conversion, and cleanup are joined; 24G830 ACMLib plus the running 25B77 AppleKeyStore kext confirm UID-bound context create, externalization, endpoint-7 session/handle framing and its raw-versus-structured secret distinction, command-3 `TouchIdEnrollment` evaluation, and endpoint-10 transport; BiometricSupport copies the resulting externalized credential set directly into mode 0 | Protocol-feasible in outline without forging macOS audit state. Live password-binding/policy validation, a root/PolicyKit broker, strict context lifetime, final T2 replay/one-shot validation, durable save verification, and the recovery journal remain mandatory before exposure |
| Delete one existing identity | Exact `userID + UUID` command known; standard Apple client sends nil options and relies on identity-management privilege; exact 24G830 Catacomb staging/promotion/recovery and typed archive schema are recovered | Technically feasible for Linux-local storage after a strict encoder, backup, independent read-back, explicit PolicyKit administration, and non-atomic failure reporting; APFS metadata is only a later macOS-resynchronization concern, and no enrollment credential ceremony is required |
| Delete all prints of one Apple user | Exact 24G830 server loops SEP-remove plus host-object-remove for each target identity, aborts on the first command error, and saves Catacomb only once after the loop; neither a mid-loop failure nor final save failure reverses earlier SEP deletions | Feasible only as a separately confirmed, per-UUID journaled administrative batch with partial-completion reporting; never claim atomicity |
| Rename/label a finger | Host identity metadata, exact keyed-archive graph, and Catacomb resave path known; standard Apple client sends nil options | Feasible for the Linux-local store after the strict encoder and explicit identity-management policy exist; label is not stored in the SEP template identity |
| Map several Linux users to existing macOS users | Exact macOS code resolves `CatacombUserUUID` from the OpenDirectory Users record matching numeric `UniqueID`, resolves `CatacombUserKeybagUUID` from `aks_get_bag_uuid(-UID)`, and binds ACM context create to the Apple numeric UID; endpoint-7 verification selects that user's `-UID` keybag | Protocol-feasible for separately authenticated mapped users when every protected mapping reconciles Linux identity, Apple UID, OD GUID, negative bag alias, live bag UUID, and Catacomb component. The broker must choose the Apple UID from its protected mapping, never from an untrusted caller; delegated cross-user administration needs a stronger PolicyKit action than self-service |
| Create a new Linux-only biometric user | Exact macOS AKS framework exposes separate top-level identity and persona-in-existing-bag operations. Request 10 reaches kernel selector `0x76` before independently fallible OpenDirectory access-token, APFS VEK/user-protection, identity-file, and rename milestones; its visible error exit does not establish complete rollback. Persona mutation separately requires root+device capability on macOS and has its own partial-failure window. Exact 24G830 BiometricSupport proves that a valid OpenDirectory Users record plus installed `-UID` bag alias are live inputs. Enrollment authority itself is now recovered, but it cannot replace those missing durable prerequisites | Not currently feasible; must remain disabled. Any future attempt is a cross-layer provisioning transaction with `TOP_LEVEL_IDENTITY_CREATE_OUTCOME_UNKNOWN` recovery, never an fprintd enrollment feature or safely retryable one-shot command |
| Survive suspend during enrollment | RemoteXPC transport is known not to recover | Not feasible transparently; cancel before suspend and reconcile after reconnect |
| Atomic enrollment/deletion rollback | Apple confirms earlier SEP components before final host-file commit, masks enrollment save failure, and may delete all host Catacombs on error 269; exact host recovery discards `prepare/` but rolls `commit/` forward per file | Not available; compensate with per-component journaling, backups, read-back, and explicit degraded states |

The project therefore remains two milestones. Existing, already-provisioned
Apple/SEP user management is technically credible after a read-only inventory
and transaction/recovery layer. Linux-native user provisioning is a separate
AppleKeyStore/account-management research project and is not established.

The next safe engineering task, if approved later, is a non-mutating
`t2-touchid identities` inventory command that reports SEP user IDs, identity
UUIDs, free slots, and the Linux mapping state. It should make no attempt to
name, enroll, delete, or repair records. That inventory would establish the
ground truth needed for subsequent protocol work without risking the working
fingerprint setup.

## Sources

- Local primary evidence: the matching Apple `biometrickitd` executable and
  its disassembly under `apple-artifacts/` (addresses cited above).
- Local primary evidence: exact 24G830 `BiometricSupport` extracted from the
  reconstructed System dyld cache with `ipsw dyld extract --objc --stubs`
  (reproducible extracted-file SHA-256
  `f2a6137800b819c6b958eec6082cb4ff38aa8fb08e58e2cf054df889629c9a8b`),
  used for the modern `BKCatacomb` staged writer, forward recovery, durability
  calls, and `BiometricKitXPCServer` save lock/order.
- Local primary evidence: extracted bridgeOS `LocalAuthenticationCore`
  (`apple-artifacts/bridgeos-cache-extracted/LocalAuthenticationCore`, SHA-256
  `fd37bb97e7c70d7362cb405a9896c495ba8b9744bd7ff79afd52d42ce7053abc`), used
  for the ACMLib policy serializer, result/requirement envelope, requirement
  allocator jump table, and semantic type mapping.
- Local primary evidence: 24G830 Intel AppleCredentialManager kext
  (`apple-artifacts/kexts/com.apple.driver.AppleCredentialManager`, SHA-256
  `34870e0c630c56a8092ee1e9b147c45d39b167437cd76d65b7025440d5d990f2`),
  used for the exact `TouchIdEnrollment` policy branch,
  `VerifyPolicyPasscodeOptional` requirement tree, credential-set authorization
  flag, credential-provider stubs, environment provider, and endpoint-10
  transport lifecycle.
- Local primary evidence: AppleKeyStore extracted from the manifest-verified
  Boot Kernel Collection collected from the running macOS 26.1 build 25B77
  system (Mach-O UUID `014567BF-63F6-3391-A782-AF69FE030A04`, SHA-256
  `af311e668b7480c699e7ba98a5402aa544e668e4211dcc51d806af445135e76c`),
  used for the operation-`0x21` session/handle order, `keybag_for_handle`
  ownership checks, and raw-versus-structured verify-secret option paths. The Apple
  binary and full kernel collection are private local research artifacts and
  are not redistributed by this repository.
- Local primary evidence: manifest-verified CodeDirectory metadata and process
  snapshot collected from the same running 25B77 installation for `coreauthd`,
  `authd`, `LocalAuthenticationRemoteService`, `applekeystored`, and
  `biometrickitd`. The public repository retains only the resulting hashes and
  conclusions; the captured Apple executables remain private.
- Same-generation ModuleACM decompilation used to corroborate the preflight ->
  mechanism -> retry flow, policy-1007 parameter omission, and option-derived
  maximum-global-credential-age input:
  https://github.com/EthanArbuckle/iPhone18-3_26.1_23B85_Restore/blob/main/System/Library/Frameworks/LocalAuthentication.framework/Support/ModulePlugins/ModuleACM.bundle/ModuleACM/ContextPluginACM.mm
- Same-generation requirement resolver and passcode mechanism used to recover
  the explicit `UserId`/audit-token subject join and biometric identity-UUID
  requirement properties:
  https://github.com/EthanArbuckle/iPhone18-3_26.1_23B85_Restore/blob/main/System/Library/Frameworks/LocalAuthentication.framework/Support/ModulePlugins/ModuleACM.bundle/ModuleACM/MechanismManagerACM.mm
  and
  https://github.com/EthanArbuckle/iPhone18-3_26.1_23B85_Restore/blob/main/System/Library/Frameworks/LocalAuthentication.framework/Support/MechanismPlugins/MechPasscode.bundle/MechPasscode/MechPasscode.mm
- Same-generation `LACACMHelper` used to recover ACM context-data modification
  timestamps and the SEP-time-since-boot freshness clock:
  https://github.com/EthanArbuckle/iPhone18-3_26.1_23B85_Restore/blob/main/System/Library/PrivateFrameworks/LocalAuthenticationCore.framework/LocalAuthenticationCore/LACACMHelper.mm
- Same-generation Apple-framework decompilation used for the exported-object
  permission map:
  https://github.com/EthanArbuckle/iPhone18-3_26.1_23B85_Restore/blob/main/System/Library/PrivateFrameworks/BiometricSupport.framework/BiometricSupport/BiometricKitXPCExportedObject.mm
- Same-generation `BiometricKitXPCServer` used to separate Darwin enrollment
  notifications and Catacomb reconciliation from ACM command `0x0e`:
  https://github.com/EthanArbuckle/iPhone18-3_26.1_23B85_Restore/blob/main/System/Library/PrivateFrameworks/BiometricSupport.framework/BiometricSupport/BiometricKitXPCServer.mm
- Independent iOS 18.2 cross-check of the fail-open permission dispatcher:
  https://github.com/EthanArbuckle/iPhone17-1_18.2_22C152_Restore/blob/main/System/Library/PrivateFrameworks/BiometricSupport.framework/BiometricKitXPCExportedObject.m
- Same-generation iOS 26.1 BiometricKitUI enrollment-controller decompilation
  used to corroborate `credset`, `userid`, refresh, result, and cancellation
  flow:
  https://github.com/EthanArbuckle/iPhone18-3_26.1_23B85_Restore/blob/main/System/Library/PrivateFrameworks/BiometricKitUI.framework/BiometricKitUI/BKUIFingerprintEnrollViewController.mm
- Same-generation iOS 26.1 Setup Assistant enrollment-client decompilation
  used to recover the concrete `generateAuthToken` implementation, LA context
  refresh, and cached-passcode authorization path:
  https://github.com/EthanArbuckle/iPhone18-3_26.1_23B85_Restore/blob/main/Applications/Setup.app/BuddyMesaEnrollmentController.mm
- Same-generation Passcode & Biometrics Settings controllers used to distinguish
  the passcode authorization token used for match-biolockout bypass from the LA
  externalized credential set used for Add Fingerprint:
  https://github.com/EthanArbuckle/iPhone18-3_26.1_23B85_Restore/blob/main/System/Library/PrivateFrameworks/PasscodeAndBiometricsSettings.framework/PasscodeAndBiometricsSettings/PABSBiometricController.mm
  and
  https://github.com/EthanArbuckle/iPhone18-3_26.1_23B85_Restore/blob/main/System/Library/PrivateFrameworks/PasscodeAndBiometricsSettings.framework/PasscodeAndBiometricsSettings/PABSTouchIDPasscodeController.mm
- Same-generation Setup Assistant client/server wrappers used to establish that
  `budd` stores and returns an existing context rather than minting one:
  https://github.com/EthanArbuckle/iPhone18-3_26.1_23B85_Restore/blob/main/System/Library/PrivateFrameworks/SetupAssistant.framework/SetupAssistant/BYBuddyDaemonGeneralClient.mm
  and
  https://github.com/EthanArbuckle/iPhone18-3_26.1_23B85_Restore/blob/main/System/Library/PrivateFrameworks/SetupAssistant.framework/SetupAssistant/BYDaemonGeneralClientConnection.mm
- Same-generation `budd` context lifecycle and connection-manager
  decompilations used for timeout/invalidation and the private entitlement gate:
  https://github.com/EthanArbuckle/iPhone18-3_26.1_23B85_Restore/blob/main/System/Library/PrivateFrameworks/SetupAssistant.framework/SetupAssistant/BYDaemonContext.mm
  and
  https://github.com/EthanArbuckle/iPhone18-3_26.1_23B85_Restore/blob/main/System/Library/PrivateFrameworks/SetupAssistant.framework/SetupAssistant/BYDaemonConnectionManager.mm
- Same-generation iOS 26.1 BiometricKit operation decompilation used to join
  `setCredentialSet:` to `BKOptionAuthWithCredentialSet`:
  https://github.com/EthanArbuckle/iPhone18-3_26.1_23B85_Restore/blob/main/System/Library/PrivateFrameworks/BiometricKit.framework/BiometricKit/BKEnrollOperation.mm
- Same-generation iOS 26.1 BiometricKit device wrapper used to confirm that
  protected-configuration calls also transport target UID and credential set
  as separate host-side inputs:
  https://github.com/EthanArbuckle/iPhone18-3_26.1_23B85_Restore/blob/main/System/Library/PrivateFrameworks/BiometricKit.framework/BiometricKit/BKDevice.mm
- Same-generation iOS 26.1 `LACPasscodeHelper` decompilation used only as a
  platform-divergence cross-check for `_keybagHandleForUserId:` (the macOS
  mapping above comes from the local macOS dyld-cache disassembly):
  https://github.com/EthanArbuckle/iPhone18-3_26.1_23B85_Restore/blob/main/System/Library/PrivateFrameworks/LocalAuthenticationCore.framework/LocalAuthenticationCore/LACPasscodeHelper.mm
- macOS 15.3.2-to-15.4 framework diffs used to establish the migration of the
  macOS `LAPasscodeHelper`, its MobileKeyBag imports, and its per-user resolver
  from `SharedUtils` to `LocalAuthenticationCore`:
  https://github.com/blacktop/ipsw-diffs/blob/main/15_3_2_24D81__vs_15_4_24E248/DYLIBS/SharedUtils.md
  and
  https://github.com/blacktop/ipsw-diffs/blob/main/15_3_2_24D81__vs_15_4_24E248/DYLIBS/LocalAuthenticationCore.md
- Local static evidence: macOS 14.4 (`23E214`) Cryptex System image
  `apple-artifacts/macos-14.4-23E214/096-17269-293.dmg` (SHA-256
  `6e63acf69f2be84a04f2cee56f73d94339c0e600bbffc4ed19a588b243044645`)
  and its extracted x86_64 `SharedUtils` image (UUID and hash cited above).
- fprintd's official D-Bus API documentation:
  https://fprint.freedesktop.org/fprintd-dev/Device.html
- libfprint's official device/enrollment documentation:
  https://fprint.freedesktop.org/libfprint-dev/FpDevice.html
- libfprint's official on-device print representation:
  https://fprint.freedesktop.org/libfprint-dev/FpPrint.html
