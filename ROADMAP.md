# Reliability roadmap

This checklist tracks the work required to turn the machine-specific proof of
concept into a reproducible experimental driver stack. Status reflects checked
evidence, not intent.

## 1. Accurate support claims

- [x] Document cold-boot sudo authentication as verified.
- [x] Stop claiming a first Omarchy lock screen exists on every installation.
- [x] Test an explicit `omarchy system lock` Touch ID flow before claiming
      lock-screen support.

## 2. Diagnostics

- [x] Add a privacy-safe `t2-touchid-doctor` human report.
- [x] Add machine-readable JSON output.
- [x] Run the installed doctor as root on the proven machine.

## 3. fprintd lifecycle

- [x] Bound stale claims and recover abandoned/completed transactions.
- [x] Add contention, cancellation, stale-claim, and timeout tests.
- [x] Reduce completed-claim retention after observed repeat-scan contention.

## 4. Configurable identity

- [x] Replace hardcoded macOS user ID 501.
- [x] Replace hardcoded special bag -501.
- [x] Replace hardcoded right-index finger metadata.
- [x] Validate all identity-related configuration fail-closed.

## 5. BridgeXPC port cache

- [x] Cache only a port that passed a BiometricKit warm-up.
- [x] Write the cache atomically.
- [x] Invalidate and rediscover after a cached endpoint fails.
- [ ] Test bridgeOS restart and port-change behavior.

## 6. Installation and rollback

- [x] Make install/update operations explicitly idempotent.
- [x] Add an uninstall command that preserves private user data by default.
- [x] Add PAM backup and rollback helpers.
- [x] Add an optional DKMS kernel-upgrade rebuild workflow.
- [x] Build, sign, and install the DKMS module for the proven running kernel.

## 7. Suspend/resume

- [x] Document the reproduced deep-S3 failure and failed live resets.
- [x] Add a privacy-safe suspend diagnostic bundle.
- [x] Prepare an upstream-ready t2bce report with exact reproduction evidence.
- [x] Fail closed unless live enrollment holds a verified sleep inhibitor.
- [x] Recheck the inhibitor inside the authorized consumer immediately before
      the first enrollment dispatch and durably abort if it was lost.
- [ ] Validate any kernel fix or alternative sleep mode on the proven machine.

## 8. Security, tests, and releases

- [x] Document threat models for PAM and host-key encrypted credentials.
- [x] Add malformed SEP/BridgeXPC response tests.
- [x] Enable GitHub Actions CI across Python 3.12 and 3.14 with pinned actions,
      unit tests, shell checks, userspace build, and both privacy scans.
- [x] Produce an experimental `v0.1.0` release checklist.

## 9. Linux identity management

- [x] List truthful reconciled labels without exposing biometric identifiers.
- [x] Resolve ephemeral management slots only against a fresh stable inventory.
- [x] Journal and persist a label-only rename with independent read-back.
- [x] Recover interrupted rename transactions without replaying SEP mutation.
- [x] Require a different boot and Bridge generation before closing a rename.
- [x] Implement journaled reconciled single-identity deletion and interruption
      recovery behind explicit acknowledgements.
- [x] Add a non-mutating live deletion-target preflight.
- [x] Promote the live-proven enrollment broker behind a stable subcommand UX.
- [x] Add a private, versioned multi-user mapping schema with one-to-one Apple
      authority and explicit per-target capabilities.
- [x] Add a transport-free per-user binding/alias/lock-state readiness
      classifier with explicit quarantine and password-bootstrap outcomes.
- [x] Add a typed runtime alias-activation journal and dependency-injected
      load/bind/unlock operation core with secret wiping and no retry.
- [x] Add fresh-generation, read-only activation recovery that never retries
      mutations or guesses how to clean up an unknown temporary handle.
- [x] Recover and implement exact read-only endpoint-7 bag-UUID operation
      `0x06`, strict keybag-state decoding, and stable double-read observation.
- [x] Compose the observer with the existing load/bind/unlock commands through
      a non-exposed adapter that pipes and never logs password bytes.
- [x] Add a non-exposed self-service policy resolver that binds distinct
      verify/inventory/enroll/identity-management and activation decisions to
      caller, target, mapping generation, operation, boot, exact Bridge runtime
      generation, and bounded time.
- [x] Require the exact policy binding in the activation core and reuse its
      operation UUID in the durable activation journal; reject reconnects and
      expired grants before the first AKS observation or mutation.
- [x] Add a race-resistant PolicyKit grant producer using the exact
      `PID,start-time,UID` subject, post-check PID-reuse detection, bounded
      grants, and installed distinct action definitions.
- [x] Add connected-Unix-peer collection with `SO_PEERPIDFD`, libsystemd pidfd
      session resolution, strict active/local/seat policy, stable fallback for
      user-manager apps, and post-PolicyKit session revalidation.
- [x] Join the pinned peer, mapping writer lock, biometric operation lock,
      stable live evidence, runtime generation, policy grants, and synchronous
      consumer handoff in one non-exposed self-service broker transaction.
- [x] Add strict identifier-free `SOCK_SEQPACKET` framing and a non-mutating
      preflight consumer that cannot collect activation authority.
- [x] Join the first operation-specific read-only identity inventory consumer
      to the exact stable broker snapshot without exposing a listener.
- [x] Add a strict one-request dispatcher for `preflight` and the exact
      `identities/inventory` pair, with no mutation command or fallback.
- [x] Add a non-installed libsystemd `Accept=yes` adapter that validates and
      owns exactly one connected Unix seqpacket descriptor per process.
- [x] Add a non-exposed one-exchange client core with bounded response framing
      and exact request/response command binding.
- [x] Add verified, disabled-by-construction candidate systemd units and a
      fixed read-only entry point without installing or enabling them.
- [x] Add one redacted non-mutating broker-exposure diagnostic that keeps the
      reconciled T2 identity count distinct from fprintd's compatibility alias.
- [x] Add a live local-files account-generation assertion over the exact
      UID/passwd/shadow/database/home binding and revalidate it after PolicyKit.
- [x] Add atomic administrator creation/rebinding for protected account
      generations; both transitions force disabled and never auto-accept drift.
- [x] Add a separate atomic live Apple/AKS/Catacomb reconciliation transaction
      before a disabled mapping may be enabled; its live session is read-only.
- [x] Add unconditional atomic administrator revocation that never depends on
      live T2, Bridge, Catacomb, account, or keybag availability.
- [x] Validate the operation-`0x19` state decoder against live Apple key order
      and bind its private account UUID into alias readiness evidence.
- [x] Validate operation `0x06` and the read-only alias observer on hardware
      after loading the rebuilt pinned module at reboot.
- [x] Verify after reboot that the pre-existing and Linux-enrolled fingerprints
      independently match while fprintd truthfully exposes one compatibility
      alias for the configured Apple user.
- [ ] Perform the first live single-identity deletion and post-reboot survivor
      verification on the proven machine.
- [ ] Replace the verification-only fprintd compatibility alias with truthful
      per-identity listing derived from fresh reconciled T2 inventory.
- [ ] Implement fprintd-native enrollment and deletion through the journaled,
      explicit-target Linux mutation brokers; never treat a D-Bus finger label
      as biometric authority.
- [ ] Support mapped Linux users through the same caller/session/PolicyKit and
      protected Apple-user authority model, including negative cross-user tests.
- [ ] Validate the complete fprint client experience—list, enroll, verify,
      delete, cancellation, contention, PAM, and desktop UI—without requiring
      repository-specific commands for ordinary use.

## Hardware/root-only gates

These require an interactive user or a reboot and cannot be inferred from unit
tests:

- Suspend/resume testing.
- Kernel upgrade/rebuild testing.
