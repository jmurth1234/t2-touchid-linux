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
      caller, target, mapping generation, operation, boot, and bounded time.
- [x] Require the exact policy binding in the activation core and reuse its
      operation UUID in the durable activation journal.
- [ ] Validate operation `0x06` and the read-only alias observer on hardware
      after loading the rebuilt pinned module at reboot.
- [ ] Perform the first live single-identity deletion and post-reboot survivor
      verification on the proven machine.
- [ ] Implement Linux-native enrollment/unenrollment policy for multiple users.

## Hardware/root-only gates

These require an interactive user or a reboot and cannot be inferred from unit
tests:

- Suspend/resume testing.
- Kernel upgrade/rebuild testing.
