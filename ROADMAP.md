# Reliability roadmap

This checklist tracks the work required to turn the machine-specific proof of
concept into a reproducible experimental driver stack. Status reflects checked
evidence, not intent.

## 1. Accurate support claims

- [x] Document cold-boot sudo authentication as verified.
- [x] Stop claiming a first Omarchy lock screen exists on every installation.
- [ ] Test an explicit `omarchy system lock` flow before claiming lock-screen
      support.

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

## 7. Suspend/resume

- [x] Document the reproduced deep-S3 failure and failed live resets.
- [x] Add a privacy-safe suspend diagnostic bundle.
- [x] Prepare an upstream-ready t2bce report with exact reproduction evidence.
- [ ] Validate any kernel fix or alternative sleep mode on the proven machine.

## 8. Security, tests, and releases

- [x] Document threat models for PAM and host-key encrypted credentials.
- [x] Add malformed SEP/BridgeXPC response tests.
- [ ] Enable the prepared GitHub Actions CI template (requires a GitHub token
      with `workflow` scope).
- [x] Produce an experimental `v0.1.0` release checklist.

## Hardware/root-only gates

These require an interactive user or a reboot and cannot be inferred from unit
tests:

- Explicit Omarchy lock/unlock positive and negative controls.
- Cold boot after any service-order or credential changes.
- Suspend/resume testing.
- Kernel upgrade/rebuild testing.
