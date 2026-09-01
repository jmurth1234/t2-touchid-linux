# Experimental release checklist

## Automated gates

- [ ] CI passes Python compilation and unit tests.
- [ ] ShellCheck passes all installed and helper scripts.
- [ ] `t2-aks-tool` builds without warnings.
- [ ] Privacy scan finds no private artifacts or stable identifiers.
- [ ] Fresh installation and repeated installation both complete.
- [ ] Uninstall preserves private data; explicit purge removes it.
- [x] DKMS builds, signs, and installs the module for the proven running kernel.
- [ ] DKMS automatically rebuilds for a newly installed kernel.

## Proven-machine gates

- [ ] Root doctor has no unexpected failures.
- [ ] Enrolled and unenrolled fingers pass raw BridgeXPC controls.
- [x] Every enrolled finger and one unenrolled finger pass explicit
  `fprintd-verify -f any "$USER"` controls; each enrolled finger also passes
  its named `fprintd-verify -f FINGER-NAME "$USER"` control.
- [ ] Enrolled and unenrolled fingers pass sudo/PAM controls.
- [x] `omarchy system lock` accepts the enrolled fingerprint.
- [x] `omarchy system lock` rejects a wrong finger and retains password fallback.
- [x] Cold boot with encrypted credential passes on the proven machine.
- [ ] Kernel upgrade rebuild/install passes.
- [ ] Suspend status is stated accurately; no unsupported claim is made.

## Documentation gates

- [ ] README status table matches what is actually installed and proven.
- [ ] Prerequisites match what a fresh install needs.
- [ ] Every command shown in the README exists and takes the documented flags.
- [ ] Non-exposed work stays in `docs/DEVELOPMENT_STATUS.md`, not the README.

## Publication

- [ ] Review diff and generated artifacts for private data.
- [ ] Tag `v0.1.0` only after every applicable gate is evidenced.
- [ ] Mark the GitHub release as pre-release and experimental.
