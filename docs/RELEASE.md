# Experimental release checklist

## Automated gates

- [ ] CI passes Python compilation and unit tests.
- [ ] ShellCheck passes all installed and helper scripts.
- [ ] `t2-aks-tool` builds without warnings.
- [ ] Privacy scan finds no private artifacts or stable identifiers.
- [ ] Fresh installation and repeated installation both complete.
- [ ] Uninstall preserves private data; explicit purge removes it.
- [ ] DKMS builds only the kernel module for a second installed kernel.

## Proven-machine gates

- [ ] Root doctor has no unexpected failures.
- [ ] Enrolled and unenrolled fingers pass raw BridgeXPC controls.
- [ ] Enrolled and unenrolled fingers pass `fprintd-verify` controls.
- [ ] Enrolled and unenrolled fingers pass sudo/PAM controls.
- [x] `omarchy system lock` accepts the enrolled fingerprint.
- [ ] `omarchy system lock` rejects a wrong finger and retains password fallback.
- [ ] Cold boot with encrypted credential passes.
- [ ] Kernel upgrade rebuild/install passes.
- [ ] Suspend status is stated accurately; no unsupported claim is made.

## Publication

- [ ] Review diff and generated artifacts for private data.
- [ ] Tag `v0.1.0` only after every applicable gate is evidenced.
- [ ] Mark the GitHub release as pre-release and experimental.
