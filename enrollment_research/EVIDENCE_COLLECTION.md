# Deferred evidence collection

These tasks correspond to the unresolved evidence table in
[FINDINGS.md](FINDINGS.md). Collection output is private by default and must not
be committed to this repository.

## 1. Exact Catacomb fixtures

Needed for independent keyed-archive reader/writer and crash-recovery tests:

- `master.cat`;
- `biolockout.cat`;
- `user_*.cat` with one and, if naturally available, multiple identities;
- before/delete/re-enroll generations; and
- ideally a genuine legacy user archive without `CatacombUserKeybagUUID`.

Boot macOS and run:

```bash
sudo ./scripts/collect-catacomb-fixtures-macos.sh /path/outside/the/repo
```

Use `--freeze-daemon` only when a consistent point-in-time copy is required.
It briefly stops `biometrickitd`, copies the files, and resumes it through a
trap. Review `manifest.sha256` and `metadata.txt`. Encrypt the directory before
moving it between operating systems. Do not publish the raw files.

## 2. Read-only account/persona inventory

Needed to join numeric UID, OpenDirectory UUID, UserPersona data, host UUID,
top-level AKS identity, bag UUID, and selector-`0x61` persona UUIDs without
assuming equal-looking UUIDs are interchangeable.

```bash
sudo ./scripts/collect-persona-inventory-macos.sh USERNAME /path/outside/the/repo
```

The script collects OS/account metadata and a private copy of `persona.kb` when
present. It cannot call private `AKSIdentityList` or selector `0x61` by itself;
those require a separately reviewed read-only helper. The output explicitly
records those missing columns rather than fabricating them.

## 3. Whole-biometric-user presence primitive

Command `0x48` is known, but zero identities does not distinguish an empty
biometric-user container from an absent one. Search exact extracted host
binaries offline:

```bash
./scripts/search-container-presence.sh /path/to/extracted/BiometricSupport \
  /path/to/biometrickitd /path/to/private/output
```

Promising symbols or strings still need disassembly and an exact request/reply
contract. Do not probe guessed commands on live hardware.

## 4. Encrypted J132 SEP artifact

The encrypted SEP image is useful for provenance and may become analyzable if a
legitimate plaintext key/image is obtained later:

```bash
./scripts/extract-encrypted-sep.sh /path/to/bridgeOS.ipsw \
  /path/outside/the/repo
```

The script extracts only Apple's encrypted IM4P and hashes it. If the `ipsw`
tool is installed, it also records metadata and wrapped KBAG data. A displayed
KBAG key is wrapped material, not a usable AES key. The script performs no
decryption and downloads nothing.

## 5. Controlled device validation

Final mode-0 consumption, replay/one-shot behavior, cancellation ambiguity,
and persistence reconciliation ultimately require a disposable-finger hardware
experiment. Do not attempt it until the read-only inventory, strict Catacomb
codec, endpoint-10 broker, and durable journal exist.

Run the non-mutating checklist generator first:

```bash
./scripts/hardware-experiment-preflight.sh /path/to/private/output
```

It intentionally exits nonzero while any prerequisite is unacknowledged and
contains no enrollment or deletion command. The eventual experiment must be a
separately reviewed change with an immutable target UID, verified backup,
password fallback, exact before/after inventory, and explicit operator consent.

## Publishing results safely

Share semantic, redacted findings rather than raw captures. Replace account
names, filesystem paths, host/account/bag/persona/identity UUIDs, session IDs,
network addresses, and hashes of private artifacts. Public hashes of unmodified
Apple binaries may be retained for reproducibility, but Apple binaries and
firmware themselves must not be committed.

Before committing documentation changes, run:

```bash
./scripts/check-public-tree.sh
../../tools/privacy-check.sh
```
