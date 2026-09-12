# Linux bring-up troubleshooting

This guide records a successful manual bring-up on a MacBookPro15,2 running
Omarchy, `linux-t2` 6.19.11, bridgeOS 23P350, and fprintd 1.94.5. Both an
enrolled-finger `verify-match` and an unenrolled-finger `verify-no-match` were
confirmed. It supplements the main installation guide with failure recovery
learned during that bring-up and omits steps the main guide already covers.

Do not publish values substituted for placeholders below. In particular, keep
account names, serials, UUIDs, MAC addresses, link-local addresses, keybags,
Catacomb files, and exported archives private.

## Safety rules

- Treat a full transport load as a one-attempt operation for the current boot.
- If capability negotiation fails, do not retry, unload, unbind, or replace the
  module. Its SEP DMA registration pins it until reboot.
- Keep macOS bootable. It is the proven recovery environment for stale SEP
  endpoint-7 state.
- Do not repeatedly restart BiometricKit port discovery. A repeated
  high-concurrency RemoteXPC scan triggered a `cdc_ncm` watchdog followed by an
  `apple_bce` kernel failure on the tested MacBookPro15,2.
- Do not overlap boot-time port discovery with SEP capability negotiation. On
  the tested machine that race produced capability timeout `-110`, pinning the
  transport without `/dev/t2-aks` for the rest of the boot. The installed units
  order transport after port discovery.

## Prevent an early transport attempt

Disable every service that can pull the transport through a dependency during
manual bring-up:

```sh
sudo systemctl disable fprintd.service t2-sep-transport.service \
  t2-keybag-load.service t2-credential-unlock.service \
  t2-biometric-ready.service
```

Disabling a unit only prevents boot activation. Another active unit can still
pull a disabled service through `Requires=`. In particular, fprintd requires
the keybag chain and wants the static post-reboot reconciler. Confirm the five
units above are disabled before a recovery boot.

If PCI autoload must also be suppressed, use a module blacklist and the active
bootloader's kernel command line. A blacklist does not block the service's
explicit `modprobe`. Verify which bootloader is actually in use before
rebuilding an initramfs or editing a command line; do not assume a generated UKI
is the selected boot entry.

## Recover stale AppleKeyStore state

On the tested MacBookPro15,2, repeated Linux reboots and full shutdowns did not
recover AppleKeyStore after a capability timeout. Waiting longer in Linux also
did not help. The proven recovery was:

1. Boot macOS and log in.
2. Confirm the existing enrolled finger works in macOS Touch ID.
3. Do not add, delete, or rename fingerprints.
4. Shut macOS down, wait about 30 seconds, and boot Linux.
5. Before loading transport, confirm the module and `/dev/t2-aks` are absent and
   the transport service has no journal entries for the new boot.

After this sequence, capability negotiation succeeded within three minutes of
Linux uptime. This indicates the recovery action was macOS reinitializing SEP,
not elapsed Linux uptime.

## Stabilize BridgeOS networking

The installed `t2-bridge-network.service` now performs this preparation before
boot-time port discovery. During an older install or manual recovery, the T2
`cdc_ncm` interface may be repeatedly managed and disconnected by
NetworkManager because BridgeOS does not provide normal DHCP. Substitute the
interface and Linux link-local address determined for the machine:

The service also handles the observed boot race where the Apple `05ac:8233`
iBridge enumerates but its first automatic `cdc_ncm` bind fails. After the
normal interface wait, it makes one bind attempt only when exactly one matching
USB control interface remains unbound. It never unbinds a device or reloads the
driver or SEP transport.

Port discovery can also leave late BridgeXPC traffic after its process exits.
The transport unit enforces a five-second quiet period after that ordered
discovery step before making the one capability-negotiation attempt for the
boot. This avoids treating process exit and endpoint quiescence as identical.

```sh
nmcli device set <T2_INTERFACE> managed no
sudo sysctl -w net.ipv6.conf.<T2_INTERFACE>.autoconf=1
sudo ip -6 addr add <LINUX_LINK_LOCAL>/64 dev <T2_INTERFACE> scope link
```

Wait for IPv6 duplicate-address detection to finish. The address must no longer
be marked `tentative`. Discover the BridgeOS peer separately:

```sh
ping -6 -c 2 -I <T2_INTERFACE> 'ff02::1%<T2_INTERFACE>'
ip -6 neigh show dev <T2_INTERFACE>
```

The Linux address and BridgeOS peer address are different. Configure
`T2_TOUCHID_HOST` with the responding BridgeOS peer, not Linux's own address.
Using the local address can leave the port cache missing and later surface as
`fingerprint inventory unavailable`.

## Provision the local reconciliation baseline

This step was missing from the earlier installation flow and is now part of the
main guide (installation step 5). Without the local baseline, fprintd correctly
fails closed with `fingerprint inventory unavailable`.

Early versions of the dedicated macOS exporter omitted `source-stat.txt` while
preserving `root:wheel` metadata in tar headers. The baseline parser supports
those persisted exports only after validating the header metadata. New exports
include the sidecar.

## Run the read-only preflight

The repository includes a manual bring-up check that does not load transport,
refresh the port, or change networking:

```sh
sudo tools/check-t2-linux-readiness.sh
```

Before the one controlled transport attempt, require:

```text
RESULT: READY
```

`NOT_READY` means a prerequisite must be fixed first. `BLOCKED` means transport
was attempted without a healthy `/dev/t2-aks`; do not retry during that boot.

## Start transport exactly once

Start the transport once from the disabled state and confirm the module and
root-only device node:

```sh
sudo systemctl start t2-sep-transport.service
sudo systemctl status t2-sep-transport.service --no-pager -l
ls -l /dev/t2-aks
```

Success requires an integrity-checked capability reply in the kernel log and
`RESULT: INITIALIZED` from `sudo tools/check-t2-linux-readiness.sh`. If the
service takes about 12 seconds and reports capability error `-110`, the state is
pinned for that boot. Use the macOS recovery sequence before another attempt.

## Unlock keybags

The unlock procedure itself is in the main guide (installation step 6). Two
bring-up signals are worth knowing:

- Both operations must return `status=0`.
- SEP status `-5`, displayed by the tool as `Remote I/O error`, is ordinary
  password rejection. If the normal handle already succeeded and the second
  password was mistyped, retry only the special handle carefully rather than
  reloading the keybag.

## Verify before PAM

The controls themselves are in the main guide (Verification). Additional
observations from the tested machine:

- Reuse a successful numeric port cache. Do not restart discovery merely to make
  the cache newer.
- In manual keybag-unlock mode, `t2-touchid-doctor` reports the encrypted
  credential as intentionally absent, and the conditional credential-unlock and
  warm-up services are not required. The warning means keybags must be unlocked
  manually after every boot.
- If the kernel currently displays `deep` but the installed systemd policy
  specifies `MemorySleepMode=s2idle`, systemd selects s2idle immediately before
  suspend. The installer's sleep drop-in is authoritative; `/sys/power/mem_sleep`
  only shows what is currently supported.

Only after all checks and both physical controls pass should PAM be installed,
with an existing root shell kept open and password fallback tested.
