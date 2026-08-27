# Intel T2 Touch ID for Linux

Experimental, fail-closed Touch ID authentication for Intel Macs with an Apple
T2 chip. It talks to bridgeOS BiometricKit over BridgeXPC and exposes a minimal
`fprintd`-compatible D-Bus service for PAM clients.

This is research software, not an upstream `libfprint` driver. Enrollment and
deletion remain in macOS. The Linux side only verifies an identity already
enrolled for macOS user ID 501.

See the redacted conversation that produced this here: https://gist.github.com/jmurth1234/4a138019fd832dfabbed26475613db3a

## Proven configuration

Developed and verified on an Intel `MacBookPro16,2`, bridgeOS build `23P1072`,
BridgeXPC 39, and Omarchy/Arch Linux. A positive right-index control and a
negative unenrolled-finger control were both verified at the raw bridge,
`fprintd`, and sudo/PAM layers.

## Security properties

- Matching is scoped to user 501 and the identity records returned by SEP.
- Success requires the enrolled 16-byte identity UUID to occur in SEP's
  protocol-v2 match-result event.
- Missing, malformed, rejected, or timeout results fail closed.
- The service never emits UUIDs, fingerprint images, or biometric payloads.
- Enrollment and deletion are deliberately unsupported on Linux.
- PAM templates are supplied but are not installed automatically.

## Important limitations

- This has only been tested on the machine/build above.
- The SEP kernel module is pinned after DMA registration and must not be
  unloaded; reboot before replacing it.
- The macOS-derived keybag must remain private and must be unlocked with the
  macOS login password after every reboot. The password is never stored.
- Suspend/resume is not currently reliable on the proven configuration. After
  a deep-S3 suspend, the T2 CDC-NCM interface may remain present while
  BridgeXPC is unreachable. Touch ID then fails closed until the machine is
  rebooted and the keybags are unlocked again.
- Never publish `*.kb`, `*.cat`, exported archives, captures, Apple binaries,
  device identifiers, or match-result payloads.

### Suspend/resume failure

This was reproduced with the `t2bce` stack on the proven configuration. The
kernel reported repeated `NETDEV WATCHDOG` transmit timeouts for the T2's
`cdc_ncm` interface after resuming from `deep` sleep. The systemd transport,
keybag, and fprintd services could still appear active because their existing
process state did not reflect loss of communication with bridgeOS.

Rebinding the `cdc_ncm` interface and deauthorizing/reauthorizing its virtual
USB device both recreated the interface but did not restore RemoteXPC. Do not
unload `t2_sep_transport` as a recovery attempt: its SEP-registered DMA memory
is deliberately pinned until reboot. The known recovery is:

1. Reboot Linux.
2. Unlock the normal and special user keybags again as described below.
3. Restart `fprintd.service` if it is not already running.
4. Repeat both the enrolled- and unenrolled-finger controls before relying on
   PAM authentication.

Treat suspend as unsupported until the underlying T2 BCE resume path is fixed
or an alternative sleep mode has been validated on the specific Mac model.

## Layout

- `src/t2_sep_transport.c`: SEP endpoint-7 DMA/keybag transport.
- `src/t2-aks-tool.c`: narrowly allow-listed AppleKeyStore operations.
- `src/discover-biometric-port.py`: privacy-preserving RemoteXPC discovery.
- `src/bridge-xpc-probe.py`: BridgeXPC command and match implementation.
- `src/t2-fprintd.py`: verification-only fprintd facade.
- `systemd/`: system and audible-feedback units.
- `pam/`: clamshell-safe Omarchy PAM templates.
- `tools/macos/`: private export helpers; outputs must never be committed.
- `tests/`: hardware-free fail-closed lifecycle tests.

## Installation outline

1. Keep macOS available and enroll exactly the finger you intend to use.
2. Run the export helpers from macOS and transfer outputs privately.
3. On Linux, identify the T2 USB-network interface and link-local IPv6 address,
   then run `sudo ./install.sh`. Edit `/etc/t2-touchid.conf` when prompted.
4. Start `t2-sep-transport.service`. The installer builds the module for the
   running kernel and installs it with `register_ool=1`. Do not unload it;
   reboot before rebuilding or replacing it. Re-run the installer after a
   kernel upgrade.
5. Place the extracted keybag at `/var/lib/t2-touchid/user.kb`, owned by root
   and mode `0600`, then start `t2-keybag-load.service`.
6. Unlock the loaded normal handle and special user bag with the macOS password:

   ```sh
   sudo /usr/local/sbin/t2-aks-tool unlock-keybag 1 HANDLE
   sudo /usr/local/sbin/t2-aks-tool unlock-keybag 1 -501
   ```

7. Start `fprintd.service`. Run `fprintd-verify` once with the enrolled finger
   and once with an unenrolled finger. Require `verify-match` and
   `verify-no-match`, respectively.
8. Only after those controls pass, install the relevant files from `pam/` into
   `/etc/pam.d/`. Preserve backups and keep password authentication as fallback.

Exact keybag extraction and hardware bring-up remain machine-sensitive. Read
`src/README.md` before loading the module.

## Tests

```sh
python -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python -m unittest tests/test_t2_fprintd.py
python -m py_compile src/*.py
```

## License

This project is licensed under the GNU General Public License version 2 only
(`GPL-2.0-only`). See [`LICENSE`](LICENSE). The userspace-facing transport
header retains the standard Linux syscall-note exception.
