# Suspend/resume upstream report template

Use this template for the relevant `t2bce` or kernel maintainer. Do not attach
raw keybags, captures, addresses, UUIDs, or biometric replies.

## Hardware and software

- Mac model: `MacBookPro16,2`
- Kernel and t2bce revisions: fill from the tested boot
- Sleep mode: `deep` (failure reproduced); `s2idle` live control passed
- bridgeOS build: `23P1072`

## Reproduction

1. Cold boot Linux and verify RemoteXPC/Touch ID works.
2. Suspend using `deep` sleep.
3. Resume and attempt a privacy-safe RemoteXPC health check.
4. Observe repeated `NETDEV WATCHDOG` transmit timeouts on the T2 `cdc_ncm`
   interface while systemd services can remain active.

## Existing evidence

- Rebinding `cdc_ncm` recreated the interface but did not restore RemoteXPC.
- USB deauthorization/reauthorization recreated the interface but did not
  restore RemoteXPC.
- Reboot restored operation.
- The SEP transport module deliberately cannot be safely unloaded after DMA
  registration.
- `s2idle` preserved RemoteXPC, SEP/keybag state, fprintd verification, and a
  clean watchdog report without restarting services. It is the installed
  workaround while the deep-resume defect remains.

## Attachments

Attach before/after output from `tools/collect-suspend-diagnostics.sh`, exact
kernel/t2bce commits, and the result of an `s2idle` comparison. Review every
attachment manually for identifiers before publishing.
