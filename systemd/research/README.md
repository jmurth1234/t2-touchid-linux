# Uninstalled integration candidates

These units are design artifacts for the future mapped-user broker. They are
not copied by `install.sh`, contain no `[Install]` section, and must not be
manually installed or started yet.

`t2-touchid-user-broker.socket` uses `ListenSequentialPacket=` with
`Accept=yes`, so systemd accepts one connection and passes only that connected
descriptor to a fresh `t2-touchid-user-broker@.service` instance. The socket is
locally connectable by any account because the broker authenticates the kernel
peer and resolves its protected mapping; it never accepts a target UID from the
request. Per-source, global, and trigger limits bound unauthenticated spawning.

The service entry point fixes mutation policy off. Its only commands are
read-only policy preflight and reconciled identity inventory. It owns one
descriptor, returns at most one response, and exits. The service sandbox keeps
only the local Unix/D-Bus and Bridge IPv6 address families, the T2 AKS device,
read-only home access needed for account-generation evidence, and narrowly
writable runtime/mapping lock directories.

Exposure remains gated on all of the following evidence:

1. The running module must match the installed DKMS build.
2. `sudo t2-aks-observe-test` must pass operation `0x06` on the rebuilt module.
3. Existing and Linux-enrolled fingers must still verify independently.
4. The protected mapped-user state must be enabled and fully reconciled.
5. A negative client/PolicyKit test must prove an unmapped or inactive caller
   receives no inventory and cannot activate a keybag.

The first four prerequisites are summarized without identifiers or mutation by:

```sh
sudo t2-touchid-user-broker-gate \
  --acknowledge-two-distinct-fingers-verified-this-boot
```

Exit status zero means only that gate 5 may be staged. This command does not
copy, start, or enable either unit in this directory.

`t2-touchid-user-broker-negative-client.py` is the fixed no-argument client for
gate 5. It is also excluded from the installer. When the units are deliberately
staged, run this client as the chosen unmapped or inactive account. It sends
only `identities/inventory` to the fixed candidate socket and accepts either an
exact `caller-session-denied`/`mapping-or-capability-denied` response containing
no inventory or authority, or a clean peer close without a response. Malformed,
truncated, cross-command, activation-bearing, inventory-bearing, unavailable-
socket, and other denial states fail the test. A passing client result does not
install or authorize the positive mapped-user path.

After those gates pass, the units still require a reviewed installer, rollback
path, socket-path client, and live failure-injection tests before enablement.

## Native fprint enrollment drop-in

`fprintd.service.d/10-native-enrollment.conf` is a separate, uninstalled
candidate for the live standard-client controls. It changes only the daemon's
exact `ExecStart` by adding `--enable-native-enrollment`; the normal service,
installer, and upgrades remain default-off. Do not stage it while the fprint
projection is incomplete or while any mutation journal requires recovery or
post-reboot proof.

After the documented mapping, canonical-label, worker-negative, fallback, and
recovery gates pass, stage it explicitly:

```sh
sudo t2-touchid-fprint-enrollment-gate \
  --acknowledge-two-distinct-fingers-verified-this-boot \
  --acknowledge-password-fallback-tested \
  --acknowledge-worker-negative-controls-passed
sudo install -d -o root -g root -m 0755 \
  /etc/systemd/system/fprintd.service.d
sudo install -o root -g root -m 0644 \
  systemd/research/fprintd.service.d/10-native-enrollment.conf \
  /etc/systemd/system/fprintd.service.d/10-native-enrollment.conf
sudo systemctl daemon-reload
sudo systemctl restart fprintd.service
```

The first command is read-only and must exit zero immediately before staging.
It combines exact stack health, AKS alias observation, a complete canonical
projection, enabled protected mapping, clear enrollment/rename/delete journals,
the effective default-off daemon command, and the three explicit live-control
attestations. It never installs the drop-in or performs a T2 mutation.

Rollback does not touch fingerprints, Catacomb data, mappings, credentials, or
journals. Remove only that exact drop-in, reload, and restart:

```sh
sudo rm /etc/systemd/system/fprintd.service.d/10-native-enrollment.conf
sudo systemctl daemon-reload
sudo systemctl restart fprintd.service
```

Before and after staging, inspect the effective command with:

```sh
systemctl show -p ExecStart fprintd.service
```
