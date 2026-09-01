# Read-only user-broker candidates

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

After those gates pass, the units still require a reviewed installer, rollback
path, socket-path client, and live failure-injection tests before enablement.
