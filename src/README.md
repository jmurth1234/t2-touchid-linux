# T2 SEP staged transport

This module is the write-capable successor to `t2-sep-probe`, but defaults to
observation-only behavior. In its default mode it claims PCI function
`106b:1802`, maps BAR4, and reads the two mailbox status registers. It performs
no DMA allocation and no MMIO writes.

The explicit `register_ool=1` mode mirrors the recovered Apple transport setup
for AppleKeyStore endpoint 7:

- enables a 44-bit coherent DMA mask and PCI bus mastering;
- allocates separate 16 KiB, page-aligned input and output buffers;
- sends endpoint-0 `SET_REMOTE_DMA_IN` and `SET_REMOTE_DMA_OUT` control calls;
- validates the matching transaction tag and zero SEP result.

It sends no AppleKeyStore request unless the additional
`probe_capabilities=1` option is supplied. That option issues exactly one
read-only opcode `0x4d` capability query after both OOL registrations succeed.
The recovered v1 request is 92 bytes and uses SHA-256 truncated to 16 bytes for
its integrity field. It does not request a fingerprint, modify SKS lock state,
or read/write enrollment records. Loading is not automated.

After OOL registration the module also creates `/dev/t2-aks` as a mode-0600
root-only exchange device. The kernel, rather than userspace, owns header
generation, transaction matching, SHA-256 verification, size bounds, and
request-buffer scrubbing. It accepts only the recovered AppleKeyStore opcodes
`0x03` (load keybag), `0x04` (change lock state), `0x19` (get device state),
`0x21` (verify secret with either a 16-byte ACM context or the bounded
password-only diagnostic), and `0x4d` (capabilities);
every other opcode is rejected. Operation `0x21` is additionally restricted to
the recovered codec, session, password, context, and option layouts. Capability
negotiation uses the required v1 header, while normal operations use the
negotiated v2 header and calendar-time extension.

The research-only `get-device-state-v1 SESSION HANDLE SELECTOR OUTPUT` command
implements the recovered 24-byte operation-`0x19` codec. Its output can contain
a private keybag UUID, is created mode `0600`, and must never be committed or
published. Decode only a private copy, redact identifiers in notes, and remove
the raw output when the observation is complete.

Operation `0x21` codec v1 contains the password and 16-byte ACM
external-context blobs followed by one 64-bit device-options value. Exact
selector `42` supplies plaintext-secret option `0x200`; the kernel accepts only
that canonical value. Memento and structured-credential variants are not
exposed by this research interface. Endpoint-7 mailbox failures are returned
to the root-only caller as a signed SEP status in the fixed-size ioctl record,
so diagnostics do not depend on scraping the kernel log.

`verify-password-only SESSION HANDLE` emits the same recovered codec with a
zero-length external-context blob. It is deliberately restricted to a nonzero
handle, session `1`, a nonempty bounded password, and option `0x200`. This is a
stage-isolation diagnostic: success would prove password/keybag verification
before ACM attachment, while failure remains inside that earlier stage. It
does not enroll, delete, or evaluate an ACM policy.

The installed wrapper selects the known positive runtime keybag and requires a
narrow acknowledgement for this non-ACM path:

```sh
sudo t2-acm-authorize-test --diagnostic-password-only \
  --acknowledge-password-verification
```

The v2 platform field formerly labelled `uid` is the caller's macOS audit
session ID (`ai_asid`). `aks_platform_asid` names it accordingly. The adjacent
64-bit field is the macOS process-unique ID, not a PID. Both are research-only,
boot-scoped data; they must not be inferred from the configured account UID.

After either buffer is successfully registered, the module pins itself in
memory. SEP retains the DMA address and Apple exposes no matching unregister
control message; freeing that memory while SEP is live would be unsafe. A
reboot clears the registration and unloads the module.

Build with `make`. Do not load both this module and `t2_sep_probe` together.
The currently loaded registration-only revision is pinned; testing a rebuilt
revision requires a reboot rather than an unload.
