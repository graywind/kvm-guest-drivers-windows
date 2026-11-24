# Fast read IOCTL corrupts the read callback stack on LiberNT

## Summary

`virtio-win` 0.1.302-1 (the stable and latest package as of 2026-08-27) crashes the
user-mode virtio-fs service on LiberNT when a file is read. The failure is a
stack-cookie (`/GS`) fail-fast in `virtiofs.exe`, immediately after a read reply
has been transferred successfully.

The regression was introduced by commit
[`3e48326`](https://github.com/virtio-win/kvm-guest-drivers-windows/commit/3e48326a366ce2885bcc4a5648d69c9ad8edc75f)
(`RHEL-152852: viofs: use faster file read IOCTL`, 2026-03-05). That commit replaced
a heap-staged reply with a stack `struct fuse_out_for_read` and had the kernel DMA
the file data directly into the WinFsp-provided read buffer.

On LiberNT, the WinFsp read buffer is a user-mode stack address immediately above
the viofs `Read` callback frame. The new stack local changes the frame layout so
that the 26-byte file data written into the WinFsp buffer lands on the frame's
security cookie. `__security_check_cookie` then calls
`__fastfail(FAST_FAIL_STACK_COOKIE_CHECK_FAILURE)`.

The previous driver, 0.1.285-1 (2025-09-15), which still uses the heap
`FUSE_READ_OUT` + `CopyMemory` path, reads the same files without failure on the
same LiberNT VM, the same WinFsp DLL, and the same kernel.

## Reproduced behaviour

Environment: LiberNT amd64 (a ReactOS fork), QEMU 11.1/libvirt, WinFsp 2.2.26323,
virtio-win 0.1.302-1, virtiofsd 1.14 on the host, a shared directory containing
`hostfile.txt` (26 bytes) and `large.bin` (4096 bytes). The virtio-fs device is
attached to the VM; `viofs.sys` is bound to it; `virtiofs.exe` is started with
`-t vmshare -m Z:`.

Directory enumeration and guest writes work:

```
dir Z:           -> vmshare, hostfile.txt 26, large.bin 4096
echo ... > Z:... -> succeeds
```

Reading file data fails. `type Z:\hostfile.txt` (or `copy Z:\hostfile.txt C:\x`)
produces the KD log below and leaves the read IRP pending; the volume is wedged
until the guest is restarted.

```
Read: Offset: 0 Length: 8192
Read: fh: 4 nodeid: 3
VirtFsFuseRequest: >>req: 15 unique: 25 len: 80
VirtFsFuseRequest: <<len: 42 error: 0 unique: 25
Read: BytesTransferred: 26
FASTFAIL rip=00007FF969C38EF1 rsp=0000004BF821FD40
  [0000004BF821FD40] 0000000000000000
  [0000004BF821FD48] 0000004BF8330000
  [0000004BF821FD50] 0000000000000000
  [0000004BF821FD58] 0000000000000000
  [0000004BF821FD60] 0000000000002000
  [0000004BF821FD68] 0000000000000000
  [0000004BF821FD70] 0000000000002000
  [0000004BF821FD78] 00007FF969C31FB6
  [0000004BF821FD80] 6B6369278B0190EF
  [0000004BF821FD88] 00007FF969C578BC
  ...
  [0000004BF821FE10] 000000000000002A
  [0000004BF821FE18] 0000000000000019
  [0000004BF821FE20] 7266206F6C6C6568   "hello fr"
  [0000004BF821FE28] 6B63696C73206D6F   "om slick"
  [0000004BF821FE30] 736F68206C696174   "tail hos"
  [0000004BF821FE38] 0000000000000A74   "t\n"
Kill virtiofs.exe, ExceptionCode: c0000409, ExceptionAddress: 00007FF969C38EF1
```

Interpretation:

- `0x2A` (42) at `FE10` is the FUSE reply header length; `0x19` (25) is the reply
  unique. The kernel wrote the 16-byte header exactly where the user-mode output
  buffer (`&read_out_fast`) lives.
- `FE20` is the WinFsp read buffer; it contains the 26 bytes of `hostfile.txt`.
- The `Read` function's epilogue is at `virtiofs.exe+0x1FB1`:
  `mov rcx,[rsp+0xA8]; xor rcx,rsp; call __security_check_cookie`. The return
  address `0x1FB6` at `FD78` places the frame's `rsp` at `FD80`, so the cookie
  slot is `FE28` - inside the 26-byte data write (`FE20`..`FE39`).
- The crash address `virtiofs.exe+0x8EF1` is `int 0x29` with `ecx = 2`
  (`FAST_FAIL_STACK_COOKIE_CHECK_FAILURE`).

## The change that caused it

Before [`3e48326`](https://github.com/virtio-win/kvm-guest-drivers-windows/commit/3e48326a366ce2885bcc4a5648d69c9ad8edc75f),
`Read` staged the whole FUSE reply in a heap buffer and copied the data into the
WinFsp buffer:

```c
FUSE_READ_OUT *read_out = HeapAlloc(GetProcessHeap(), 0, sizeof(*read_out) + BufSize);
...
VirtFsFuseRequest(..., read_out, sizeof(*read_out) + Size);   // IOCTL_VIRTFS_FUSE_REQUEST
...
CopyMemory(Buf, read_out->buf, OutSize);
SafeHeapFree(read_out);
```

After that commit, the reply header lives on the callback stack and the kernel
writes the data directly into the WinFsp buffer:

```c
fuse_out_for_read read_out_fast;
read_out_fast.hdr.len = Size;
read_out_fast.original_pointer = (uint64_t)(ULONG_PTR)Buf;
...
VirtFsFuseRequest(..., &read_out_fast, sizeof(read_out_fast),
                  IOCTL_VIRTFS_FUSE_REQUEST_READ);
```

The fast path itself completed correctly: the kernel mapped the output buffer to
a system VA whose page offset matched the user `read_out_fast` (the `WDFOUT`
diagnostic showed `FFFF8080198FEE10`, page offset `0xE10`, matching user
`FE10`), built the two-MDL chain, and delivered the 16-byte header and 26-byte
data to the intended addresses. `MmBuildMdlForNonPagedPool` saw only system VAs.
No kernel IOCTL, MDL or WDF failure was involved.

## Why this is not a LiberNT deficiency

The strongest evidence is a direct A/B on the same LiberNT VM, the same WinFsp
DLL, the same kernel and the same virtio-fs device:

| Driver pair | Read path | 26-byte read | 4 KiB read |
|---|---|---|---|
| 0.1.285-1 (2025-09) | heap `FUSE_READ_OUT` + copy | works | works |
| 0.1.302-1 (2026-08) | stack `fuse_out_for_read` + fast IOCTL | fail-fast | not reached |

Additional points:

- The fail-fast is the standard MSVC `/GS` stack-cookie check, not
  `FAST_FAIL_GS_COOKIE_INIT` and not a CET/shadow-stack violation. It is the
  expected result of user-mode stack overwrite; it is not a missing LiberNT API.
- The kernel-side fast IOCTL behaved correctly. The output buffer system VA,
  the page offset, the header write and the data write all matched the intended
  user addresses (see the `WDFOUT` and `MmBuildMdlForNonPagedPool` diagnostics).
- The WinFsp `Read` buffer is not a kernel user mapping placed by LiberNT in the
  stack. The `MiMapFramesUser`/`MmMapLockedPagesSpecifyCache(UserMode)` path was
  instrumented (`MiMapFramesUser: ... va=... pages=...`) and never fired during
  the read, so the buffer is a WinFsp user-mode stack buffer, not a mapping the
  LiberNT memory manager placed. The documented WinFsp zero-copy mapping is not
  the mechanism exercised by this synchronous read path.
- The heap implementation works with the same WinFsp buffer address and the same
  user-mode stack. The only difference is the viofs `Read` frame layout and the
  place the FUSE reply is written.

## Why it was missed in testing

- The fast-read change is recent: 2026-03-05, first shipped in 0.1.302
  (2026-08-27). 0.1.285 (2025-09-15) predates it.
- virtio-win's tests and CI run on Windows. The fault depends on the WinFsp
  read-buffer stack address relative to the viofs `Read` frame; a different stack
  layout or ASLR placement can hide it. It is not a deterministic protocol
  failure and does not reproduce from the FUSE protocol alone.
- On LiberNT the virtio-fs stack was not usable until the Ex UNC provider
  registration (`FsRtlRegisterUncProviderEx`) and SCM image-path
  canonicalisation were fixed; before that the WinFsp driver could not load, so
  file reads through viofs were never exercised. The first successful mount
  tests covered directory enumeration and guest writes; the first file read
  crashed.
- The failure kills the user-mode filesystem process and leaves the read IRP
  pending; the volume stops responding. Without KD-on-COM1 and a stack capture
  this looks like a hang, not a crash, so simple "does it mount?" tests pass.
- There is no LiberNT CI that runs virtio-win; Windows testing cannot observe the
  LiberNT stack layout.

## The fix

This change restores the pre-regression read implementation in `viofs/svc/virtiofs.cpp`:

- allocate a heap `FUSE_READ_OUT` of `sizeof(*read_out) + BufSize`,
- issue `IOCTL_VIRTFS_FUSE_REQUEST` as before,
- validate `hdr.len` and `OutSize` exactly as the current code does,
- `CopyMemory(Buf, read_out->buf, OutSize)`, and free the heap buffer on every
  success or error path.

The FUSE reply header and data never touch the callback stack, and the WinFsp
buffer is written by the copy. The cost is one copy per read chunk, which is the
pre-regression behaviour.

Alternatives considered:

- Heap-allocate only `fuse_out_for_read` and keep the fast IOCTL: the kernel still
  DMAs into the WinFsp stack buffer, so a larger read can still cover the canary
  if the buffer overlaps the frame.
- Add a stack pad: fixes one layout and breaks with another.
- Change WinFsp's read buffer allocation/lifetime: broader than this driver, no
  upstream fix is available (WinFsp 2.2 is the latest), and the A/B test shows the
  old viofs layout is compatible with the buffer.
- Gate or disable the fast IOCTL at runtime: does not address the stack overlap.

Validation so far: the 0.1.285 heap pair reads both files on the same VM.

### Build status and end-to-end validation

The patched `virtiofs.exe` was built for the MSVC ABI with `clang-cl` against
the MSVC CRT/SDK (xwin), `/MT` static CRT, `/std:c++20`, linking the vendor
`winfsp_x64.lib`. The resulting PE imports only KERNEL32, ADVAPI32, CFGMGR32,
SETUPAPI, SHELL32 and `winfsp-x64.dll` - the same set as the vendor build, with
no UCRT API-set or MinGW runtime imports.

Test on the same LiberNT VM:

- the signed virtio-win **0.1.302** package for w10/amd64 (`viofs.sys` 63,128
  bytes, matching catalog) was installed with `pnputil` and the active
  `VirtioFsDrv` image was confirmed as 63,128 bytes after a restart;
- `c:\viofs\virtiofs-patched-msvc.exe -t vmshare -m Z:` reports
  "The service VirtIO-FS has been started.";
- `dir Z:` enumerates `guestfile.txt` (21), `hostfile.txt` (26) and
  `large.bin` (4096);
- `type Z:\hostfile.txt` returns the 26-byte content;
- `copy Z:\large.bin` succeeds and produces a 4,096-byte file;
- `comp Z:\large.bin C:\large-msvc.bin` reports "Files compare OK", and
  `certutil -hashfile C:\large-msvc.bin SHA256` returns
  `9ad4c1f2e6381f353cdd8856527000cb312741d9041b928e5b88eaca41c9c009`, the same
  hash as the host file, so the 4 KiB read is byte-accurate.

No FASTFAIL and no wedged read occurred.

An earlier MinGW-w64 cross-build also failed at service start with
`STATUS_NOT_IMPLEMENTED` (c0000002). That was not a toolchain defect: the same
failure occurs with the MSVC build while the **0.1.285** driver is active,
because a 0.1.302 exe cannot start against the older driver image. After the
0.1.302 driver was installed, the MSVC build mounts and reads normally. The
MinGW build was not retested after the driver swap; the validated artifact is
the MSVC build above.

Build-only adaptations for the MinGW attempt, not part of the PR: `-DUNICODE`,
C++20, `SCOPE_EXIT` with `##__VA_ARGS__`, a `Min` template, a `<Windows.h>` case
shim, a `REPARSE_DATA_BUFFER` shim, `#undef _ReadWriteBarrier` in the WinFsp
header, and static libstdc++/libgcc. The MSVC build needed none of these.


## What would overturn this conclusion

- A Windows 11 run of 0.1.302 failing the same way (it would then also be a
  Windows regression, not LiberNT-specific).
- The old heap pair failing on larger reads on the same VM (it would show the
  WinFsp buffer overlap is not removed by heap staging).
- Evidence that the WinFsp buffer is a kernel user mapping that LiberNT placed
  inside the stack VAD (the mapping instrumentation did not fire; a different
  mapping path would need to be demonstrated).
- A LiberNT API or ABI defect in the exercised path (none was observed; the
  kernel IOCTL/MDL/WDF traces are correct).

## References

- [`3e48326` RHEL-152852: viofs: use faster file read IOCTL](https://github.com/virtio-win/kvm-guest-drivers-windows/commit/3e48326a366ce2885bcc4a5648d69c9ad8edc75f)
- [PR 1539](https://github.com/virtio-win/kvm-guest-drivers-windows/pull/1539)
- [virtio-win-pkg-scripts README](https://github.com/virtio-win/virtio-win-pkg-scripts/blob/master/README.md)
- [WinFsp Design: Prepare/Complete and zero-copy read buffers](https://winfsp.dev/doc/WinFsp-Design/)
- [`__fastfail`](https://learn.microsoft.com/en-us/cpp/intrinsics/fastfail),
  [/GS](https://learn.microsoft.com/en-us/cpp/build/reference/gs-buffer-security-check)
