# Torito — Rootless Linux ISO Compiler

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform: Windows](https://img.shields.io/badge/Platform-Windows%2010%2F11-0078D6.svg)](https://microsoft.com)
[![Python: 3.10+](https://img.shields.io/badge/Python-3.10%2B-3776AB.svg)](https://python.org)

**Torito** builds bootable Arch-based live Linux ISOs **on Windows**, in pure
Python: no WSL2, no Docker, no VM, no root, no loop mounts. You describe the
system in a manifest; Torito downloads the packages, assembles the root
filesystem in memory and writes a hybrid ISO that boots on **BIOS and UEFI**,
from **CD/DVD or USB**, on real hardware and in VMware, VirtualBox, QEMU and
Hyper-V.

```powershell
pip install -r requirements.txt
python -m torito --init mydistro      # scaffold a project
python -m torito mydistro\distro.toml -v
python -m torito --inspect mydistro\output\mydistro-x86_64.iso
```

---

## How it works

```
manifest (TOML/JSON/INI)
   │
   ├─ repo       pacman sync DBs → dependency resolver (provides, groups,
   │             vercmp) → parallel, SHA-256-verified downloads (cached)
   ├─ ingest     .pkg.tar.zst streamed into an in-memory POSIX VFS
   │             (owners, modes, setuid, symlinks, hard links, xattrs);
   │             payloads spooled to a pack file so RAM stays flat;
   │             pacman local DB written so `pacman -Q` works in the image
   ├─ overlays   Windows folders laid over / (CRLF → LF for text)
   ├─ mutations  /etc/passwd|group|shadow|gshadow from the filesystem package
   │             + every sysusers.d + your users (glibc-compatible $6$ hashes);
   │             `systemctl enable` semantics (WantedBy/Alias/Also/templates,
   │             --global); post-install hooks that need Linux binaries
   │             (depmod, locale-gen, glib schemas, mime, CA trust, fonts,
   │             pacman keyring) run once at first boot inside the target
   ├─ initramfs  static busybox + the kernel modules needed to find the medium
   │             (dependency closure read from each module's ELF .modinfo);
   │             finds the ISO by volume label, loop-mounts the SquashFS,
   │             stacks a tmpfs overlay, switch_root → systemd
   ├─ squashfs   SquashFS 4.0 writer (zstd/xz/gzip, parallel compression,
   │             fragments, sparse blocks, extended inodes, xattrs)
   ├─ fatfs      EFI System Partition (FAT16/FAT32 chosen by cluster count,
   │             exactly as firmware decides) with systemd-boot + kernel
   └─ iso9660    ISO9660 + Rock Ridge, El Torito (ISOLINUX with
                 boot-info-table + EFI entry), isohybrid MBR with an 0xEF
                 ESP partition for USB boot, streamed to disk
```

### Boot chain

| Firmware | Path |
|---|---|
| BIOS, optical | El Torito → ISOLINUX (`/boot/syslinux`) → menu → kernel + initramfs |
| BIOS, USB | isohybrid MBR (`isohdpfx`) → ISOLINUX → … |
| UEFI, optical | El Torito EFI entry → ESP image → `\EFI\BOOT\BOOTX64.EFI` (systemd-boot) |
| UEFI, USB | MBR partition type 0xEF → same ESP → systemd-boot |

The kernel command line identifies the medium with `torito.label=<volume id>`.
Extra knobs understood by the initramfs: `torito.copytoram`,
`torito.overlay_size=4G`, `torito.break` (rescue shell before switch_root),
`torito.debug`, `init=`.

## Manifest

See [`example.toml`](example.toml) for every option. The minimum:

```toml
name     = "MyLinux"
packages = ["base", "linux"]
```

Highlights:

* `packages` — repository package names (dependencies resolved automatically)
  or paths to local `.pkg.tar.zst` / `.deb` / `.apk` files.
* `[[repositories]]` — defaults to Arch `core` + `extra`.
* `rootfs_overlay_dirs`, `file_permissions = { "/path" = "uid:gid:mode" }`,
  `remove_paths`.
* `[[users]]`, `[[groups]]`, `[[services]]` (`user = true` for user units),
  `default_target`.
* `[kernel] cmdline`, `[bootloader] bios/uefi/timeout`, `[live] copytoram`,
  `[iso] volume_id/squashfs_*`.

## Verifying an image

`python -m torito --inspect image.iso` prints the MBR, El Torito catalog, ESP
and SquashFS details; `--verify` exits non-zero if anything that decides
bootability is wrong (unpatched boot-info-table, ESP whose FAT type does not
match its cluster count, overlapping MBR partitions, missing kernel/rootfs,
SquashFS tables in an order the kernel rejects, label mismatch…). Every build
runs the verifier automatically.

## Tests

```powershell
python -m unittest discover -s tests -v
```

The suite is offline and ends with an end-to-end build of a bootable ISO from
synthetic packages.

## What changed in 2.0

Torito 1.x produced ISOs that could not boot. 2.0 fixes, among others:

* no kernel, initramfs or boot loader was ever placed in the image, and the
  BIOS El Torito entry was empty — there is now a real kernel (from the
  package set), a live initramfs, ISOLINUX and systemd-boot;
* the "BOOTX64.EFI" in the ESP was a placeholder; the ESP was labelled FAT32
  with far too few clusters, so firmware read it as FAT16;
* GPT partition offsets were in 2048-byte sectors instead of 512-byte LBAs;
* file names were truncated to ISO9660 8.3 (`FILESYSTEM.SQUASH`); Rock Ridge
  is now emitted;
* the kernel command line used `CDLABEL=TORITO` while the volume had another
  label, and expected a dracut initramfs that did not exist;
* SquashFS: directories over 64 KiB overflowed a 16-bit field, listing was
  O(n²), everything was held in RAM; packages were not resolved or
  downloaded at all, package text files were rewritten (CRLF), owners were
  not mapped, `/bin` vs usr-merge was wrong, services ignored
  `Alias=`/`Also=`, and package filenames with an epoch (`zlib-1:1.3…`)
  were written into NTFS alternate data streams.

## License

MIT. See [LICENSE](LICENSE).
