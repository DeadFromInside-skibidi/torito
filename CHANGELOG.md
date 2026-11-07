# Changelog

## 2.1.0

Making the first build work for people who have never built an ISO.

### Added
- **Project templates.** `torito --init DIR --template console|desktop|server`
  and `--list-templates`. The `desktop` template is an XFCE live system that
  logs straight in, with Firefox, NetworkManager and PipeWire.
- **New project…** and **Open output folder** buttons in the GUI.
- **Automatic networking.** When the manifest enables no network manager,
  Torito sets up systemd-networkd (DHCP on wired interfaces) and
  systemd-resolved. Opt out with `[network] auto = false`.
- **Automatic kernel and base.** A repository build without a kernel gets
  `linux` (or `[kernel] package`), and one without `base` gets `base`.
  `packages` is now optional.
- **Manifest checks.** Unknown keys are reported with "did you mean …?"
  suggestions, including the classic TOML trap of a top-level key placed
  after a `[table]` header. Misspelled package names get close-match
  suggestions.
- The hostname now defaults to a slug of `name` instead of `torito`.
- `tools/boot-test.sh` boots an ISO in QEMU (BIOS or UEFI) and waits for a
  login prompt. CI now builds the default template from the real Arch
  repositories on Windows and Linux, and boot-tests it under BIOS and UEFI.
- README rewritten for first-time users: install, templates, VM testing,
  USB writing (Rufus DD mode), Secure Boot, troubleshooting, limitations.
- `CONTRIBUTING.md`, issue templates and `.gitattributes`.

### Fixed
- `pacman -Sy` in the booted image failed with "no servers configured",
  because `pacman-mirrorlist` ships every server commented out. The mirrors
  the image was built from are now enabled (an overlay mirrorlist is kept).
- Files of 4 GiB or more were silently truncated in the ISO directory record
  (32-bit size). They now stop the build with an explanation.
- Non-x86_64 `arch` values produced unbootable images; they are now rejected.
- The GUI showed version 1.0.0.

### Removed
- `torito/fat32.py`, the unused 1.x ESP writer (replaced by `fatfs.py`).

## 2.0.0

Torito 1.x produced ISOs that could not boot. 2.0 is a rewrite of the
pipeline:

- No kernel, initramfs or boot loader was ever placed in the image, and the
  BIOS El Torito entry was empty. There is now a real kernel (from the
  package set), a live initramfs, ISOLINUX and systemd-boot.
- The "BOOTX64.EFI" in the ESP was a placeholder. The ESP was labelled FAT32
  with far too few clusters, so firmware read it as FAT16.
- GPT partition offsets were in 2048-byte sectors instead of 512-byte LBAs.
- File names were truncated to ISO9660 8.3 (`FILESYSTEM.SQUASH`). Rock Ridge
  is now emitted.
- The kernel command line used `CDLABEL=TORITO` while the volume had another
  label, and expected a dracut initramfs that did not exist.
- SquashFS: directories over 64 KiB overflowed a 16-bit field, listing was
  O(n²), and everything was held in RAM.
- Packages were not resolved or downloaded at all; package text files were
  rewritten (CRLF); owners were not mapped; `/bin` vs usr-merge was wrong.
- Services ignored `Alias=`/`Also=`.
- Package filenames with an epoch (`zlib-1:1.3…`) were written into NTFS
  alternate data streams.
