# Torito — build a bootable Linux ISO on Windows

[![CI](https://github.com/DeadFromInside-skibidi/torito/actions/workflows/ci.yml/badge.svg)](https://github.com/DeadFromInside-skibidi/torito/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python: 3.10+](https://img.shields.io/badge/Python-3.10%2B-3776AB.svg)](https://python.org)
[![Platform: Windows](https://img.shields.io/badge/Platform-Windows%2010%2F11-0078D6.svg)](#)

You want your own live Linux ISO, and you are on Windows. The usual answer
is "set up WSL / Docker / a Linux VM, install archiso, run it as root, and
fix the loop-device errors". **Torito skips all of that.** It is a small,
pure-Python program that downloads Arch Linux packages and writes a
finished, bootable ISO directly — no WSL, no Docker, no virtual machine, no
admin rights.

The ISO boots on **BIOS and UEFI**, from **DVD or USB stick**, on real PCs
and in VirtualBox, VMware, Hyper-V and QEMU. The kernel, initramfs, boot
loaders, users, passwords, services and networking are all handled for you.

```powershell
pip install git+https://github.com/DeadFromInside-skibidi/torito
torito --init MyLinux --template desktop
torito MyLinux\distro.toml
# → MyLinux\output\mylinux-x86_64.iso
```

---

## Contents

- [Quick start](#quick-start)
- [Templates](#templates)
- [What Torito takes care of](#what-torito-takes-care-of)
- [Try your ISO](#try-your-iso) · [Write it to a USB stick](#write-it-to-a-usb-stick)
- [Customising your system](#customising-your-system)
- [Troubleshooting](#troubleshooting)
- [Limitations](#limitations)
- [How it works](#how-it-works) · [Development](#development)

## Quick start

**1. Install Python 3.10 or newer** from [python.org](https://www.python.org/downloads/windows/).
In the installer, tick **"Add python.exe to PATH"**.

**2. Install Torito.** Open PowerShell or Command Prompt and run:

```powershell
pip install git+https://github.com/DeadFromInside-skibidi/torito
```

No Git? Download the repository as a ZIP, extract it, open a terminal in that
folder and run `pip install .` instead.

**3. Create a project.** Pick a [template](#templates):

```powershell
torito --init MyLinux --template desktop
```

This creates a `MyLinux` folder holding `distro.toml` (the description of
your system) and an `overlays\rootfs` folder for your own files.

**4. Build.**

```powershell
torito MyLinux\distro.toml
```

The first build downloads the packages (about 1 GB for the desktop template)
into a cache folder that later builds reuse. The finished ISO, with a
`.sha256` checksum next to it, lands in `MyLinux\output\`.

**Prefer clicking?** Run `torito-gui` (or `python -m torito` with no
arguments). Choose **New project…**, pick a template and a folder, then press
**Build ISO**.

> If the `torito` command is not found, use `python -m torito` instead. That
> happens when Python's `Scripts` folder is not on `PATH`.

## Templates

| Template | What you get | ISO size |
|---|---|---|
| `console` *(default)* | Text-mode live system: NetworkManager (`nmtui` for Wi-Fi), sudo, vim/nano, SSH client, CPU microcode, firmware for real hardware | ~900 MiB |
| `desktop` | XFCE desktop that logs straight in, with Firefox, Wi-Fi applet, PipeWire sound and file manager | ~1.4 GiB |
| `server` | Headless rescue system: SSH server on, DHCP networking, partitioning/recovery tools (parted, gdisk, LVM, LUKS, mdadm, testdisk, ddrescue…) | ~800 MiB |

A first build takes a few minutes, mostly downloading. On a typical PC
with a warm cache, the console and server templates build in about a
minute and the desktop in about three.

`torito --list-templates` shows the same list. Templates are only a starting
point: open `distro.toml` in any text editor and change whatever you like.

**Default logins** are `live`/`live` and `root`/`root` (`admin`/`admin` on
the server template). Change them in `distro.toml` before you share an image.

## What Torito takes care of

All the things that normally need a Linux machine and root access:

- **Packages.** It downloads Arch Linux's package databases, resolves every
  dependency (virtual packages, groups, version constraints), and downloads in
  parallel with SHA-256 checks and mirror fail-over.
- **Kernel.** If you leave out a kernel, `linux` is added, and if you leave
  out `base`, it is added too. Intel/AMD microcode is loaded early when those
  packages are installed.
- **Initramfs.** Torito builds its own live initramfs containing the drivers
  needed to find the boot medium: SATA, NVMe, USB, SD, and the virtio,
  VMware, Hyper-V and Xen disk drivers, with module dependencies worked out
  automatically.
- **Boot loaders.** ISOLINUX for BIOS and systemd-boot for UEFI, each with a
  menu that has *live*, *safe graphics* and *copy to RAM* entries. An
  isohybrid MBR makes the same file bootable from DVD and from a USB stick.
- **Users, passwords and groups.** The `/etc/passwd`, `group` and `shadow`
  files are created the way `systemd-sysusers` would do it, with proper
  `$6$` password hashes, and home folders are filled from `/etc/skel`.
- **Services.** `systemctl enable` is emulated, including `WantedBy`,
  `Alias`, `Also` and template units, and you can set the default target.
- **Networking.** If you don't enable a network manager, wired DHCP is set
  up with systemd-networkd and systemd-resolved, so the system is online out
  of the box.
- **Linux permissions from Windows.** Owners, modes, setuid bits, symlinks,
  hard links and xattrs come straight from the packages. Windows CRLF line
  endings in your own files are converted. File names that NTFS cannot store
  (`:` in package versions) are handled.
- **`pacman -S` works in the booted system.** Arch ships its mirrorlist
  fully commented out; Torito enables the mirrors the image was built from.
- **Post-install steps.** Steps that need Linux binaries (`depmod`,
  `locale-gen`, font/icon caches, CA trust, pacman keyring) run automatically
  on first boot.
- **`pacman` keeps working** inside the image, because the package database
  is written for it.
- **Mistakes are caught early.** A misspelled package or manifest key gets a
  "did you mean …?" hint, and a key placed under the wrong TOML table is
  reported. Every build is verified automatically.

## Try your ISO

Booting in a virtual machine is the quickest test.

| Hypervisor | Settings |
|---|---|
| **VirtualBox** | New VM → type *Linux*, version *Arch Linux (64-bit)*, 2 GB RAM, attach the ISO. Tick *Enable EFI* to test UEFI. |
| **VMware Workstation/Player** | New VM → *Installer disc image file (iso)* → guest *Other Linux 5.x kernel 64-bit*. BIOS or UEFI both work. |
| **Hyper-V** | *Generation 1* works as is. For *Generation 2*, turn **Secure Boot off** in the VM's security settings. |
| **QEMU** | `qemu-system-x86_64 -m 2048 -cdrom MyLinux\output\mylinux-x86_64.iso` |

Every Torito image also prints its boot log to the first serial port
(`console=ttyS0`), which helps when testing headless. `tools/boot-test.sh`
boots an ISO in QEMU and waits for a login prompt; CI uses it on every push.

## Write it to a USB stick

- **[Rufus](https://rufus.ie):** select the ISO and press *Start*. When Rufus
  asks how to write the hybrid image, **choose "DD Image mode"**. ISO mode
  copies the files onto a FAT stick whose label is cut to 11 characters, and
  the live system finds its medium by that label.
- **[balenaEtcher](https://etcher.balena.io)** and Linux `dd` write the image
  as is, which is correct.

Then boot the PC from the stick (usually F12, F11, F8 or Esc at power-on).

> **Secure Boot:** Torito's boot loaders are not signed, so turn Secure Boot
> off in the firmware settings to boot on UEFI PCs that have it on.

## Customising your system

Everything lives in `distro.toml`. [`example.toml`](example.toml) documents
every option; here are the common ones.

```toml
name     = "MyLinux"
hostname = "mylinux"
timezone = "Europe/Berlin"           # any name under /usr/share/zoneinfo
keymap   = "de"

# Any package from https://archlinux.org/packages (core + extra).
packages = ["base", "linux", "linux-firmware", "firefox", "git", "python"]

# Your own files: overlays/rootfs/etc/motd ends up as /etc/motd.
rootfs_overlay_dirs = ["overlays/rootfs"]

# Windows can't store Linux permissions; give scripts/secrets theirs here.
file_permissions = { "/usr/local/bin/hello" = "0:0:755" }

remove_paths = ["/usr/share/doc"]    # make the image smaller

# --- tables come after all plain settings ---
[[users]]
name     = "me"
password = "s3cret"                  # hashed at build time; "" = no password
groups   = ["wheel"]

[[services]]
name = "sshd"                        # systemctl enable sshd

[kernel]
cmdline = "quiet"                    # extra kernel arguments
# package = "linux-lts"              # a different kernel

[bootloader]
timeout = 3

[iso]
volume_id = "MYLINUX_LIVE"
squashfs_compression = "xz"          # smaller, slower to build (default zstd)
```

> **TOML gotcha:** plain `key = value` lines must come *before* the first
> `[table]` or `[[table]]` header. Anything after a header belongs to that
> table. Torito warns you if it spots this.

**Packages not in Arch's repositories** (for example from the AUR): build
the `.pkg.tar.zst` somewhere, then list its path in `packages`. Debian `.deb`
and Alpine `.apk` files can be listed the same way.

**More repositories / mirrors:** see `[[repositories]]` in `example.toml`.

### Boot-time options

Press **Tab** in the BIOS menu, or **e** in the UEFI menu, to add any of these:

| Option | Effect |
|---|---|
| `torito.copytoram` | Copy the whole system to RAM so the USB stick or DVD can be removed |
| `torito.overlay_size=4G` | Size of the in-memory writable layer (default 75% of RAM) |
| `torito.break` | Rescue shell just before switching to the real system |
| `torito.debug` | Trace the live initramfs |
| `nomodeset` | Avoid graphics driver problems (the *safe graphics* entry) |

## Troubleshooting

**"these packages are not in the configured repositories"** — the name is
wrong or the package lives in the AUR. Torito suggests close matches; check
the exact name on [archlinux.org/packages](https://archlinux.org/packages/).

**The build is slow on Windows.** Windows Defender scans every file Torito
writes. Adding an exclusion for the project folder (or at least for
`.torito-cache` and `.torito-work`) speeds builds up a lot. The second build
is much faster because the downloads are cached.

**"waiting for the live medium labelled …" / rescue shell at boot.** The
initramfs could not find the ISO. On USB, rewrite the stick in **DD mode**.
In a VM, check the ISO is attached. In the rescue shell, `ls /dev` and
`blkid` show what the kernel sees. Unusual storage controllers can be added
with `[kernel] initramfs_modules = ["driver_name"]`.

**Black screen after the boot menu.** Use the *safe graphics* entry
(`nomodeset`).

**UEFI PC ignores the stick.** Turn Secure Boot off, or boot it in
legacy/CSM mode.

**Wi-Fi.** Keep `linux-firmware` in `packages`. On the console template use
`nmtui`; on the desktop template use the network icon.

**Changing the system after boot is lost on reboot.** That is how live
systems work: changes live in RAM. Put permanent changes in `distro.toml` or
in the overlay folder and rebuild.

**A file over 4 GiB.** A single file in an ISO9660 image cannot exceed 4 GiB.
If the compressed system gets that big, drop packages, use `remove_paths`, or
set `squashfs_compression = "xz"`.

Inspect any ISO with `torito --inspect image.iso`, and check its boot
structures with `torito --verify image.iso` (it exits non-zero on problems).

## Limitations

- **x86_64 only**, and Arch-based: packages come from pacman repositories.
- **Live systems only.** There is no installer. You can add `archinstall`
  to `packages` if you want one.
- **Secure Boot is not supported**; the boot loaders are unsigned.
- Package install scripts (`.INSTALL`) are not run at build time. Their
  important effects are emulated or run at first boot, but an unusual
  package may need a manual tweak through an overlay file or a first-boot
  service.

## How it works

```
distro.toml
   │
   ├─ repo       pacman sync DBs → dependency resolver (provides, groups,
   │             vercmp) → parallel, SHA-256-verified downloads (cached)
   ├─ ingest     .pkg.tar.zst streamed into an in-memory POSIX VFS
   │             (owners, modes, setuid, symlinks, hard links, xattrs);
   │             payloads spooled to a pack file so RAM stays flat;
   │             pacman local DB written so `pacman -Q` works in the image
   ├─ overlays   Windows folders laid over / (CRLF → LF for text)
   ├─ mutations  passwd/group/shadow from `filesystem` + sysusers.d + your
   │             users; systemctl-enable semantics; default networking;
   │             hooks needing Linux binaries deferred to first boot
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

| Firmware | Boot path |
|---|---|
| BIOS, DVD | El Torito → ISOLINUX (`/boot/syslinux`) → menu → kernel + initramfs |
| BIOS, USB | isohybrid MBR (`isohdpfx`) → ISOLINUX → … |
| UEFI, DVD | El Torito EFI entry → ESP image → `\EFI\BOOT\BOOTX64.EFI` (systemd-boot) |
| UEFI, USB | MBR partition type 0xEF → same ESP → systemd-boot |

Torito runs anywhere Python does. Linux and macOS work too, but Windows is
the platform it exists for.

## Development

```powershell
git clone https://github.com/DeadFromInside-skibidi/torito
cd torito
pip install -e .
python -m unittest discover -s tests -v
```

The test suite works offline and ends with an end-to-end build of a bootable
ISO from synthetic packages. CI also builds the `console` template from the
real Arch repositories on Windows and Linux, and boots it in QEMU under BIOS
and UEFI. See [CONTRIBUTING.md](CONTRIBUTING.md) and
[CHANGELOG.md](CHANGELOG.md).

## License

MIT. See [LICENSE](LICENSE). Torito downloads Arch Linux packages at build
time; each package keeps its own license, and an ISO you distribute is a
Linux distribution, so the usual GPL source-availability obligations apply.
