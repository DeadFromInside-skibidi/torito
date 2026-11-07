# Torito — Rootless Linux ISO Compiler

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform: Windows](https://img.shields.io/badge/Platform-Windows%2010%2F11-0078D6.svg)](https://microsoft.com)
[![Python: 3.10+](https://img.shields.io/badge/Python-3.10%2B-3776AB.svg)](https://python.org)
[![Zero Host Dependencies](https://img.shields.io/badge/Zero%20Dependencies-No%20WSL2%20%7C%20No%20Docker%20%7C%20No%20Root-brightgreen.svg)]()

**Torito** is an industrial-grade, pure userspace, Windows-native Linux distribution compiler. It synthesizes bit-for-bit reproducible, bootable hybrid **BIOS (El Torito) / UEFI (GPT + ESP)** Linux `.iso` images directly on Windows NTFS **without WSL2, Docker, hypervisors, `chroot`, or loopback mounts**.

---

## The Problem: Distro Building on Non-Linux Hosts

Historically, assembling a Linux ISO image has required a running Linux kernel with root privileges:
* `chroot` to run `systemctl enable`, `useradd`, and package post-install scripts.
* `mknod` to create character and block device nodes (`/dev/console`, `/dev/null`).
* `mkinitcpio` or `dracut` to build the initramfs CPIO archive.
* `mksquashfs` to serialize the rootfs into SquashFS.
* `mount -o loop` and `mkfs.vfat` to build the EFI System Partition (`efiboot.img`).
* `xorriso` to master the hybrid ISO9660 image with El Torito and GPT tables.

On Windows, developers have been forced into slow, heavy VMs (WSL2, Hyper-V, or Docker containers). Furthermore, checking out Linux distribution files directly onto NTFS mangles Linux permissions (no `04755` `suid` bit), strips symbolic links, and introduces Windows `CRLF` (`\r\n`) line endings that break Linux shell scripts and systemd units.

---

## The Solution: Pure Userspace State Synthesis

Torito proves that **every step in a Linux OS build is simply bytes placed at specific offsets inside well-defined binary formats**. None of them require a running Linux kernel:

```
┌────────────────────────────────────────────────────────────────────────┐
│                          Declarative Manifest                          │
│               (distro.toml / distro.json / distro.ini)                 │
└──────────────────────────────────┬─────────────────────────────────────┘
                                   │
                                   ▼
┌────────────────────────────────────────────────────────────────────────┐
│                 In-Memory POSIX Virtual Filesystem (VFS)               │
│  • BTreeMap<Path, VfsNode> with Linux UID/GID, octal modes (04755 suid) │
│  • Auto-strips Windows CRLF (\r\n -> \n) across scripts and configs    │
│  • Ingests overlays and packages (.pkg.tar.zst / .deb / .apk)          │
│  • Forges /dev device nodes in metadata without calling mknod          │
└──────────────────────────────────┬─────────────────────────────────────┘
                                   │
       ┌───────────────────────────┼───────────────────────────┐
       ▼                           ▼                           ▼
┌──────────────┐           ┌──────────────┐            ┌──────────────┐
│ State Module │           │ CPIO Module  │            │ SquashFS     │
│ • SHA-512 $6$│           │ • SVR4 newc  │            │ • SquashFS 4 │
│   shadow hash│           │   structs    │            │ • Inode/Dir  │
│ • systemd /  │           │ • Multithread│            │   tables     │
│   openrc /   │           │   Zstd initrd│            │ • Tail frags │
│   runit links│           └──────┬───────┘            └──────┬───────┘
└──────┬───────┘                  │                           │
       └──────────────────────────┼───────────────────────────┘
                                  │
                                  ▼
       ┌───────────────────────────────────────────────────────┐
       │ In-Memory FAT32 EFI System Partition (efiboot.img)    │
       │ • Sector 0 BPB + FSInfo + dual FAT32 tables           │
       │ • /EFI/BOOT/BOOTX64.EFI + kernel + initramfs          │
       └──────────────────────────┬────────────────────────────┘
                                  │
                                  ▼
       ┌───────────────────────────────────────────────────────┐
       │ Hybrid ISO9660 + El Torito + GPT Assembler            │
       │ • LBA 0: Protective MBR (0xEE)                        │
       │ • LBA 1-33: Primary GPT header & partition table      │
       │ • Sector 16: Primary Volume Descriptor (PVD)          │
       │ • Sector 17: El Torito Boot Record (BRVD)             │
       │ • El Torito multi-boot catalog (BIOS x86 + UEFI EFI)  │
       │ • Backup GPT at end of disk                           │
       └──────────────────────────┬────────────────────────────┘
                                  │
                                  ▼
                     Bootable Hybrid Linux .iso
          (Writes directly to host NTFS disk; USB dd-bootable)
```

---

## Architectural Highlights

### 1. In-Memory POSIX Virtual Filesystem (`torito.vfs`)
Maintains an ordered tree of POSIX inodes in memory. Windows NTFS metadata is never consulted.
* Tracks Linux `UID`, `GID`, and full octal mode words (`0755`, `0644`, `04755` `suid`).
* Symbolic links (`VfsNodeType.SYMLINK`) and device nodes (`VfsNodeType.CHAR_DEVICE`, `VfsNodeType.BLOCK_DEVICE`) exist purely in metadata without host kernel restrictions.
* **CRLF Sanitizer**: Files detected as scripts (shebang `#!`, `.sh`, `.conf`, `.service`, etc.) automatically have `\r\n` converted to `\n` in transit.

### 2. Rootless State Synthesis (`torito.mutations`)
Eliminates `chroot` by deterministically generating system files:
* **`/etc/shadow`**: Pure-Python implementation of Ulrich Drepper's glibc **SHA-512 crypt (`$6$`)** hashing algorithm.
* **`/etc/passwd` & `/etc/group`**: Auto-populates standard Linux system accounts and injects user accounts, group memberships, and home skeletons (`.bashrc`).
* **Service Wiring**: Directly inserts symlinks for **systemd** (`/etc/systemd/system/*.wants/`), **OpenRC** (`/etc/runlevels/`), and **runit** (`/var/service/`).

### 3. SVR4 New ASCII CPIO Packer (`torito.cpio`)
Produces Linux initramfs archives conforming to the SVR4 `newc` (`070701`) standard:
* Packed with strict 110-byte ASCII hex headers and 4-byte payload padding.
* Compresses using multi-threaded **Zstandard (`zstd`)**, gzip, or xz.
* Tested and verified against standard GNU/BSD `cpio` and `tar` unpackers.

### 4. Direct VFS-to-SquashFS 4.0 Serialization (`torito.squashfs`)
Serializes the virtual tree into a bit-for-bit reproducible SquashFS image:
* Full SquashFS 4.0 superblock (96 bytes).
* Metadata block streaming (8192-byte blocks with 2-byte headers).
* Inode table supporting regular files, directories, symlinks, device nodes, and FIFOs.
* Grouped directory tables with 16-bit signed inode deltas.
* Tail and small-file fragment packing for maximum storage efficiency.
* 4096-byte sector alignment.

### 5. Loopback-Free In-Memory FAT32 ESP (`torito.fat32`)
Constructs the UEFI boot partition without `mount -o loop` or external binaries:
* Formats a complete FAT32 volume in memory (BPB, FSInfo, FAT1 & FAT2 mirroring).
* Emits standard 8.3 short names and UTF-16LE VFAT Long Filename (LFN) entries.
* Populates `/EFI/BOOT/BOOTX64.EFI`, `/vmlinuz`, and `/initramfs.img`.

### 6. Hybrid ISO9660 + El Torito + GPT Assembler (`torito.iso9660`)
Produces images that boot both via optical media (CD/DVD) and USB flash drives:
* **El Torito Boot Catalog**: Multi-platform catalog with default BIOS boot entry (no emulation) and EFI section entry pointing to `efiboot.img`.
* **Isohybrid MBR**: Protective MBR at LBA 0 with partition type `0xEE`.
* **Dual GPT**: Primary GPT at LBA 1-33 and Backup GPT at disk end, pointing directly to the embedded EFI System Partition.

---

## User Interface: Native Windows 10 GUI

Torito includes a classic Windows 10 dialog-box style Tkinter GUI:
* Built with `ttk` utilizing the native Windows `vista` theme and `#F0F0F0` system surfaces.
* Native Win32 group frames and directory browse dialogs.
* **Threaded Non-Blocking Controller**: The build engine executes on a background thread; the UI remains 100% responsive.
* **Determinate Progress Bar**: Reflects exact pipeline stage execution.
* **Real-Time Scrolling Telemetry Console**: Displays formatted build events, compression ratios, and stage milestones.

To launch the GUI:
```powershell
python -m torito
```

---

## Installation

```powershell
# Clone the repository
git clone https://github.com/DeadFromInside-skibidi/torito.git
cd torito

# Install dependencies (only zstandard is required)
pip install -r requirements.txt

# Install the package in editable mode
pip install -e .
```

---

## Declarative Build Manifest

Torito supports **TOML**, **JSON**, and **INI/Conf** formats. Here is an example `distro.toml`:

```toml
name        = "ToritoLinux"
version     = "1.0.0"
arch        = "x86_64"
hostname    = "torito-live"
locale      = "en_US.UTF-8"
timezone    = "UTC"

# Rootfs overlay directories from Windows
rootfs_overlay_dirs = [
    "overlays/rootfs",
]

# Packages to ingest (.pkg.tar.zst, .deb, .apk)
[[packages]]
path   = "packages/base-system.pkg.tar.zst"
format = "auto"

# Kernel and bootloader
[kernel]
vmlinuz = "boot/vmlinuz-linux"
cmdline = "root=live:CDLABEL=TORITO rd.live.image quiet splash"

[bootloader]
efi_binary = "boot/BOOTX64.EFI"

# Users and groups
[[users]]
name     = "liveuser"
uid      = 1000
gid      = 1000
password = "livepassword"
groups   = ["wheel", "audio", "video"]

# Enabled services
[[services]]
name        = "NetworkManager"
init_system = "systemd"

# ISO output configuration
[iso]
output               = "output/torito-x86_64.iso"
volume_id            = "TORITO"
squashfs_compression = "zstd"
```

---

## CLI Usage

Build headlessly from any Windows shell or CI/CD runner:

```powershell
# Build ISO from manifest
python -m torito distro.toml

# Verbose telemetry output
python -m torito distro.toml -v

# Launch GUI explicitly
python -m torito --gui
```

---

## Python API Usage

You can also use Torito as an embedded library in your own build pipelines:

```python
from torito.vfs import PosixVfs
from torito.config import load_config
from torito.mutations import apply_all_mutations
from torito.squashfs import build_squashfs
from torito.fat32 import build_efi_esp
from torito.iso9660 import build_hybrid_iso

# 1. Load manifest
cfg = load_config("distro.toml")

# 2. Populate VFS
vfs = PosixVfs(source_date_epoch=cfg.source_date_epoch)
vfs.init_base_hierarchy()
apply_all_mutations(vfs, cfg)

# 3. Serialize rootfs to SquashFS
squashfs_bytes = build_squashfs(vfs, compression="zstd")

# 4. Build in-memory EFI System Partition
esp_bytes = build_efi_esp(efi_binary=open("BOOTX64.EFI", "rb").read())

# 5. Master hybrid ISO
iso_bytes = build_hybrid_iso(
    files={"/live/filesystem.squashfs": squashfs_bytes},
    efi_boot_image=esp_bytes,
    volume_id="TORITO",
)

with open("output/torito.iso", "wb") as f:
    f.write(iso_bytes)
```

---

## Test Suite

Run the exhaustive test suite verifying all binary structures, hashing, packing, and full pipeline builds:

```powershell
python -m unittest tests/test_torito.py -v
```

---

## License

MIT License. See [LICENSE](LICENSE) for details.

