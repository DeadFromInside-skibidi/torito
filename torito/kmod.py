"""
torito.kmod — Kernel Discovery & Module Dependency Resolution
=============================================================
A pure-Python stand-in for ``depmod``/``modinfo``: indexes the kernel
modules found in the VFS, reads each module's ELF ``.modinfo`` section
(``depends=``, ``softdep=``, ``alias=``) and computes load-ordered
dependency closures for the initramfs.
"""

from __future__ import annotations

import gzip
import lzma
import struct
from dataclasses import dataclass, field
from typing import Callable, Dict, Iterable, List, Optional, Set, Tuple

from .vfs import PosixVfs, VfsNodeType

MODULE_EXTS = (".ko.zst", ".ko.xz", ".ko.gz", ".ko")


def decompress_module(data: bytes) -> bytes:
    if data[:4] == b"\x28\xb5\x2f\xfd":
        import zstandard

        return zstandard.ZstdDecompressor().decompressobj().decompress(data)
    if data[:6] == b"\xfd7zXZ\x00":
        return lzma.decompress(data)
    if data[:2] == b"\x1f\x8b":
        return gzip.decompress(data)
    return data


def elf_section(data: bytes, wanted: str) -> Optional[bytes]:
    """Return the raw bytes of section *wanted* from a 64- or 32-bit ELF."""
    if data[:4] != b"\x7fELF":
        return None
    is64 = data[4] == 2
    endian = "<" if data[5] == 1 else ">"
    try:
        if is64:
            shoff = struct.unpack_from(endian + "Q", data, 0x28)[0]
            shentsize, shnum, shstrndx = struct.unpack_from(endian + "HHH", data, 0x3A)
        else:
            shoff = struct.unpack_from(endian + "I", data, 0x20)[0]
            shentsize, shnum, shstrndx = struct.unpack_from(endian + "HHH", data, 0x2E)

        def sh(i: int) -> Tuple[int, int, int]:
            base = shoff + i * shentsize
            if is64:
                name, _type, _flags, _addr, off, size = struct.unpack_from(endian + "IIQQQQ", data, base)
            else:
                name, _type, _flags, _addr, off, size = struct.unpack_from(endian + "IIIIII", data, base)
            return name, off, size

        _, str_off, str_size = sh(shstrndx)
        strtab = data[str_off: str_off + str_size]
        for i in range(shnum):
            name_off, off, size = sh(i)
            end = strtab.find(b"\x00", name_off)
            if strtab[name_off:end].decode("ascii", "replace") == wanted:
                return data[off: off + size]
    except struct.error:
        return None
    return None


def parse_modinfo(blob: bytes) -> Dict[str, List[str]]:
    info: Dict[str, List[str]] = {}
    for item in blob.split(b"\x00"):
        if b"=" not in item:
            continue
        k, v = item.split(b"=", 1)
        info.setdefault(k.decode("ascii", "replace"), []).append(v.decode("utf-8", "replace"))
    return info


def norm_mod(name: str) -> str:
    return name.replace("-", "_")


@dataclass
class KernelModule:
    name: str
    path: str  # VFS path of the (possibly compressed) module
    rel: str  # path relative to /usr/lib/modules/<kver>/, without compression suffix
    _info: Optional[Dict[str, List[str]]] = None
    _raw: Optional[bytes] = None


@dataclass
class KernelInfo:
    version: str
    vmlinuz_path: str  # VFS path
    modules_root: str  # /usr/lib/modules/<kver>
    pkgbase: str = ""
    modules: Dict[str, KernelModule] = field(default_factory=dict)
    builtin: Set[str] = field(default_factory=set)


def find_kernels(vfs: PosixVfs) -> List[KernelInfo]:
    """Locate kernels shipped the modern way: /usr/lib/modules/<kver>/vmlinuz."""
    out: List[KernelInfo] = []
    base = vfs.resolve("/usr/lib/modules", follow_last=True)
    for kver in vfs.list_dir(base):
        root = f"{base}/{kver}"
        vm = f"{root}/vmlinuz"
        node = vfs.lookup(vm)
        if node is None or node.node_type != VfsNodeType.REGULAR_FILE:
            continue
        pkgbase = (vfs.read_file(f"{root}/pkgbase") or b"").decode().strip()
        out.append(KernelInfo(version=kver, vmlinuz_path=vm, modules_root=root, pkgbase=pkgbase))
    return out


def index_modules(vfs: PosixVfs, kernel: KernelInfo) -> None:
    root = kernel.modules_root
    for path, node in vfs.iter_subtree(root):
        if node.node_type != VfsNodeType.REGULAR_FILE:
            continue
        fname = path.rsplit("/", 1)[-1]
        for ext in MODULE_EXTS:
            if fname.endswith(ext):
                name = norm_mod(fname[: -len(ext)])
                rel = path[len(root) + 1:]
                rel = rel[: len(rel) - len(ext)] + ".ko"
                kernel.modules.setdefault(name, KernelModule(name=name, path=path, rel=rel))
                break
    builtin = vfs.read_file(f"{root}/modules.builtin") or b""
    for line in builtin.decode("utf-8", "replace").splitlines():
        line = line.strip()
        if line.endswith(".ko"):
            kernel.builtin.add(norm_mod(line.rsplit("/", 1)[-1][:-3]))


def module_raw(vfs: PosixVfs, mod: KernelModule) -> bytes:
    if mod._raw is None:
        node = vfs.lookup(mod.path)
        mod._raw = decompress_module(node.data if node is not None else b"")
    return mod._raw


def module_info(vfs: PosixVfs, mod: KernelModule) -> Dict[str, List[str]]:
    if mod._info is None:
        sec = elf_section(module_raw(vfs, mod), ".modinfo") or b""
        mod._info = parse_modinfo(sec)
    return mod._info


def resolve_modules(
    vfs: PosixVfs,
    kernel: KernelInfo,
    wanted: Iterable[str],
    log: Callable[[str], None] = lambda m: None,
) -> List[KernelModule]:
    """Dependency closure of *wanted*, ordered so dependencies load first."""
    order: List[KernelModule] = []
    seen: Set[str] = set()
    missing: List[str] = []

    def visit(name: str, optional: bool) -> None:
        n = norm_mod(name)
        if n in seen:
            return
        seen.add(n)
        if n in kernel.builtin:
            return
        mod = kernel.modules.get(n)
        if mod is None:
            if not optional:
                missing.append(n)
            return
        info = module_info(vfs, mod)
        for dep_line in info.get("depends", []):
            for d in dep_line.split(","):
                if d.strip():
                    visit(d.strip(), False)
        for soft in info.get("softdep", []):
            # "pre: a b post: c" — only 'pre' deps must be present first.
            mode = ""
            for tok in soft.split():
                if tok.endswith(":"):
                    mode = tok[:-1]
                elif mode == "pre":
                    visit(tok, True)
        order.append(mod)

    for w in wanted:
        visit(w, True)
    if missing:
        log("  modules not found (ignored): " + ", ".join(sorted(set(missing))))
    return order


# Drivers needed to find and mount the live medium on real hardware and in
# the common hypervisors (VMware, VirtualBox, QEMU/KVM, Hyper-V).
LIVE_MODULES: List[str] = [
    # optical / block / filesystems used by the live boot
    "sr_mod", "cdrom", "sd_mod", "isofs", "squashfs", "overlay", "loop",
    # legacy IDE / SATA
    "ata_piix", "pata_acpi", "ata_generic", "pata_amd", "pata_via", "pata_oldpiix",
    "pata_atiixp", "pata_jmicron", "pata_marvell", "pata_sis", "ahci", "libahci", "libata",
    # paravirtual / hypervisor storage
    "virtio_blk", "virtio_scsi", "virtio_pci", "vmw_pvscsi", "mptspi", "mptsas",
    "BusLogic", "hv_storvsc", "hv_vmbus", "xen_blkfront",
    # NVMe / SD
    "nvme", "mmc_block", "sdhci_pci", "sdhci_acpi", "rtsx_pci_sdmmc",
    # USB storage
    "xhci_pci", "xhci_plat_hcd", "ehci_pci", "ohci_pci", "uhci_hcd", "usb_storage", "uas",
    # keyboard for the rescue shell
    "hid_generic", "usbhid", "atkbd", "i8042",
    # filesystems that copytoram / persistence might need
    "vfat", "nls_cp437", "nls_iso8859_1", "nls_utf8",
]
