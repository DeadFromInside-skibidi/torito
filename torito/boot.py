"""
torito.boot — Bootloader Configuration & Boot Layout
====================================================
Generates the boot menus and decides where every boot artefact lives:

* **BIOS** — ISOLINUX (El Torito no-emulation, boot-info-table) with a
  menu, plus an isohybrid MBR so the image also boots from USB.
* **UEFI** — systemd-boot as ``/EFI/BOOT/BOOTX64.EFI`` inside a FAT EFI
  System Partition image that also carries the kernel, microcode and
  initramfs (El Torito EFI entry + MBR partition 0xEF for USB).

Kernel arguments always identify the medium by volume label
(``torito.label=``), which is what the Torito initramfs looks for.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .config import BuildConfig

KERNEL_ISO_PATH = "/boot/x86_64/vmlinuz"
INITRD_ISO_PATH = "/boot/x86_64/initramfs.img"
SQUASHFS_ISO_PATH = "/live/x86_64/rootfs.sfs"
SYSLINUX_DIR = "/boot/syslinux"

SYSLINUX_MODULES = ["ldlinux.c32", "menu.c32", "libutil.c32", "libcom32.c32", "reboot.c32", "poweroff.c32"]


@dataclass
class BootEntry:
    key: str
    title: str
    cmdline: str


def base_cmdline(config: BuildConfig) -> str:
    args = [f"torito.label={config.iso.volume_id}"]
    if config.live.copytoram:
        args.append("torito.copytoram")
    if config.live.overlay_size and config.live.overlay_size != "75%":
        args.append(f"torito.overlay_size={config.live.overlay_size}")
    extra = config.kernel.cmdline.strip()
    # Legacy manifests put dracut-style "root=live:..." here; drop those.
    extra = " ".join(a for a in extra.split() if not a.startswith(("root=live:", "rd.live.")))
    if extra:
        args.append(extra)
    if config.live.serial_console and not any(a.startswith("console=") for a in extra.split()):
        args += ["console=ttyS0,115200", "console=tty0"]
    return " ".join(args)


def boot_entries(config: BuildConfig) -> List[BootEntry]:
    title = config.bootloader.menu_title or f"{config.name} {config.version}"
    base = base_cmdline(config)
    entries = [
        BootEntry("live", f"{title} (live)", base),
        BootEntry("safe", f"{title} (safe graphics)", base + " nomodeset"),
    ]
    if "torito.copytoram" not in base:
        entries.append(BootEntry("ram", f"{title} (copy to RAM)", base + " torito.copytoram"))
    for i, e in enumerate(config.bootloader.extra_entries):
        entries.append(BootEntry(f"extra{i}", e.get("title", f"Entry {i}"), base + " " + e.get("cmdline", "")))
    return entries


def generate_syslinux_cfg(config: BuildConfig, initrds: List[str]) -> str:
    title = config.bootloader.menu_title or f"{config.name} {config.version}"
    lines = []
    if config.live.serial_console:
        lines.append("SERIAL 0 115200")
    lines += [
        "UI menu.c32",
        f"MENU TITLE {title}",
        "PROMPT 0",
        f"TIMEOUT {max(1, config.bootloader.timeout) * 10}",
        "DEFAULT live",
        "",
    ]
    for e in boot_entries(config):
        lines += [
            f"LABEL {e.key}",
            f"    MENU LABEL {e.title}",
            f"    LINUX {KERNEL_ISO_PATH}",
            f"    INITRD {','.join(initrds)}",
            f"    APPEND {e.cmdline}",
            "",
        ]
    lines += [
        "LABEL reboot",
        "    MENU LABEL Reboot",
        "    COM32 reboot.c32",
        "",
        "LABEL poweroff",
        "    MENU LABEL Power off",
        "    COM32 poweroff.c32",
        "",
    ]
    return "\n".join(lines)


def generate_systemd_boot_entries(config: BuildConfig, initrds: Optional[List[str]] = None) -> Dict[str, str]:
    initrds = initrds or [INITRD_ISO_PATH]
    out: Dict[str, str] = {}
    entries = boot_entries(config)
    out["/loader/loader.conf"] = (
        f"timeout {max(0, config.bootloader.timeout)}\n"
        f"default 01-{entries[0].key}.conf\n"
        "editor yes\n"
        "console-mode auto\n"
    )
    for i, e in enumerate(entries, 1):
        body = f"title   {e.title}\nlinux   {KERNEL_ISO_PATH}\n"
        body += "".join(f"initrd  {p}\n" for p in initrds)
        body += f"options {e.cmdline}\n"
        out[f"/loader/entries/{i:02d}-{e.key}.conf"] = body
    return out


# Backwards-compatible generators (older API) -------------------------------


def generate_isolinux_cfg(config: BuildConfig) -> str:
    return generate_syslinux_cfg(config, [INITRD_ISO_PATH])


def generate_grub_cfg(config: BuildConfig) -> str:
    entries = boot_entries(config)
    out = [f"set default=0\nset timeout={config.bootloader.timeout}\n"]
    out.append(f"search --no-floppy --set=root --label {config.iso.volume_id}\n")
    for e in entries:
        out.append(f'menuentry "{e.title}" {{\n    linux {KERNEL_ISO_PATH} {e.cmdline}\n    initrd {INITRD_ISO_PATH}\n}}\n')
    return "\n".join(out)


def generate_limine_cfg(config: BuildConfig) -> str:
    out = [f"timeout: {config.bootloader.timeout}\n"]
    for e in boot_entries(config):
        out.append(f"/{e.title}\n    protocol: linux\n    kernel_path: boot():{KERNEL_ISO_PATH}\n"
                   f"    module_path: boot():{INITRD_ISO_PATH}\n    cmdline: {e.cmdline}\n")
    return "\n".join(out)


def generate_startup_nsh(config: BuildConfig) -> str:
    return f"@echo -off\n\\EFI\\BOOT\\BOOTX64.EFI\n"
