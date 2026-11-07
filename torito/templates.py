"""
torito.templates - Ready-to-build project templates
===================================================
``torito --init DIR --template NAME`` writes one of these: a manifest plus
the overlay files it needs, so a first build works without knowing what a
display manager, an autologin group or a sudoers drop-in is.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Dict, List


@dataclass
class Template:
    name: str
    summary: str
    manifest: str
    files: Dict[str, str] = field(default_factory=dict)  # overlay-relative path → text


_COMMON_HEADER = """# Torito build manifest for {name}
# Build:  torito distro.toml          (or: python -m torito distro.toml)
# Every option is documented in example.toml in the Torito repository.
name        = "{name}"
version     = "1.0.0"
arch        = "x86_64"
hostname    = "{host}"
locale      = "en_US.UTF-8"
timezone    = "UTC"
keymap      = "us"

# Files copied over the root filesystem (Windows line endings are fixed).
rootfs_overlay_dirs = ["overlays/rootfs"]

# Windows cannot store Linux owners/modes - set the ones that matter here.
file_permissions = {{ "/etc/sudoers.d/10-wheel" = "0:0:440" }}

# NOTE: plain `key = value` settings must stay above the first [table] or
# [[table]] header below - TOML puts later keys inside that table.
"""

_COMMON_FOOTER = """
[iso]
output    = "output/{slug}-x86_64.iso"
volume_id = "{label}"
"""

CONSOLE = Template(
    name="console",
    summary="text-mode live system with networking, sudo and editors (~900 MiB ISO)",
    manifest=_COMMON_HEADER + """default_target = "multi-user.target"

# Packages come from the Arch Linux repositories (core + extra) and their
# dependencies are resolved automatically. 'base' and a kernel are added
# for you if you leave them out.
packages = [
    "base", "linux", "linux-firmware", "intel-ucode", "amd-ucode",
    "networkmanager", "sudo", "nano", "vim", "less", "man-db",
    "openssh", "curl", "htop",
]

[[users]]
name     = "live"
password = "live"
groups   = ["wheel", "audio", "video", "network", "storage", "input"]

[[users]]
name     = "root"
password = "root"

[[services]]
name = "NetworkManager"
""" + _COMMON_FOOTER,
    files={
        "etc/motd": "Welcome to {name}! Built with Torito.\nLog in as 'live' (password 'live'); sudo works. Wi-Fi: nmtui\n",
        "etc/sudoers.d/10-wheel": "%wheel ALL=(ALL:ALL) ALL\n",
    },
)

DESKTOP = Template(
    name="desktop",
    summary="XFCE desktop that logs straight in, with Firefox, Wi-Fi and sound (~1.4 GiB ISO)",
    manifest=_COMMON_HEADER + """default_target = "graphical.target"

packages = [
    "base", "linux", "linux-firmware", "intel-ucode", "amd-ucode",
    # graphics
    "xorg-server", "xorg-xinit", "mesa", "vulkan-swrast",
    # desktop
    "xfce4", "xfce4-terminal", "mousepad", "thunar-archive-plugin", "xfce4-pulseaudio-plugin",
    "xfce4-whiskermenu-plugin", "xfce4-screenshooter", "ristretto", "file-roller",
    "lightdm", "lightdm-gtk-greeter",
    "adwaita-icon-theme", "noto-fonts", "noto-fonts-emoji", "ttf-dejavu",
    # network & sound
    "networkmanager", "network-manager-applet", "pipewire", "pipewire-pulse",
    "pipewire-alsa", "wireplumber", "pavucontrol",
    # apps & tools
    "firefox", "gvfs", "sudo", "nano", "htop", "less",
]

[[users]]
name     = "live"
password = "live"
groups   = ["wheel", "audio", "video", "network", "storage", "input", "autologin"]

[[users]]
name     = "root"
password = "root"

[[services]]
name = "lightdm"                 # becomes display-manager.service

[[services]]
name = "NetworkManager"

[kernel]
cmdline = "quiet"
""" + _COMMON_FOOTER,
    files={
        "etc/motd": "Welcome to {name}! Built with Torito.\n",
        "etc/sudoers.d/10-wheel": "%wheel ALL=(ALL:ALL) ALL\n",
        # Log the live user straight into XFCE (LightDM requires the
        # 'autologin' group membership granted above).
        "etc/lightdm/lightdm.conf.d/50-torito-autologin.conf": (
            "[Seat:*]\nautologin-user=live\nautologin-session=xfce\nuser-session=xfce\n"
        ),
    },
)

SERVER = Template(
    name="server",
    summary="headless rescue/server image: SSH on, DHCP networking, disk tools (~800 MiB ISO)",
    manifest=_COMMON_HEADER + """default_target = "multi-user.target"

# No network manager is listed, so Torito configures systemd-networkd with
# DHCP on every wired interface automatically.
packages = [
    "base", "linux", "linux-firmware",
    "openssh", "sudo", "nano", "vim", "less", "htop", "tmux", "rsync", "curl",
    "parted", "gptfdisk", "dosfstools", "e2fsprogs", "btrfs-progs", "xfsprogs", "ntfs-3g",
    "lvm2", "cryptsetup", "mdadm", "smartmontools", "nvme-cli", "ddrescue", "testdisk",
]

[[users]]
name     = "admin"
password = "admin"                # change this before you share the image!
groups   = ["wheel"]

[[users]]
name     = "root"
password = "root"

[[services]]
name = "sshd"
""" + _COMMON_FOOTER,
    files={
        "etc/motd": "{name} rescue system. SSH is running; log in as 'admin'.\n",
        "etc/sudoers.d/10-wheel": "%wheel ALL=(ALL:ALL) ALL\n",
    },
)

TEMPLATES: Dict[str, Template] = {t.name: t for t in (CONSOLE, DESKTOP, SERVER)}
DEFAULT_TEMPLATE = "console"


def template_names() -> List[str]:
    return list(TEMPLATES)


def scaffold_project(target_dir: str, template: str = DEFAULT_TEMPLATE, name: str = "") -> str:
    """Create a project directory from *template*; return the manifest path."""
    if template not in TEMPLATES:
        raise ValueError(f"unknown template {template!r} (choose from: {', '.join(TEMPLATES)})")
    tpl = TEMPLATES[template]
    abs_dir = os.path.abspath(target_dir)
    manifest = os.path.join(abs_dir, "distro.toml")
    if os.path.exists(manifest):
        raise FileExistsError(f"{manifest} already exists - refusing to overwrite it")
    base = os.path.basename(abs_dir.rstrip("\\/")) or "mydistro"
    name = name or (base[:1].upper() + base[1:])
    slug = re.sub(r"[^a-z0-9_-]+", "-", name.lower()).strip("-_") or "mydistro"
    host = re.sub(r"[^a-z0-9-]+", "-", slug).strip("-")[:63] or "mydistro"
    label = re.sub(r"[^A-Z0-9_]", "_", slug.upper())[:26] + "_LIVE"
    fmt = {"name": name.replace('"', ""), "slug": slug, "host": host, "label": label}
    os.makedirs(os.path.join(abs_dir, "overlays", "rootfs"), exist_ok=True)
    os.makedirs(os.path.join(abs_dir, "output"), exist_ok=True)
    for rel, text in tpl.files.items():
        path = os.path.join(abs_dir, "overlays", "rootfs", *rel.split("/"))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text.format(**fmt))
    with open(manifest, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(tpl.manifest.format(**fmt))
    with open(os.path.join(abs_dir, ".gitignore"), "w", encoding="utf-8", newline="\n") as fh:
        fh.write("output/\n.torito-cache/\n.torito-work/\n")
    return manifest
