"""
torito.config — Declarative Build Manifest Parser
===================================================
Parses TOML, JSON, or INI build manifests into a strongly-typed
``BuildConfig`` dataclass that drives every stage of the ISO compiler.
"""

from __future__ import annotations

import configparser
import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class UserSpec:
    """Specification for a system user to synthesise."""

    name: str
    uid: int
    gid: int
    home: str = "/home"
    shell: str = "/bin/bash"
    password: str = ""  # plaintext; hashed at synthesis time
    groups: List[str] = field(default_factory=list)
    gecos: str = ""

    def home_dir(self) -> str:
        if self.home.endswith("/"):
            return self.home + self.name
        if self.name in self.home:
            return self.home
        return self.home + "/" + self.name


@dataclass
class GroupSpec:
    """Specification for a system group to synthesise."""

    name: str
    gid: int
    members: List[str] = field(default_factory=list)


@dataclass
class ServiceSpec:
    """Specification for a service to enable at boot."""

    name: str
    init_system: str = "systemd"  # systemd | openrc | runit
    target: str = "multi-user.target"  # systemd target
    runlevel: str = "default"  # openrc runlevel


@dataclass
class PackageSpec:
    """Specification for a package archive to ingest."""

    path: str  # local filesystem path to .pkg.tar.zst / .deb / .apk
    format: str = "auto"  # auto | pacman | deb | apk


@dataclass
class KernelSpec:
    """Specification for the Linux kernel and initramfs."""

    vmlinuz_path: str = ""
    modules_dir: str = ""
    initramfs_extra_dirs: List[str] = field(default_factory=list)
    initramfs_extra_files: List[str] = field(default_factory=list)
    cmdline: str = "root=live:CDLABEL=TORITO rd.live.image quiet splash"


@dataclass
class BootloaderSpec:
    """Specification for the EFI/BIOS bootloader."""

    efi_binary_path: str = ""  # Path to BOOTX64.EFI (GRUB, Limine, systemd-boot)
    bios_binary_path: str = ""  # Path to El Torito BIOS boot image (e.g., isolinux.bin)
    boot_catalog_path: str = "boot/boot.cat"


@dataclass
class IsoSpec:
    """Specification for the output ISO image."""

    output_path: str = "torito-x86_64.iso"
    volume_id: str = "TORITO"
    volume_set_id: str = ""
    publisher_id: str = "Torito ISO Compiler"
    application_id: str = "TORITO"
    system_id: str = "LINUX"
    squashfs_compression: str = "zstd"
    squashfs_block_size: int = 131072  # 128 KiB


@dataclass
class BuildConfig:
    """
    Top-level build configuration parsed from a TOML/JSON/INI manifest.

    Every field has a sensible default so that minimal manifests work
    out of the box.
    """

    name: str = "torito-linux"
    version: str = "1.0.0"
    arch: str = "x86_64"
    source_date_epoch: Optional[int] = None

    # Directory layout
    project_dir: str = "."
    rootfs_overlay_dirs: List[str] = field(default_factory=list)
    packages: List[PackageSpec] = field(default_factory=list)
    kernel: KernelSpec = field(default_factory=KernelSpec)
    bootloader: BootloaderSpec = field(default_factory=BootloaderSpec)
    iso: IsoSpec = field(default_factory=IsoSpec)

    # Users and groups
    users: List[UserSpec] = field(default_factory=list)
    groups: List[GroupSpec] = field(default_factory=list)

    # Services
    services: List[ServiceSpec] = field(default_factory=list)

    # Hostname and locale
    hostname: str = "torito"
    locale: str = "en_US.UTF-8"
    timezone: str = "UTC"
    keymap: str = "us"


def _parse_user(raw: Dict[str, Any]) -> UserSpec:
    return UserSpec(
        name=str(raw.get("name", "user")),
        uid=int(raw.get("uid", 1000)),
        gid=int(raw.get("gid", 1000)),
        home=str(raw.get("home", "/home")),
        shell=str(raw.get("shell", "/bin/bash")),
        password=str(raw.get("password", "")),
        groups=list(raw.get("groups", [])),
        gecos=str(raw.get("gecos", "")),
    )


def _parse_group(raw: Dict[str, Any]) -> GroupSpec:
    return GroupSpec(
        name=str(raw.get("name", "users")),
        gid=int(raw.get("gid", 100)),
        members=list(raw.get("members", [])),
    )


def _parse_service(raw: Dict[str, Any]) -> ServiceSpec:
    return ServiceSpec(
        name=str(raw.get("name", "")),
        init_system=str(raw.get("init_system", "systemd")),
        target=str(raw.get("target", "multi-user.target")),
        runlevel=str(raw.get("runlevel", "default")),
    )


def _parse_package(raw: Dict[str, Any]) -> PackageSpec:
    return PackageSpec(
        path=str(raw.get("path", "")),
        format=str(raw.get("format", "auto")),
    )


def _populate_from_dict(cfg: BuildConfig, d: Dict[str, Any], project_dir: str) -> None:
    """Fill a ``BuildConfig`` from a parsed dict (TOML or JSON root)."""
    cfg.name = str(d.get("name", cfg.name))
    cfg.version = str(d.get("version", cfg.version))
    cfg.arch = str(d.get("arch", cfg.arch))
    cfg.hostname = str(d.get("hostname", cfg.hostname))
    cfg.locale = str(d.get("locale", cfg.locale))
    cfg.timezone = str(d.get("timezone", cfg.timezone))
    cfg.keymap = str(d.get("keymap", cfg.keymap))
    cfg.project_dir = project_dir

    epoch = d.get("source_date_epoch")
    if epoch is not None:
        cfg.source_date_epoch = int(epoch)

    cfg.rootfs_overlay_dirs = [
        str(x) for x in d.get("rootfs_overlay_dirs", d.get("overlays", []))
    ]

    # Packages
    pkgs_raw = d.get("packages", [])
    for pr in pkgs_raw:
        if isinstance(pr, str):
            cfg.packages.append(PackageSpec(path=pr))
        elif isinstance(pr, dict):
            cfg.packages.append(_parse_package(pr))

    # Kernel
    kern = d.get("kernel", {})
    if isinstance(kern, dict):
        cfg.kernel = KernelSpec(
            vmlinuz_path=str(kern.get("vmlinuz", kern.get("vmlinuz_path", ""))),
            modules_dir=str(kern.get("modules_dir", "")),
            initramfs_extra_dirs=list(kern.get("initramfs_extra_dirs", [])),
            initramfs_extra_files=list(kern.get("initramfs_extra_files", [])),
            cmdline=str(kern.get("cmdline", cfg.kernel.cmdline)),
        )

    # Bootloader
    bl = d.get("bootloader", {})
    if isinstance(bl, dict):
        cfg.bootloader = BootloaderSpec(
            efi_binary_path=str(bl.get("efi_binary", bl.get("efi_binary_path", ""))),
            bios_binary_path=str(bl.get("bios_binary", bl.get("bios_binary_path", ""))),
            boot_catalog_path=str(bl.get("boot_catalog", cfg.bootloader.boot_catalog_path)),
        )

    # ISO
    iso = d.get("iso", {})
    if isinstance(iso, dict):
        cfg.iso = IsoSpec(
            output_path=str(iso.get("output", iso.get("output_path", cfg.iso.output_path))),
            volume_id=str(iso.get("volume_id", cfg.iso.volume_id)),
            volume_set_id=str(iso.get("volume_set_id", cfg.iso.volume_set_id)),
            publisher_id=str(iso.get("publisher_id", cfg.iso.publisher_id)),
            application_id=str(iso.get("application_id", cfg.iso.application_id)),
            system_id=str(iso.get("system_id", cfg.iso.system_id)),
            squashfs_compression=str(iso.get("squashfs_compression", cfg.iso.squashfs_compression)),
            squashfs_block_size=int(iso.get("squashfs_block_size", cfg.iso.squashfs_block_size)),
        )

    # Users
    for u in d.get("users", []):
        if isinstance(u, dict):
            cfg.users.append(_parse_user(u))

    # Groups
    for g in d.get("groups", []):
        if isinstance(g, dict):
            cfg.groups.append(_parse_group(g))

    # Services
    for s in d.get("services", []):
        if isinstance(s, dict):
            cfg.services.append(_parse_service(s))
        elif isinstance(s, str):
            cfg.services.append(ServiceSpec(name=s))


def load_config(manifest_path: str) -> BuildConfig:
    """
    Load a build manifest from a TOML, JSON, or INI file.

    The file format is auto-detected from the extension.
    """
    path = os.path.abspath(manifest_path)
    project_dir = os.path.dirname(path)
    ext = os.path.splitext(path)[1].lower()

    cfg = BuildConfig()

    if ext in (".toml",):
        cfg = _load_toml(path, project_dir)
    elif ext in (".json",):
        cfg = _load_json(path, project_dir)
    elif ext in (".ini", ".conf", ".cfg"):
        cfg = _load_ini(path, project_dir)
    else:
        # Try TOML first, fall back to JSON, then INI
        try:
            cfg = _load_toml(path, project_dir)
        except Exception:
            try:
                cfg = _load_json(path, project_dir)
            except Exception:
                cfg = _load_ini(path, project_dir)

    # Resolve relative paths against project_dir
    cfg.project_dir = project_dir
    cfg.rootfs_overlay_dirs = [
        os.path.join(project_dir, d) if not os.path.isabs(d) else d
        for d in cfg.rootfs_overlay_dirs
    ]
    for pkg in cfg.packages:
        if not os.path.isabs(pkg.path):
            pkg.path = os.path.join(project_dir, pkg.path)
    for attr in ("vmlinuz_path", "modules_dir"):
        val = getattr(cfg.kernel, attr)
        if val and not os.path.isabs(val):
            setattr(cfg.kernel, attr, os.path.join(project_dir, val))
    for attr in ("efi_binary_path", "bios_binary_path"):
        val = getattr(cfg.bootloader, attr)
        if val and not os.path.isabs(val):
            setattr(cfg.bootloader, attr, os.path.join(project_dir, val))
    if cfg.iso.output_path and not os.path.isabs(cfg.iso.output_path):
        cfg.iso.output_path = os.path.join(project_dir, cfg.iso.output_path)

    return cfg


def _load_toml(path: str, project_dir: str) -> BuildConfig:
    """Load from a TOML file, supporting Python 3.11+ tomllib or tomli."""
    try:
        import tomllib
    except ImportError:
        try:
            import tomli as tomllib  # type: ignore[no-redef]
        except ImportError:
            raise ImportError(
                "TOML support requires Python 3.11+ or the 'tomli' package"
            )
    with open(path, "rb") as fh:
        data = tomllib.load(fh)
    cfg = BuildConfig()
    _populate_from_dict(cfg, data, project_dir)
    return cfg


def _load_json(path: str, project_dir: str) -> BuildConfig:
    """Load from a JSON file."""
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    cfg = BuildConfig()
    _populate_from_dict(cfg, data, project_dir)
    return cfg


def _load_ini(path: str, project_dir: str) -> BuildConfig:
    """
    Load from an INI / .conf file.

    Uses a flat key-value mapping with section-based grouping.
    List values are comma-separated.
    """
    cp = configparser.ConfigParser(interpolation=None)
    cp.read(path, encoding="utf-8")

    d: Dict[str, Any] = {}

    if cp.has_section("general") or cp.has_section("distro"):
        sec = "general" if cp.has_section("general") else "distro"
        for key in ("name", "version", "arch", "hostname", "locale", "timezone", "keymap"):
            if cp.has_option(sec, key):
                d[key] = cp.get(sec, key)
        if cp.has_option(sec, "source_date_epoch"):
            d["source_date_epoch"] = cp.getint(sec, "source_date_epoch")
        if cp.has_option(sec, "overlays"):
            d["rootfs_overlay_dirs"] = [
                s.strip() for s in cp.get(sec, "overlays").split(",") if s.strip()
            ]

    if cp.has_section("kernel"):
        kern: Dict[str, Any] = {}
        for key in ("vmlinuz", "modules_dir", "cmdline"):
            if cp.has_option("kernel", key):
                kern[key] = cp.get("kernel", key)
        if cp.has_option("kernel", "initramfs_extra_dirs"):
            kern["initramfs_extra_dirs"] = [
                s.strip()
                for s in cp.get("kernel", "initramfs_extra_dirs").split(",")
                if s.strip()
            ]
        d["kernel"] = kern

    if cp.has_section("bootloader"):
        bl: Dict[str, Any] = {}
        for key in ("efi_binary", "bios_binary", "boot_catalog"):
            if cp.has_option("bootloader", key):
                bl[key] = cp.get("bootloader", key)
        d["bootloader"] = bl

    if cp.has_section("iso"):
        iso: Dict[str, Any] = {}
        for key in (
            "output",
            "volume_id",
            "volume_set_id",
            "publisher_id",
            "application_id",
            "system_id",
            "squashfs_compression",
        ):
            if cp.has_option("iso", key):
                iso[key] = cp.get("iso", key)
        if cp.has_option("iso", "squashfs_block_size"):
            iso["squashfs_block_size"] = cp.getint("iso", "squashfs_block_size")
        d["iso"] = iso

    if cp.has_section("packages"):
        pkgs: List[Dict[str, Any]] = []
        for key, val in cp.items("packages"):
            if key.startswith("pkg"):
                parts = val.split(",")
                p: Dict[str, str] = {"path": parts[0].strip()}
                if len(parts) > 1:
                    p["format"] = parts[1].strip()
                pkgs.append(p)
        d["packages"] = pkgs

    if cp.has_section("services"):
        svcs: List[Dict[str, Any]] = []
        for key, val in cp.items("services"):
            if key.startswith("svc") or key.startswith("service"):
                parts = val.split(",")
                s: Dict[str, str] = {"name": parts[0].strip()}
                if len(parts) > 1:
                    s["init_system"] = parts[1].strip()
                if len(parts) > 2:
                    s["target"] = parts[2].strip()
                svcs.append(s)
        d["services"] = svcs

    # Parse user sections: [user.username]
    users: List[Dict[str, Any]] = []
    for sec in cp.sections():
        if sec.startswith("user."):
            uname = sec[5:]
            u: Dict[str, Any] = {"name": uname}
            for key in ("uid", "gid"):
                if cp.has_option(sec, key):
                    u[key] = cp.getint(sec, key)
            for key in ("home", "shell", "password", "gecos"):
                if cp.has_option(sec, key):
                    u[key] = cp.get(sec, key)
            if cp.has_option(sec, "groups"):
                u["groups"] = [
                    g.strip() for g in cp.get(sec, "groups").split(",") if g.strip()
                ]
            users.append(u)
    if users:
        d["users"] = users

    # Parse group sections: [group.groupname]
    groups: List[Dict[str, Any]] = []
    for sec in cp.sections():
        if sec.startswith("group."):
            gname = sec[6:]
            g_dict: Dict[str, Any] = {"name": gname}
            if cp.has_option(sec, "gid"):
                g_dict["gid"] = cp.getint(sec, "gid")
            if cp.has_option(sec, "members"):
                g_dict["members"] = [
                    m.strip() for m in cp.get(sec, "members").split(",") if m.strip()
                ]
            groups.append(g_dict)
    if groups:
        d["groups"] = groups

    cfg = BuildConfig()
    _populate_from_dict(cfg, d, project_dir)
    return cfg

