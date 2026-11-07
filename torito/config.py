"""
torito.config — Declarative Build Manifest Parser
=================================================
Parses TOML, JSON, or INI build manifests into a strongly-typed
``BuildConfig`` that drives every stage of the ISO compiler.

Minimal manifest that produces a bootable Arch-based live ISO::

    name     = "MyDistro"
    packages = ["base", "linux"]
"""

from __future__ import annotations

import configparser
import json
import os
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .repo import DEFAULT_MIRRORS


@dataclass
class UserSpec:
    """A user account to create (or update, e.g. ``root``)."""

    name: str
    uid: Optional[int] = None
    gid: Optional[int] = None
    home: str = ""
    shell: str = "/bin/bash"
    password: Optional[str] = None  # plaintext → SHA-512 crypt; "" = no password; None = locked
    groups: List[str] = field(default_factory=list)
    gecos: str = ""
    create_home: bool = True

    def home_dir(self) -> str:
        if self.home:
            if self.home.rstrip("/") == "/home":
                return f"/home/{self.name}"
            return self.home
        return "/root" if self.name == "root" else f"/home/{self.name}"


@dataclass
class GroupSpec:
    name: str
    gid: Optional[int] = None
    members: List[str] = field(default_factory=list)


@dataclass
class ServiceSpec:
    """A unit to enable (``systemctl enable``) at build time."""

    name: str
    init_system: str = "systemd"  # systemd | openrc | runit
    target: str = ""  # systemd: override WantedBy target (default: unit's [Install])
    runlevel: str = "default"  # openrc
    user: bool = False  # systemd --global enable
    mask: bool = False


@dataclass
class PackageSpec:
    """A local package archive to ingest."""

    path: str
    format: str = "auto"


@dataclass
class RepositorySpec:
    name: str
    servers: List[str] = field(default_factory=list)


@dataclass
class KernelSpec:
    package: str = ""  # kernel package (auto-detected when empty)
    vmlinuz_path: str = ""  # explicit host kernel image (overrides package)
    modules_dir: str = ""
    cmdline: str = ""  # extra kernel arguments appended to the live arguments
    initramfs_modules: List[str] = field(default_factory=list)
    initramfs_extra_dirs: List[str] = field(default_factory=list)
    initramfs_extra_files: List[str] = field(default_factory=list)
    initramfs_compression: str = "zstd"
    microcode: bool = True  # prepend intel/amd microcode when those packages are installed


@dataclass
class BootloaderSpec:
    bios: str = "syslinux"  # syslinux | none
    uefi: str = "systemd-boot"  # systemd-boot | none
    efi_binary_path: str = ""  # override BOOTX64.EFI (host path)
    bios_binary_path: str = ""  # override El Torito BIOS image (host path)
    timeout: int = 5
    menu_title: str = ""
    extra_entries: List[Dict[str, str]] = field(default_factory=list)  # {title, cmdline}
    safe_graphics_cmdline: str = "nomodeset"  # arguments of the "safe graphics" entry
    boot_catalog_path: str = "boot/boot.cat"


@dataclass
class LiveSpec:
    copytoram: bool = False
    overlay_size: str = "75%"
    serial_console: bool = True  # add console=ttyS0 so boots can be logged headless


@dataclass
class IsoSpec:
    output_path: str = "torito-x86_64.iso"
    volume_id: str = "TORITO"
    volume_set_id: str = ""
    publisher_id: str = "Torito ISO Compiler"
    application_id: str = "TORITO"
    system_id: str = "LINUX"
    squashfs_compression: str = "zstd"
    squashfs_block_size: int = 131072
    squashfs_level: int = 15
    hybrid: bool = True  # isohybrid MBR so the image can be dd'd to USB


@dataclass
class BuildConfig:
    name: str = "torito-linux"
    version: str = "1.0.0"
    arch: str = "x86_64"
    source_date_epoch: Optional[int] = None

    project_dir: str = "."
    cache_dir: str = ".torito-cache"
    work_dir: str = ".torito-work"

    rootfs_overlay_dirs: List[str] = field(default_factory=list)
    packages: List[PackageSpec] = field(default_factory=list)  # local archives
    package_names: List[str] = field(default_factory=list)  # resolved from repositories
    repositories: List[RepositorySpec] = field(default_factory=list)
    package_preferences: Dict[str, str] = field(default_factory=dict)
    ignore_packages: List[str] = field(default_factory=list)
    remove_paths: List[str] = field(default_factory=list)
    file_permissions: Dict[str, str] = field(default_factory=dict)

    kernel: KernelSpec = field(default_factory=KernelSpec)
    bootloader: BootloaderSpec = field(default_factory=BootloaderSpec)
    live: LiveSpec = field(default_factory=LiveSpec)
    iso: IsoSpec = field(default_factory=IsoSpec)

    users: List[UserSpec] = field(default_factory=list)
    groups: List[GroupSpec] = field(default_factory=list)
    services: List[ServiceSpec] = field(default_factory=list)
    default_target: str = ""

    hostname: str = "torito"
    locale: str = "en_US.UTF-8"
    timezone: str = "UTC"
    keymap: str = "us"
    os_release: Dict[str, str] = field(default_factory=dict)
    # Configure DHCP on wired interfaces with systemd-networkd/resolved when
    # the manifest does not enable a network manager of its own.
    network_auto: bool = True
    # Things Torito decided on the user's behalf, or manifest problems worth
    # reporting (unknown keys …). The builder prints them.
    notes: List[str] = field(default_factory=list)


KERNEL_PACKAGES = ("linux", "linux-lts", "linux-zen", "linux-hardened", "linux-rt", "linux-rt-lts")

_KNOWN_KEYS: Dict[str, set] = {
    "": {
        "name", "version", "arch", "hostname", "locale", "timezone", "keymap", "default_target",
        "cache_dir", "work_dir", "source_date_epoch", "rootfs_overlay_dirs", "overlays", "remove_paths",
        "file_permissions", "package_preferences", "ignore_packages", "os_release", "packages",
        "package_files", "repositories", "repos", "mirrors", "kernel", "bootloader", "live", "iso",
        "users", "groups", "services", "network",
    },
    "kernel": {
        "package", "vmlinuz", "vmlinuz_path", "modules_dir", "cmdline", "initramfs_modules",
        "initramfs_extra_dirs", "initramfs_extra_files", "initramfs_compression", "microcode",
    },
    "bootloader": {
        "bios", "uefi", "efi_binary", "efi_binary_path", "bios_binary", "bios_binary_path", "timeout",
        "menu_title", "extra_entries", "safe_graphics_cmdline", "boot_catalog",
    },
    "live": {"copytoram", "overlay_size", "serial_console"},
    "iso": {
        "output", "output_path", "volume_id", "volume_set_id", "publisher_id", "application_id",
        "system_id", "squashfs_compression", "squashfs_block_size", "squashfs_level", "hybrid",
    },
    "network": {"auto"},
    "users": {"name", "uid", "gid", "home", "shell", "password", "groups", "gecos", "create_home"},
    "groups": {"name", "gid", "members"},
    "services": {"name", "init_system", "target", "runlevel", "user", "global", "mask"},
}


def _check_unknown_keys(d: Dict[str, Any], notes: List[str]) -> None:
    import difflib

    def check(table: Dict[str, Any], section: str, where: str) -> None:
        known = _KNOWN_KEYS[section]
        for key in table:
            if key in known:
                continue
            msg = f"unknown manifest key {where}'{key}' (ignored)"
            if key in _KNOWN_KEYS[""] and section:
                msg += f" — it is a top-level setting; move it above the first [table] header"
            else:
                hint = difflib.get_close_matches(key, known, n=1)
                if hint:
                    msg += f" — did you mean '{hint[0]}'?"
            notes.append(msg)

    check(d, "", "")
    for section in ("kernel", "bootloader", "live", "iso", "network"):
        if isinstance(d.get(section), dict):
            check(d[section], section, f"[{section}] ")
    for section in ("users", "groups", "services"):
        if isinstance(d.get(section), list):
            for i, entry in enumerate(d[section]):
                if isinstance(entry, dict):
                    check(entry, section, f"[[{section}]] #{i + 1} ")


def default_hostname(name: str) -> str:
    h = re.sub(r"[^a-z0-9-]+", "-", name.lower()).strip("-")[:63]
    return h or "torito"


def apply_smart_defaults(cfg: BuildConfig) -> None:
    """
    Make the obvious things work without the user having to know about them:
    a repository build with no kernel gets ``linux``, and one with no init
    system gets ``base`` (systemd, coreutils, …). Local package builds are
    left alone — the user is assembling the system by hand.
    """
    if not cfg.users:
        cfg.users.append(UserSpec(name="root", password=""))
        cfg.notes.append("no [[users]] given: root can log in on the console without a password")
    if cfg.packages:
        return
    want_kernel = cfg.bootloader.bios != "none" or cfg.bootloader.uefi != "none"
    names = cfg.package_names
    if not any(n in ("base", "systemd") for n in names):
        names.insert(0, "base")
        cfg.notes.append("added package 'base' (init system and core tools) — every bootable system needs it")
    if want_kernel and not cfg.kernel.vmlinuz_path:
        if cfg.kernel.package and cfg.kernel.package not in names:
            names.append(cfg.kernel.package)
            cfg.notes.append(f"added kernel package '{cfg.kernel.package}' from [kernel] package")
        elif not any(n in KERNEL_PACKAGES for n in names) and not cfg.kernel.package:
            names.append("linux")
            cfg.notes.append("added kernel package 'linux' (no kernel listed in packages)")


# ---------------------------------------------------------------------------


def _opt_int(v: Any) -> Optional[int]:
    if v is None or v == "":
        return None
    return int(v)


def _parse_user(raw: Dict[str, Any]) -> UserSpec:
    pw = raw.get("password", None)
    return UserSpec(
        name=str(raw.get("name", "user")),
        uid=_opt_int(raw.get("uid")),
        gid=_opt_int(raw.get("gid")),
        home=str(raw.get("home", "")),
        shell=str(raw.get("shell", "/bin/bash")),
        password=None if pw is None else str(pw),
        groups=[str(g) for g in raw.get("groups", [])],
        gecos=str(raw.get("gecos", "")),
        create_home=bool(raw.get("create_home", True)),
    )


def _parse_group(raw: Dict[str, Any]) -> GroupSpec:
    return GroupSpec(
        name=str(raw.get("name", "users")),
        gid=_opt_int(raw.get("gid")),
        members=[str(m) for m in raw.get("members", [])],
    )


def _parse_service(raw: Dict[str, Any]) -> ServiceSpec:
    return ServiceSpec(
        name=str(raw.get("name", "")),
        init_system=str(raw.get("init_system", "systemd")),
        target=str(raw.get("target", "")),
        runlevel=str(raw.get("runlevel", "default")),
        user=bool(raw.get("user", raw.get("global", False))),
        mask=bool(raw.get("mask", False)),
    )


def _looks_like_path(s: str) -> bool:
    return ("/" in s or "\\" in s or ".pkg.tar" in s or s.endswith((".deb", ".apk", ".tar", ".tar.gz", ".tar.zst", ".tar.xz")))


def sanitise_volume_id(vol: str) -> str:
    v = re.sub(r"[^A-Z0-9_]", "_", vol.upper())[:32]
    return v or "TORITO"


def _populate_from_dict(cfg: BuildConfig, d: Dict[str, Any], project_dir: str) -> None:
    _check_unknown_keys(d, cfg.notes)
    cfg.name = str(d.get("name", cfg.name))
    cfg.version = str(d.get("version", cfg.version))
    cfg.arch = str(d.get("arch", cfg.arch))
    cfg.hostname = str(d.get("hostname") or default_hostname(cfg.name))
    cfg.locale = str(d.get("locale", cfg.locale))
    cfg.timezone = str(d.get("timezone", cfg.timezone))
    cfg.keymap = str(d.get("keymap", cfg.keymap))
    cfg.default_target = str(d.get("default_target", cfg.default_target))
    cfg.cache_dir = str(d.get("cache_dir", cfg.cache_dir))
    cfg.work_dir = str(d.get("work_dir", cfg.work_dir))
    cfg.project_dir = project_dir
    if d.get("source_date_epoch") is not None:
        cfg.source_date_epoch = int(d["source_date_epoch"])

    cfg.rootfs_overlay_dirs = [str(x) for x in d.get("rootfs_overlay_dirs", d.get("overlays", []))]
    cfg.remove_paths = [str(x) for x in d.get("remove_paths", [])]
    cfg.file_permissions = {str(k): str(v) for k, v in dict(d.get("file_permissions", {})).items()}
    cfg.package_preferences = {str(k): str(v) for k, v in dict(d.get("package_preferences", {})).items()}
    cfg.ignore_packages = [str(x) for x in d.get("ignore_packages", [])]
    cfg.os_release = {str(k): str(v) for k, v in dict(d.get("os_release", {})).items()}

    # Packages: strings are repo package names unless they look like files.
    for pr in d.get("packages", []):
        if isinstance(pr, str):
            if _looks_like_path(pr):
                cfg.packages.append(PackageSpec(path=pr))
            else:
                cfg.package_names.append(pr)
        elif isinstance(pr, dict):
            if "path" in pr:
                cfg.packages.append(PackageSpec(path=str(pr["path"]), format=str(pr.get("format", "auto"))))
            elif "name" in pr:
                cfg.package_names.append(str(pr["name"]))
    for pf in d.get("package_files", []):
        cfg.packages.append(PackageSpec(path=str(pf)))

    repos = d.get("repositories", d.get("repos"))
    if isinstance(repos, list):
        for r in repos:
            if isinstance(r, str):
                cfg.repositories.append(RepositorySpec(name=r))
            elif isinstance(r, dict):
                servers = r.get("servers", r.get("server", []))
                if isinstance(servers, str):
                    servers = [servers]
                cfg.repositories.append(RepositorySpec(name=str(r["name"]), servers=[str(s) for s in servers]))
    mirrors = d.get("mirrors")
    for r in cfg.repositories:
        if not r.servers:
            r.servers = [str(m) for m in mirrors] if isinstance(mirrors, list) and mirrors else list(DEFAULT_MIRRORS)

    kern = d.get("kernel", {})
    if isinstance(kern, dict):
        k = cfg.kernel
        k.package = str(kern.get("package", k.package))
        k.vmlinuz_path = str(kern.get("vmlinuz", kern.get("vmlinuz_path", k.vmlinuz_path)))
        k.modules_dir = str(kern.get("modules_dir", k.modules_dir))
        k.cmdline = str(kern.get("cmdline", k.cmdline))
        k.initramfs_modules = [str(x) for x in kern.get("initramfs_modules", k.initramfs_modules)]
        k.initramfs_extra_dirs = [str(x) for x in kern.get("initramfs_extra_dirs", k.initramfs_extra_dirs)]
        k.initramfs_extra_files = [str(x) for x in kern.get("initramfs_extra_files", k.initramfs_extra_files)]
        k.initramfs_compression = str(kern.get("initramfs_compression", k.initramfs_compression))
        k.microcode = bool(kern.get("microcode", k.microcode))

    bl = d.get("bootloader", {})
    if isinstance(bl, dict):
        b = cfg.bootloader
        b.bios = str(bl.get("bios", b.bios))
        b.uefi = str(bl.get("uefi", b.uefi))
        b.efi_binary_path = str(bl.get("efi_binary", bl.get("efi_binary_path", b.efi_binary_path)))
        b.bios_binary_path = str(bl.get("bios_binary", bl.get("bios_binary_path", b.bios_binary_path)))
        b.timeout = int(bl.get("timeout", b.timeout))
        b.menu_title = str(bl.get("menu_title", b.menu_title))
        b.extra_entries = [dict(e) for e in bl.get("extra_entries", b.extra_entries)]
        b.safe_graphics_cmdline = str(bl.get("safe_graphics_cmdline", b.safe_graphics_cmdline))
        b.boot_catalog_path = str(bl.get("boot_catalog", b.boot_catalog_path))

    lv = d.get("live", {})
    if isinstance(lv, dict):
        cfg.live.copytoram = bool(lv.get("copytoram", cfg.live.copytoram))
        cfg.live.overlay_size = str(lv.get("overlay_size", cfg.live.overlay_size))
        cfg.live.serial_console = bool(lv.get("serial_console", cfg.live.serial_console))

    iso = d.get("iso", {})
    if isinstance(iso, dict):
        i = cfg.iso
        i.output_path = str(iso.get("output", iso.get("output_path", i.output_path)))
        i.volume_id = str(iso.get("volume_id", i.volume_id))
        i.volume_set_id = str(iso.get("volume_set_id", i.volume_set_id))
        i.publisher_id = str(iso.get("publisher_id", i.publisher_id))
        i.application_id = str(iso.get("application_id", i.application_id))
        i.system_id = str(iso.get("system_id", i.system_id))
        i.squashfs_compression = str(iso.get("squashfs_compression", i.squashfs_compression))
        i.squashfs_block_size = int(iso.get("squashfs_block_size", i.squashfs_block_size))
        i.squashfs_level = int(iso.get("squashfs_level", i.squashfs_level))
        i.hybrid = bool(iso.get("hybrid", i.hybrid))
    iso_d = iso if isinstance(iso, dict) else {}
    slug = re.sub(r"[^a-z0-9_-]+", "-", cfg.name.lower()).strip("-_") or "torito"
    if "output" not in iso_d and "output_path" not in iso_d:
        cfg.iso.output_path = f"output/{slug}-x86_64.iso"
    if "volume_id" not in iso_d:
        cfg.iso.volume_id = slug.upper()[:26] + "_LIVE"
    cfg.iso.volume_id = sanitise_volume_id(cfg.iso.volume_id)

    net = d.get("network", {})
    if isinstance(net, dict):
        cfg.network_auto = bool(net.get("auto", cfg.network_auto))

    for u in d.get("users", []):
        if isinstance(u, dict):
            cfg.users.append(_parse_user(u))
    for g in d.get("groups", []):
        if isinstance(g, dict):
            cfg.groups.append(_parse_group(g))
    for s in d.get("services", []):
        if isinstance(s, dict):
            cfg.services.append(_parse_service(s))
        elif isinstance(s, str):
            cfg.services.append(ServiceSpec(name=s))


def load_config(manifest_path: str) -> BuildConfig:
    """Load a build manifest from a TOML, JSON, or INI file."""
    path = os.path.abspath(manifest_path)
    project_dir = os.path.dirname(path)
    ext = os.path.splitext(path)[1].lower()

    if ext == ".toml":
        cfg = _load_toml(path, project_dir)
    elif ext == ".json":
        cfg = _load_json(path, project_dir)
    elif ext in (".ini", ".conf", ".cfg"):
        cfg = _load_ini(path, project_dir)
    else:
        try:
            cfg = _load_toml(path, project_dir)
        except Exception:
            try:
                cfg = _load_json(path, project_dir)
            except Exception:
                cfg = _load_ini(path, project_dir)

    def absp(p: str) -> str:
        return p if (not p or os.path.isabs(p)) else os.path.join(project_dir, p)

    cfg.project_dir = project_dir
    cfg.rootfs_overlay_dirs = [absp(x) for x in cfg.rootfs_overlay_dirs]
    for pkg in cfg.packages:
        pkg.path = absp(pkg.path)
    cfg.kernel.vmlinuz_path = absp(cfg.kernel.vmlinuz_path)
    cfg.kernel.modules_dir = absp(cfg.kernel.modules_dir)
    cfg.kernel.initramfs_extra_dirs = [absp(x) for x in cfg.kernel.initramfs_extra_dirs]
    cfg.kernel.initramfs_extra_files = [absp(x) for x in cfg.kernel.initramfs_extra_files]
    cfg.bootloader.efi_binary_path = absp(cfg.bootloader.efi_binary_path)
    cfg.bootloader.bios_binary_path = absp(cfg.bootloader.bios_binary_path)
    cfg.iso.output_path = absp(cfg.iso.output_path)
    cfg.cache_dir = absp(cfg.cache_dir)
    cfg.work_dir = absp(cfg.work_dir)
    apply_smart_defaults(cfg)
    # Repository package names given without any repository → Arch core+extra.
    if cfg.package_names and not cfg.repositories:
        cfg.repositories = [
            RepositorySpec("core", list(DEFAULT_MIRRORS)),
            RepositorySpec("extra", list(DEFAULT_MIRRORS)),
        ]
    return cfg


def _load_toml(path: str, project_dir: str) -> BuildConfig:
    try:
        import tomllib
    except ImportError:  # pragma: no cover
        import tomli as tomllib  # type: ignore[no-redef]
    with open(path, "rb") as fh:
        raw = fh.read()
    # Windows editors (Notepad, PowerShell 5) like to prepend a UTF-8 BOM.
    data = tomllib.loads(raw.decode("utf-8-sig"))
    cfg = BuildConfig()
    _populate_from_dict(cfg, data, project_dir)
    return cfg


def _load_json(path: str, project_dir: str) -> BuildConfig:
    with open(path, "r", encoding="utf-8-sig") as fh:
        data = json.load(fh)
    cfg = BuildConfig()
    _populate_from_dict(cfg, data, project_dir)
    return cfg


def _load_ini(path: str, project_dir: str) -> BuildConfig:
    """INI / .conf manifests: sections map onto the TOML structure; lists are comma-separated."""
    cp = configparser.ConfigParser(interpolation=None)
    cp.read(path, encoding="utf-8")

    def lst(sec: str, key: str) -> List[str]:
        return [s.strip() for s in cp.get(sec, key).split(",") if s.strip()]

    d: Dict[str, Any] = {}
    sec = "general" if cp.has_section("general") else ("distro" if cp.has_section("distro") else None)
    if sec:
        for key in ("name", "version", "arch", "hostname", "locale", "timezone", "keymap", "default_target"):
            if cp.has_option(sec, key):
                d[key] = cp.get(sec, key)
        if cp.has_option(sec, "source_date_epoch"):
            d["source_date_epoch"] = cp.getint(sec, "source_date_epoch")
        if cp.has_option(sec, "overlays"):
            d["rootfs_overlay_dirs"] = lst(sec, "overlays")
        if cp.has_option(sec, "packages"):
            d["packages"] = lst(sec, "packages")

    if cp.has_section("kernel"):
        kern: Dict[str, Any] = {}
        for key in ("vmlinuz", "modules_dir", "cmdline", "package"):
            if cp.has_option("kernel", key):
                kern[key] = cp.get("kernel", key)
        for key in ("initramfs_extra_dirs", "initramfs_modules"):
            if cp.has_option("kernel", key):
                kern[key] = lst("kernel", key)
        d["kernel"] = kern

    if cp.has_section("bootloader"):
        d["bootloader"] = {k: cp.get("bootloader", k) for k in ("efi_binary", "bios_binary", "boot_catalog", "bios", "uefi") if cp.has_option("bootloader", k)}

    if cp.has_section("iso"):
        iso: Dict[str, Any] = {}
        for key in ("output", "volume_id", "volume_set_id", "publisher_id", "application_id", "system_id", "squashfs_compression"):
            if cp.has_option("iso", key):
                iso[key] = cp.get("iso", key)
        if cp.has_option("iso", "squashfs_block_size"):
            iso["squashfs_block_size"] = cp.getint("iso", "squashfs_block_size")
        d["iso"] = iso

    if cp.has_section("packages"):
        pkgs: List[Any] = d.setdefault("packages", [])
        for key, val in cp.items("packages"):
            if key.startswith("pkg"):
                parts = [p.strip() for p in val.split(",")]
                entry: Dict[str, str] = {"path": parts[0]}
                if len(parts) > 1:
                    entry["format"] = parts[1]
                pkgs.append(entry)

    if cp.has_section("services"):
        svcs: List[Dict[str, Any]] = []
        for key, val in cp.items("services"):
            if key.startswith("svc") or key.startswith("service"):
                parts = [p.strip() for p in val.split(",")]
                s: Dict[str, Any] = {"name": parts[0]}
                if len(parts) > 1:
                    s["init_system"] = parts[1]
                if len(parts) > 2:
                    s["target"] = parts[2]
                svcs.append(s)
        d["services"] = svcs

    users: List[Dict[str, Any]] = []
    groups: List[Dict[str, Any]] = []
    for sec_name in cp.sections():
        if sec_name.startswith("user."):
            u: Dict[str, Any] = {"name": sec_name[5:]}
            for key in ("uid", "gid"):
                if cp.has_option(sec_name, key):
                    u[key] = cp.getint(sec_name, key)
            for key in ("home", "shell", "password", "gecos"):
                if cp.has_option(sec_name, key):
                    u[key] = cp.get(sec_name, key)
            if cp.has_option(sec_name, "groups"):
                u["groups"] = lst(sec_name, "groups")
            users.append(u)
        elif sec_name.startswith("group."):
            g: Dict[str, Any] = {"name": sec_name[6:]}
            if cp.has_option(sec_name, "gid"):
                g["gid"] = cp.getint(sec_name, "gid")
            if cp.has_option(sec_name, "members"):
                g["members"] = lst(sec_name, "members")
            groups.append(g)
    if users:
        d["users"] = users
    if groups:
        d["groups"] = groups

    cfg = BuildConfig()
    _populate_from_dict(cfg, d, project_dir)
    return cfg
