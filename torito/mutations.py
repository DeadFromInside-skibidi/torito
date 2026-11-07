"""
torito.mutations — Rootless State Synthesis
=============================================
Deterministically generates ``/etc/passwd``, ``/etc/group``,
``/etc/shadow`` (SHA-512), and wires init-system service symlinks
directly inside the VFS — replacing ``chroot``, ``useradd``,
``systemctl enable``, and ``rc-update add`` entirely.
"""

from __future__ import annotations

import hashlib
import os
import struct
import time
from typing import List, Optional

from .config import BuildConfig, GroupSpec, ServiceSpec, UserSpec
from .vfs import PosixVfs


# ---------------------------------------------------------------------------
# SHA-512 crypt ($6$) — pure-Python implementation for Windows
# ---------------------------------------------------------------------------
# Implements the SHA-512 password hashing scheme as specified by
# Ulrich Drepper's specification (used by glibc crypt(3) with $6$ prefix).

_SHA512_CRYPT_ROUNDS_DEFAULT = 5000
_SHA512_CRYPT_ROUNDS_MIN = 1000
_SHA512_CRYPT_ROUNDS_MAX = 999999999

_B64_CHARS = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"


def _b64_from_24bit(b2: int, b1: int, b0: int, n: int) -> str:
    """Encode 3 bytes into *n* base-64 characters (crypt-style ordering)."""
    w = (b2 << 16) | (b1 << 8) | b0
    result = []
    for _ in range(n):
        result.append(_B64_CHARS[w & 0x3F])
        w >>= 6
    return "".join(result)


def sha512_crypt(password: str, salt: str, rounds: int = _SHA512_CRYPT_ROUNDS_DEFAULT) -> str:
    """
    Compute a ``$6$`` SHA-512 password hash identical to glibc's ``crypt(3)``.

    Parameters
    ----------
    password : str
        The plaintext password.
    salt : str
        A salt string (up to 16 characters from ``[./0-9A-Za-z]``).
    rounds : int
        Number of hashing rounds (default 5000).

    Returns
    -------
    str
        The full ``$6$...`` hash string suitable for ``/etc/shadow``.
    """
    rounds = max(_SHA512_CRYPT_ROUNDS_MIN, min(rounds, _SHA512_CRYPT_ROUNDS_MAX))
    salt = salt[:16]

    pwd = password.encode("utf-8")
    slt = salt.encode("utf-8")

    # Step 1-3: initial digest B
    b_ctx = hashlib.sha512()
    b_ctx.update(pwd)
    b_ctx.update(slt)
    b_ctx.update(pwd)
    digest_b = b_ctx.digest()

    # Step 4-8: initial digest A
    a_ctx = hashlib.sha512()
    a_ctx.update(pwd)
    a_ctx.update(slt)

    plen = len(pwd)
    count = plen
    while count > 64:
        a_ctx.update(digest_b)
        count -= 64
    a_ctx.update(digest_b[:count])

    # Step 9-10: alternating bits of password length
    i = plen
    while i > 0:
        if i & 1:
            a_ctx.update(digest_b)
        else:
            a_ctx.update(pwd)
        i >>= 1

    digest_a = a_ctx.digest()

    # Step 11-12: DP = repeated hash of password
    dp_ctx = hashlib.sha512()
    for _ in range(plen):
        dp_ctx.update(pwd)
    digest_dp = dp_ctx.digest()

    # Step 13: produce P string
    p_bytes = b""
    count = plen
    while count > 64:
        p_bytes += digest_dp
        count -= 64
    p_bytes += digest_dp[:count]

    # Step 14-15: DS = repeated hash of salt
    ds_ctx = hashlib.sha512()
    for _ in range(16 + digest_a[0]):
        ds_ctx.update(slt)
    digest_ds = ds_ctx.digest()

    # Step 16: produce S string
    s_bytes = b""
    count = len(slt)
    while count > 64:
        s_bytes += digest_ds
        count -= 64
    s_bytes += digest_ds[:count]

    # Step 17-20: rounds
    digest_c = digest_a
    for r in range(rounds):
        c_ctx = hashlib.sha512()
        if r & 1:
            c_ctx.update(p_bytes)
        else:
            c_ctx.update(digest_c)
        if r % 3:
            c_ctx.update(s_bytes)
        if r % 7:
            c_ctx.update(p_bytes)
        if r & 1:
            c_ctx.update(digest_c)
        else:
            c_ctx.update(p_bytes)
        digest_c = c_ctx.digest()

    # Step 21: encode final digest
    final = digest_c
    hash_str = (
        _b64_from_24bit(final[0], final[21], final[42], 4)
        + _b64_from_24bit(final[22], final[43], final[1], 4)
        + _b64_from_24bit(final[44], final[2], final[23], 4)
        + _b64_from_24bit(final[3], final[24], final[45], 4)
        + _b64_from_24bit(final[25], final[46], final[4], 4)
        + _b64_from_24bit(final[47], final[5], final[26], 4)
        + _b64_from_24bit(final[6], final[27], final[48], 4)
        + _b64_from_24bit(final[28], final[49], final[7], 4)
        + _b64_from_24bit(final[50], final[8], final[29], 4)
        + _b64_from_24bit(final[9], final[30], final[51], 4)
        + _b64_from_24bit(final[31], final[52], final[10], 4)
        + _b64_from_24bit(final[53], final[11], final[32], 4)
        + _b64_from_24bit(final[12], final[33], final[54], 4)
        + _b64_from_24bit(final[34], final[55], final[13], 4)
        + _b64_from_24bit(final[56], final[14], final[35], 4)
        + _b64_from_24bit(final[15], final[36], final[57], 4)
        + _b64_from_24bit(final[37], final[58], final[16], 4)
        + _b64_from_24bit(final[59], final[17], final[38], 4)
        + _b64_from_24bit(final[18], final[39], final[60], 4)
        + _b64_from_24bit(final[40], final[61], final[19], 4)
        + _b64_from_24bit(final[62], final[20], final[41], 4)
        + _b64_from_24bit(0, 0, final[63], 2)
    )

    if rounds == _SHA512_CRYPT_ROUNDS_DEFAULT:
        return f"$6${salt}${hash_str}"
    return f"$6$rounds={rounds}${salt}${hash_str}"


def _generate_salt(length: int = 16) -> str:
    """Generate a random salt string for crypt hashing."""
    raw = os.urandom(length)
    return "".join(_B64_CHARS[b % 64] for b in raw)[:length]


# ---------------------------------------------------------------------------
# /etc/passwd, /etc/group, /etc/shadow synthesis
# ---------------------------------------------------------------------------

# Standard system accounts that every Linux rootfs needs
_SYSTEM_PASSWD_ENTRIES = [
    "root:x:0:0:root:/root:/bin/bash",
    "bin:x:1:1:bin:/bin:/usr/bin/nologin",
    "daemon:x:2:2:daemon:/:/usr/bin/nologin",
    "mail:x:8:12:mail:/var/spool/mail:/usr/bin/nologin",
    "ftp:x:14:11:ftp:/srv/ftp:/usr/bin/nologin",
    "http:x:33:33:http:/srv/http:/usr/bin/nologin",
    "nobody:x:65534:65534:Kernel Overflow User:/:/usr/bin/nologin",
    "dbus:x:81:81:System Message Bus:/:/usr/bin/nologin",
    "systemd-journal-remote:x:982:982::/:/usr/bin/nologin",
    "systemd-network:x:981:981::/:/usr/bin/nologin",
    "systemd-oom:x:980:980::/:/usr/bin/nologin",
    "systemd-resolve:x:979:979::/:/usr/bin/nologin",
    "systemd-timesync:x:978:978::/:/usr/bin/nologin",
    "systemd-coredump:x:977:977::/:/usr/bin/nologin",
    "polkitd:x:102:102:PolicyKit daemon:/:/usr/bin/nologin",
]

_SYSTEM_GROUP_ENTRIES = [
    "root:x:0:root",
    "bin:x:1:root,bin,daemon",
    "daemon:x:2:root,bin,daemon",
    "sys:x:3:root,bin",
    "adm:x:4:root,daemon",
    "tty:x:5:",
    "disk:x:6:root",
    "lp:x:7:daemon",
    "mem:x:8:",
    "kmem:x:9:",
    "wheel:x:10:root",
    "ftp:x:11:",
    "mail:x:12:",
    "uucp:x:14:",
    "log:x:19:root",
    "utmp:x:20:",
    "locate:x:21:",
    "rfkill:x:24:",
    "smmsp:x:25:",
    "proc:x:26:",
    "http:x:33:",
    "games:x:50:",
    "lock:x:54:",
    "uuidd:x:68:",
    "dbus:x:81:",
    "network:x:90:",
    "power:x:98:",
    "nobody:x:65534:",
    "users:x:100:",
    "video:x:985:",
    "audio:x:986:",
    "optical:x:987:",
    "storage:x:988:",
    "input:x:989:",
    "scanner:x:990:",
    "render:x:991:",
    "sgx:x:992:",
    "kvm:x:993:",
    "polkitd:x:102:",
    "systemd-journal:x:976:",
    "systemd-journal-remote:x:982:",
    "systemd-network:x:981:",
    "systemd-oom:x:980:",
    "systemd-resolve:x:979:",
    "systemd-timesync:x:978:",
    "systemd-coredump:x:977:",
]

_SYSTEM_SHADOW_ENTRIES = [
    "root:!:19000:0:99999:7:::",
    "bin:!*:19000::::::",
    "daemon:!*:19000::::::",
    "mail:!*:19000::::::",
    "ftp:!*:19000::::::",
    "http:!*:19000::::::",
    "nobody:!*:19000::::::",
    "dbus:!*:19000::::::",
    "systemd-journal-remote:!*:19000::::::",
    "systemd-network:!*:19000::::::",
    "systemd-oom:!*:19000::::::",
    "systemd-resolve:!*:19000::::::",
    "systemd-timesync:!*:19000::::::",
    "systemd-coredump:!*:19000::::::",
    "polkitd:!*:19000::::::",
]


def synthesise_users_and_groups(vfs: PosixVfs, config: BuildConfig) -> None:
    """
    Generate ``/etc/passwd``, ``/etc/group``, and ``/etc/shadow`` in the VFS.

    Replaces ``chroot useradd``, ``groupadd``, and ``passwd`` entirely.
    """
    days_since_epoch = int(time.time()) // 86400

    passwd_lines = list(_SYSTEM_PASSWD_ENTRIES)
    group_lines = list(_SYSTEM_GROUP_ENTRIES)
    shadow_lines = list(_SYSTEM_SHADOW_ENTRIES)

    # Existing group names for membership injection
    group_members: dict[str, List[str]] = {}
    for gl in group_lines:
        parts = gl.split(":")
        name = parts[0]
        members = parts[3].split(",") if parts[3] else []
        group_members[name] = members

    # Add custom groups from config
    for grp in config.groups:
        entry = f"{grp.name}:x:{grp.gid}:{','.join(grp.members)}"
        group_lines.append(entry)
        group_members[grp.name] = list(grp.members)

    # Add custom users from config
    for user in config.users:
        gecos = user.gecos if user.gecos else user.name
        home = user.home_dir()
        passwd_lines.append(
            f"{user.name}:x:{user.uid}:{user.gid}:{gecos}:{home}:{user.shell}"
        )

        # Hash the password
        if user.password:
            salt = _generate_salt(16)
            hashed = sha512_crypt(user.password, salt)
        else:
            hashed = "!"

        shadow_lines.append(
            f"{user.name}:{hashed}:{days_since_epoch}:0:99999:7:::"
        )

        # Ensure the user's primary group exists
        primary_gid_exists = any(
            int(gl.split(":")[2]) == user.gid for gl in group_lines
        )
        if not primary_gid_exists:
            group_lines.append(f"{user.name}:x:{user.gid}:")
            group_members[user.name] = []

        # Add user to supplementary groups
        for grp_name in user.groups:
            if grp_name in group_members:
                if user.name not in group_members[grp_name]:
                    group_members[grp_name].append(user.name)

        # Create home directory
        vfs.mkdir(home, mode=0o700, uid=user.uid, gid=user.gid)

        # Create .bashrc and .bash_profile
        bashrc_content = (
            b"# ~/.bashrc\n"
            b"[[ $- != *i* ]] && return\n"
            b"alias ls='ls --color=auto'\n"
            b"PS1='[\\u@\\h \\W]\\$ '\n"
        )
        vfs.add_file(f"{home}/.bashrc", bashrc_content, mode=0o644, uid=user.uid, gid=user.gid)
        vfs.add_file(
            f"{home}/.bash_profile",
            b"# ~/.bash_profile\n[[ -f ~/.bashrc ]] && . ~/.bashrc\n",
            mode=0o644,
            uid=user.uid,
            gid=user.gid,
        )

    # Rebuild group lines with updated membership
    rebuilt_groups = []
    for gl in group_lines:
        parts = gl.split(":")
        name = parts[0]
        if name in group_members:
            parts[3] = ",".join(group_members[name])
        rebuilt_groups.append(":".join(parts))

    # Write files to VFS
    vfs.mkdir("/etc", mode=0o755)
    vfs.add_file(
        "/etc/passwd",
        ("\n".join(passwd_lines) + "\n").encode("utf-8"),
        mode=0o644,
    )
    vfs.add_file(
        "/etc/group",
        ("\n".join(rebuilt_groups) + "\n").encode("utf-8"),
        mode=0o644,
    )
    vfs.add_file(
        "/etc/shadow",
        ("\n".join(shadow_lines) + "\n").encode("utf-8"),
        mode=0o000,
    )
    # gshadow
    gshadow_lines = []
    for gl in rebuilt_groups:
        parts = gl.split(":")
        gshadow_lines.append(f"{parts[0]}:!::{parts[3]}")
    vfs.add_file(
        "/etc/gshadow",
        ("\n".join(gshadow_lines) + "\n").encode("utf-8"),
        mode=0o000,
    )


# ---------------------------------------------------------------------------
# Init system service wiring
# ---------------------------------------------------------------------------


def _enable_systemd_service(vfs: PosixVfs, svc: ServiceSpec) -> None:
    """
    Wire a systemd service by creating the appropriate ``*.wants/`` symlink.

    Equivalent to ``systemctl enable <service>`` inside a chroot.
    """
    service_filename = svc.name if svc.name.endswith(".service") else f"{svc.name}.service"
    target = svc.target if svc.target else "multi-user.target"

    wants_dir = f"/etc/systemd/system/{target}.wants"
    vfs.mkdir(wants_dir, mode=0o755)

    link_path = f"{wants_dir}/{service_filename}"
    unit_target = f"/usr/lib/systemd/system/{service_filename}"

    # If the unit file exists in the VFS, parse its [Install] section
    unit_node = vfs.get(unit_target)
    if unit_node is not None and unit_node.data:
        wanted_by = _parse_systemd_wanted_by(unit_node.data.decode("utf-8", errors="replace"))
        if wanted_by:
            # The unit file may specify different targets
            for wb_target in wanted_by:
                wb_dir = f"/etc/systemd/system/{wb_target}.wants"
                vfs.mkdir(wb_dir, mode=0o755)
                vfs.add_symlink(f"{wb_dir}/{service_filename}", unit_target)
            return

    vfs.add_symlink(link_path, unit_target)


def _parse_systemd_wanted_by(unit_content: str) -> List[str]:
    """Extract ``WantedBy=`` values from a systemd unit file."""
    results = []
    in_install = False
    for line in unit_content.splitlines():
        stripped = line.strip()
        if stripped == "[Install]":
            in_install = True
            continue
        if stripped.startswith("[") and in_install:
            break
        if in_install and stripped.startswith("WantedBy="):
            values = stripped[len("WantedBy="):].strip()
            results.extend(v.strip() for v in values.split() if v.strip())
    return results


def _enable_openrc_service(vfs: PosixVfs, svc: ServiceSpec) -> None:
    """
    Wire an OpenRC service by creating the appropriate symlink in
    ``/etc/runlevels/<runlevel>/``.

    Equivalent to ``rc-update add <service> <runlevel>``.
    """
    runlevel = svc.runlevel if svc.runlevel else "default"
    svc_name = svc.name.replace(".service", "")

    runlevel_dir = f"/etc/runlevels/{runlevel}"
    vfs.mkdir(runlevel_dir, mode=0o755)

    init_script = f"/etc/init.d/{svc_name}"
    link_path = f"{runlevel_dir}/{svc_name}"
    vfs.add_symlink(link_path, init_script)


def _enable_runit_service(vfs: PosixVfs, svc: ServiceSpec) -> None:
    """
    Wire a runit service by creating the appropriate symlink in
    ``/var/service/`` pointing to ``/etc/sv/<service>/``.

    Equivalent to ``ln -s /etc/sv/<service> /var/service/``.
    """
    svc_name = svc.name.replace(".service", "")
    sv_dir = f"/etc/sv/{svc_name}"
    service_link = f"/var/service/{svc_name}"

    vfs.mkdir("/var/service", mode=0o755)
    vfs.add_symlink(service_link, sv_dir)


def wire_services(vfs: PosixVfs, config: BuildConfig) -> None:
    """Enable all services specified in the build configuration."""
    for svc in config.services:
        if svc.init_system == "systemd":
            _enable_systemd_service(vfs, svc)
        elif svc.init_system == "openrc":
            _enable_openrc_service(vfs, svc)
        elif svc.init_system == "runit":
            _enable_runit_service(vfs, svc)
        else:
            raise ValueError(f"Unknown init system: {svc.init_system!r}")


# ---------------------------------------------------------------------------
# System configuration synthesis
# ---------------------------------------------------------------------------


def synthesise_system_config(vfs: PosixVfs, config: BuildConfig) -> None:
    """
    Generate standard system configuration files:
    ``/etc/hostname``, ``/etc/hosts``, ``/etc/locale.conf``,
    ``/etc/vconsole.conf``, ``/etc/localtime``, ``/etc/os-release``,
    ``/etc/machine-id``, and ``/etc/fstab``.
    """
    vfs.mkdir("/etc", mode=0o755)

    # /etc/hostname
    vfs.add_file(
        "/etc/hostname",
        (config.hostname + "\n").encode("utf-8"),
        mode=0o644,
    )

    # /etc/hosts
    hosts = (
        f"127.0.0.1   localhost\n"
        f"::1         localhost\n"
        f"127.0.1.1   {config.hostname}.localdomain {config.hostname}\n"
    )
    vfs.add_file("/etc/hosts", hosts.encode("utf-8"), mode=0o644)

    # /etc/locale.conf
    vfs.add_file(
        "/etc/locale.conf",
        f"LANG={config.locale}\n".encode("utf-8"),
        mode=0o644,
    )

    # /etc/vconsole.conf
    vfs.add_file(
        "/etc/vconsole.conf",
        f"KEYMAP={config.keymap}\n".encode("utf-8"),
        mode=0o644,
    )

    # /etc/localtime -> timezone symlink
    vfs.add_symlink(
        "/etc/localtime",
        f"/usr/share/zoneinfo/{config.timezone}",
    )

    # /etc/os-release
    os_release = (
        f'NAME="{config.name}"\n'
        f'VERSION="{config.version}"\n'
        f'ID={config.name.lower().replace(" ", "-")}\n'
        f'VERSION_ID="{config.version}"\n'
        f'PRETTY_NAME="{config.name} {config.version}"\n'
        f'HOME_URL="https://github.com/DeadFromInside-skibidi/torito"\n'
        f'BUILD_ID="{config.version}"\n'
    )
    vfs.add_file("/etc/os-release", os_release.encode("utf-8"), mode=0o644)

    # /etc/machine-id (empty for first-boot generation)
    vfs.add_file("/etc/machine-id", b"", mode=0o444)

    # /etc/fstab (minimal live ISO fstab)
    fstab = (
        "# /etc/fstab - Torito live ISO\n"
        "# <file system>  <mount point>  <type>  <options>  <dump>  <pass>\n"
        "tmpfs            /tmp           tmpfs   defaults,nosuid,nodev  0  0\n"
        "tmpfs            /run           tmpfs   defaults,nosuid,nodev,mode=0755  0  0\n"
    )
    vfs.add_file("/etc/fstab", fstab.encode("utf-8"), mode=0o644)

    # /etc/locale.gen
    vfs.add_file(
        "/etc/locale.gen",
        f"{config.locale} UTF-8\n".encode("utf-8"),
        mode=0o644,
    )


def apply_all_mutations(vfs: PosixVfs, config: BuildConfig) -> None:
    """
    Run every rootless mutation step in the correct order:

    1. System configuration files
    2. Users and groups
    3. Service wiring
    """
    synthesise_system_config(vfs, config)
    synthesise_users_and_groups(vfs, config)
    wire_services(vfs, config)

