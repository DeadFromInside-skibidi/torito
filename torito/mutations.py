"""
torito.mutations — Rootless State Synthesis
===========================================
Replaces everything a distro build normally does inside a ``chroot``:

* ``/etc/passwd|group|shadow|gshadow`` — merged from the ``filesystem``
  package, every package's ``sysusers.d`` declarations (what
  ``systemd-sysusers`` would create) and the manifest's users, with
  glibc-compatible SHA-512 ``$6$`` password hashes.
* ``systemctl enable/mask/set-default`` — real ``[Install]`` semantics
  (WantedBy/RequiredBy/Alias/Also/DefaultInstance, template instances,
  ``--global`` user units).
* Package post-install scripts — the effects that matter at build time are
  emulated; hooks that need Linux binaries (``depmod``,
  ``glib-compile-schemas``, ``update-mime-database``, ``update-ca-trust``…)
  are deferred to an early-boot oneshot that runs them inside the target.
"""

from __future__ import annotations

import hashlib
import os
import re
import shlex
import time
from collections import OrderedDict
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Tuple

from .config import BuildConfig, ServiceSpec
from .vfs import PosixVfs, VfsNodeType

Log = Callable[[str], None]


def _nolog(_: str) -> None:
    pass


# ---------------------------------------------------------------------------
# SHA-512 crypt ($6$) — Ulrich Drepper's algorithm as used by glibc crypt(3)
# ---------------------------------------------------------------------------

_SHA512_CRYPT_ROUNDS_DEFAULT = 5000
_SHA512_CRYPT_ROUNDS_MIN = 1000
_SHA512_CRYPT_ROUNDS_MAX = 999999999
_B64_CHARS = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"


def _b64_from_24bit(b2: int, b1: int, b0: int, n: int) -> str:
    w = (b2 << 16) | (b1 << 8) | b0
    out = []
    for _ in range(n):
        out.append(_B64_CHARS[w & 0x3F])
        w >>= 6
    return "".join(out)


def sha512_crypt(password: str, salt: str, rounds: int = _SHA512_CRYPT_ROUNDS_DEFAULT) -> str:
    """Compute a ``$6$`` SHA-512 password hash identical to glibc's ``crypt(3)``."""
    rounds = max(_SHA512_CRYPT_ROUNDS_MIN, min(rounds, _SHA512_CRYPT_ROUNDS_MAX))
    salt = salt[:16]
    pwd = password.encode("utf-8")
    slt = salt.encode("utf-8")

    digest_b = hashlib.sha512(pwd + slt + pwd).digest()
    a_ctx = hashlib.sha512()
    a_ctx.update(pwd)
    a_ctx.update(slt)
    plen = len(pwd)
    count = plen
    while count > 64:
        a_ctx.update(digest_b)
        count -= 64
    a_ctx.update(digest_b[:count])
    i = plen
    while i > 0:
        a_ctx.update(digest_b if i & 1 else pwd)
        i >>= 1
    digest_a = a_ctx.digest()

    dp_ctx = hashlib.sha512()
    for _ in range(plen):
        dp_ctx.update(pwd)
    digest_dp = dp_ctx.digest()
    p_bytes = (digest_dp * (plen // 64 + 1))[:plen]

    ds_ctx = hashlib.sha512()
    for _ in range(16 + digest_a[0]):
        ds_ctx.update(slt)
    digest_ds = ds_ctx.digest()
    s_bytes = (digest_ds * (len(slt) // 64 + 1))[: len(slt)]

    digest_c = digest_a
    for r in range(rounds):
        c_ctx = hashlib.sha512()
        c_ctx.update(p_bytes if r & 1 else digest_c)
        if r % 3:
            c_ctx.update(s_bytes)
        if r % 7:
            c_ctx.update(p_bytes)
        c_ctx.update(digest_c if r & 1 else p_bytes)
        digest_c = c_ctx.digest()

    f = digest_c
    order = [
        (0, 21, 42), (22, 43, 1), (44, 2, 23), (3, 24, 45), (25, 46, 4), (47, 5, 26),
        (6, 27, 48), (28, 49, 7), (50, 8, 29), (9, 30, 51), (31, 52, 10), (53, 11, 32),
        (12, 33, 54), (34, 55, 13), (56, 14, 35), (15, 36, 57), (37, 58, 16), (59, 17, 38),
        (18, 39, 60), (40, 61, 19), (62, 20, 41),
    ]
    hash_str = "".join(_b64_from_24bit(f[a], f[b], f[c], 4) for a, b, c in order)
    hash_str += _b64_from_24bit(0, 0, f[63], 2)
    if rounds == _SHA512_CRYPT_ROUNDS_DEFAULT:
        return f"$6${salt}${hash_str}"
    return f"$6$rounds={rounds}${salt}${hash_str}"


def _generate_salt(length: int = 16) -> str:
    raw = os.urandom(length)
    return "".join(_B64_CHARS[b % 64] for b in raw)[:length]


# ---------------------------------------------------------------------------
# Account database
# ---------------------------------------------------------------------------

_FALLBACK_PASSWD = [
    "root:x:0:0::/root:/bin/bash",
    "bin:x:1:1::/:/usr/bin/nologin",
    "daemon:x:2:2::/:/usr/bin/nologin",
    "mail:x:8:12::/var/spool/mail:/usr/bin/nologin",
    "ftp:x:14:11::/srv/ftp:/usr/bin/nologin",
    "http:x:33:33::/srv/http:/usr/bin/nologin",
    "nobody:x:65534:65534:Kernel Overflow User:/:/usr/bin/nologin",
]
_FALLBACK_GROUP = [
    "root:x:0:root", "sys:x:3:bin", "mem:x:8:", "ftp:x:11:", "mail:x:12:", "log:x:19:",
    "smmsp:x:25:", "proc:x:26:", "games:x:50:", "lock:x:54:", "network:x:90:",
    "floppy:x:94:", "scanner:x:96:", "power:x:98:", "adm:x:999:daemon", "wheel:x:998:",
    "utmp:x:997:", "audio:x:996:", "disk:x:995:", "input:x:994:", "kmem:x:993:",
    "kvm:x:992:", "lp:x:991:", "optical:x:990:", "render:x:989:", "sgx:x:988:",
    "storage:x:987:", "tty:x:5:", "uucp:x:986:", "video:x:985:", "users:x:984:",
    "nobody:x:65534:", "bin:x:1:daemon", "daemon:x:2:bin", "http:x:33:",
]


class Accounts:
    """In-memory view of passwd/group/shadow/gshadow with sysusers semantics."""

    SYS_MAX = 999
    SYS_MIN = 1  # never hand out 0
    USER_MIN = 1000

    def __init__(self) -> None:
        self.passwd: "OrderedDict[str, List[str]]" = OrderedDict()
        self.group: "OrderedDict[str, List[str]]" = OrderedDict()
        self.shadow: "OrderedDict[str, List[str]]" = OrderedDict()
        self.gshadow: "OrderedDict[str, List[str]]" = OrderedDict()

    # --- loading ---------------------------------------------------------
    @staticmethod
    def _parse(text: Optional[bytes], fields: int) -> "OrderedDict[str, List[str]]":
        out: "OrderedDict[str, List[str]]" = OrderedDict()
        if not text:
            return out
        for line in text.decode("utf-8", "replace").splitlines():
            if not line.strip() or line.startswith("#"):
                continue
            parts = line.split(":")
            parts += [""] * (fields - len(parts))
            out[parts[0]] = parts[:fields]
        return out

    @classmethod
    def from_vfs(cls, vfs: PosixVfs) -> "Accounts":
        a = cls()
        a.passwd = cls._parse(vfs.read_file("/etc/passwd"), 7)
        a.group = cls._parse(vfs.read_file("/etc/group"), 4)
        a.shadow = cls._parse(vfs.read_file("/etc/shadow"), 9)
        a.gshadow = cls._parse(vfs.read_file("/etc/gshadow"), 4)
        if not a.passwd:
            for line in _FALLBACK_PASSWD:
                p = line.split(":")
                a.passwd[p[0]] = p
        if not a.group:
            for line in _FALLBACK_GROUP:
                g = line.split(":")
                a.group[g[0]] = g
        for name in a.passwd:
            if name not in a.shadow:
                a.shadow[name] = [name, "!*" if name != "root" else "*", "", "", "", "", "", "", ""]
        for name, g in a.group.items():
            if name not in a.gshadow:
                a.gshadow[name] = [name, "!*", "", g[3]]
        return a

    # --- queries ---------------------------------------------------------
    def uids(self) -> Dict[str, int]:
        return {n: int(p[2]) for n, p in self.passwd.items() if p[2].isdigit()}

    def gids(self) -> Dict[str, int]:
        return {n: int(g[2]) for n, g in self.group.items() if g[2].isdigit()}

    def _used_uids(self) -> set:
        return set(self.uids().values())

    def _used_gids(self) -> set:
        return set(self.gids().values())

    def _alloc_system(self, want_both: bool) -> int:
        uu, gg = self._used_uids(), self._used_gids()
        for i in range(self.SYS_MAX, self.SYS_MIN - 1, -1):
            if want_both:
                if i not in uu and i not in gg:
                    return i
            elif i not in gg:
                return i
        raise RuntimeError("system ID range exhausted")

    def _alloc_user(self) -> int:
        uu, gg = self._used_uids(), self._used_gids()
        i = self.USER_MIN
        while i in uu or i in gg:
            i += 1
        return i

    # --- mutation --------------------------------------------------------
    def add_group(self, name: str, gid: Optional[int] = None, system: bool = True) -> int:
        if name in self.group:
            return int(self.group[name][2])
        if gid is None or gid in self._used_gids():
            gid = self._alloc_system(False) if system else self._alloc_user()
        self.group[name] = [name, "x", str(gid), ""]
        self.gshadow[name] = [name, "!*", "", ""]
        return gid

    def add_member(self, group: str, user: str) -> None:
        if group not in self.group:
            self.add_group(group)
        members = [m for m in self.group[group][3].split(",") if m]
        if user not in members:
            members.append(user)
        self.group[group][3] = ",".join(members)
        if group in self.gshadow:
            self.gshadow[group][3] = ",".join(members)

    def add_system_user(self, name: str, uid_spec: str, gecos: str, home: str, shell: str) -> None:
        if name in self.passwd:
            return
        uid: Optional[int] = None
        gid: Optional[int] = None
        group_name = name
        if uid_spec and uid_spec != "-" and not uid_spec.startswith("/"):
            if ":" in uid_spec:
                u, g = uid_spec.split(":", 1)
                uid = int(u) if u.isdigit() else None
                if g.isdigit():
                    gid = int(g)
                else:
                    group_name = g
            elif uid_spec.isdigit():
                uid = int(uid_spec)
        if uid is not None and uid in self._used_uids():
            uid = None
        if uid is None:
            want = int(self.group[group_name][2]) if group_name in self.group else None
            uid = want if (want is not None and want not in self._used_uids()) else self._alloc_system(group_name not in self.group)
        if group_name in self.group:
            gid = int(self.group[group_name][2])
        else:
            gid = self.add_group(group_name, gid if gid is not None else uid)
        self.passwd[name] = [name, "x", str(uid), str(gid), gecos, home or "/", shell or "/usr/bin/nologin"]
        self.shadow[name] = [name, "!*", "", "", "", "", "", "", ""]

    def apply_sysusers(self, text: str, log: Log = _nolog) -> None:
        for raw in text.splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            try:
                toks = shlex.split(line)
            except ValueError:
                continue
            if len(toks) < 2:
                continue
            kind, name = toks[0].rstrip("!"), toks[1]
            arg = toks[2] if len(toks) > 2 else "-"
            if kind == "g":
                gid = int(arg) if arg.isdigit() else None
                self.add_group(name, gid)
            elif kind == "u":
                gecos = toks[3] if len(toks) > 3 and toks[3] != "-" else ""
                home = toks[4] if len(toks) > 4 and toks[4] != "-" else "/"
                shell = toks[5] if len(toks) > 5 and toks[5] != "-" else "/usr/bin/nologin"
                self.add_system_user(name, arg, gecos, home, shell)
            elif kind == "m":
                if name in self.passwd:
                    self.add_member(arg, name)
            # 'r' (ranges) only constrains allocation; our defaults already match.

    def set_password(self, user: str, password: Optional[str], last_change: int) -> None:
        if password is None:
            hashed = "!*"
        elif password == "":
            hashed = ""
        elif password.startswith("$"):
            hashed = password  # already hashed
        else:
            hashed = sha512_crypt(password, _generate_salt(16))
        self.shadow[user] = [user, hashed, str(last_change), "0", "99999", "7", "", "", ""]

    # --- output ----------------------------------------------------------
    def write(self, vfs: PosixVfs) -> None:
        def dump(d: "OrderedDict[str, List[str]]") -> bytes:
            return ("\n".join(":".join(v) for v in d.values()) + "\n").encode("utf-8")

        vfs.add_file("/etc/passwd", dump(self.passwd), mode=0o644)
        vfs.add_file("/etc/group", dump(self.group), mode=0o644)
        vfs.add_file("/etc/shadow", dump(self.shadow), mode=0o600)
        vfs.add_file("/etc/gshadow", dump(self.gshadow), mode=0o600)


def _sysusers_files(vfs: PosixVfs) -> List[Tuple[str, bytes]]:
    chosen: Dict[str, bytes] = {}
    for d in ("/usr/lib/sysusers.d", "/etc/sysusers.d"):
        for name in vfs.list_dir(d):
            if name.endswith(".conf"):
                data = vfs.read_file(f"{d}/{name}")
                if data is not None:
                    chosen[name] = data  # /etc overrides /usr/lib
    return sorted(chosen.items())


def synthesise_users_and_groups(vfs: PosixVfs, config: BuildConfig, log: Log = _nolog) -> Accounts:
    """Build the account database and home directories. Returns the result."""
    acc = Accounts.from_vfs(vfs)
    for name, data in _sysusers_files(vfs):
        acc.apply_sysusers(data.decode("utf-8", "replace"), log)

    days = int(time.time()) // 86400

    for grp in config.groups:
        acc.add_group(grp.name, grp.gid, system=grp.gid is not None and grp.gid < 1000)
        if grp.gid is not None and acc.group[grp.name][2] != str(grp.gid):
            acc.group[grp.name][2] = str(grp.gid)
        for m in grp.members:
            if m in acc.passwd or any(u.name == m for u in config.users):
                pass  # membership added after users exist

    for user in config.users:
        home = user.home_dir()
        if user.name in acc.passwd:
            entry = acc.passwd[user.name]
            if user.uid is not None:
                entry[2] = str(user.uid)
            if user.gid is not None:
                entry[3] = str(user.gid)
            entry[5] = home if user.home else entry[5]
            entry[6] = user.shell or entry[6]
            if user.gecos:
                entry[4] = user.gecos
        else:
            uid = user.uid if user.uid is not None else acc._alloc_user()
            if user.gid is not None:
                gid = user.gid
                existing = [n for n, g in acc.group.items() if g[2] == str(gid)]
                if not existing:
                    acc.add_group(user.name, gid, system=False)
            else:
                gid = acc.add_group(user.name, uid, system=False)
            acc.passwd[user.name] = [user.name, "x", str(uid), str(gid), user.gecos, home, user.shell]
        acc.set_password(user.name, user.password, days)
        for g in user.groups:
            acc.add_member(g, user.name)

    for grp in config.groups:
        for m in grp.members:
            if m in acc.passwd:
                acc.add_member(grp.name, m)

    acc.write(vfs)

    # Home directories with /etc/skel contents.
    uids, gids = acc.uids(), acc.gids()
    for user in config.users:
        if not user.create_home:
            continue
        entry = acc.passwd[user.name]
        uid, gid, home = int(entry[2]), int(entry[3]), entry[5]
        if not home or home == "/":
            continue
        vfs.mkdir(home, mode=0o700 if user.name != "root" else 0o750, uid=uid, gid=gid)
        for path, node in list(vfs.iter_subtree("/etc/skel")):
            rel = path[len("/etc/skel"):]
            if not rel:
                continue
            dest = home.rstrip("/") + rel
            if vfs.exists(dest):
                continue
            if node.node_type == VfsNodeType.DIRECTORY:
                vfs.mkdir(dest, mode=node.mode, uid=uid, gid=gid)
            elif node.node_type == VfsNodeType.REGULAR_FILE:
                vfs.add_file(dest, node.data, mode=node.mode, uid=uid, gid=gid)
            elif node.node_type == VfsNodeType.SYMLINK:
                vfs.add_symlink(dest, node.link_target, uid=uid, gid=gid)
        # Anything an overlay already put in the home belongs to the user.
        for path, node in vfs.iter_subtree(home):
            node.uid, node.gid = uid, gid
            node.uname = node.gname = ""
    log(f"  accounts: {len(acc.passwd)} users, {len(acc.group)} groups")
    return acc


# ---------------------------------------------------------------------------
# systemd unit enablement
# ---------------------------------------------------------------------------

SYSTEM_UNIT_DIRS = ["/etc/systemd/system", "/usr/lib/systemd/system"]
USER_UNIT_DIRS = ["/etc/systemd/user", "/usr/lib/systemd/user"]
_UNIT_SUFFIXES = (".service", ".socket", ".target", ".timer", ".path", ".mount", ".automount", ".swap", ".slice", ".scope", ".device")


def _unit_name(name: str) -> str:
    return name if name.endswith(_UNIT_SUFFIXES) else name + ".service"


def _split_instance(unit: str) -> Tuple[str, str, str]:
    """``getty@tty1.service`` → (``getty@.service``, ``tty1``, ``.service``)."""
    base, dot, suffix = unit.rpartition(".")
    if "@" in base:
        prefix, inst = base.split("@", 1)
        return f"{prefix}@.{suffix}", inst, "." + suffix
    return unit, "", "." + suffix


def _find_unit(vfs: PosixVfs, unit: str, dirs: Sequence[str]) -> Optional[str]:
    for d in dirs:
        p = f"{d}/{unit}"
        if vfs.lookup(p) is not None:
            return p
    return None


def parse_install_section(text: str) -> Dict[str, List[str]]:
    out: Dict[str, List[str]] = {}
    section = ""
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1]
            continue
        if section != "Install" or "=" not in line:
            continue
        k, v = line.split("=", 1)
        out.setdefault(k.strip(), []).extend(v.split())
    return out


def _parse_systemd_wanted_by(unit_content: str) -> List[str]:
    """Backwards-compatible helper: WantedBy= targets of a unit."""
    return parse_install_section(unit_content).get("WantedBy", [])


def enable_systemd_unit(
    vfs: PosixVfs,
    name: str,
    user: bool = False,
    target_override: str = "",
    log: Log = _nolog,
    _seen: Optional[set] = None,
) -> bool:
    """Equivalent of ``systemctl [--global] enable <name>``. Returns success."""
    seen = _seen if _seen is not None else set()
    unit = _unit_name(name)
    if unit in seen:
        return True
    seen.add(unit)
    dirs = USER_UNIT_DIRS if user else SYSTEM_UNIT_DIRS
    etc_dir = dirs[0]
    template, instance, _ = _split_instance(unit)
    path = _find_unit(vfs, unit, dirs) or (_find_unit(vfs, template, dirs) if instance or "@" in unit else None)
    if path is None:
        log(f"  ⚠ cannot enable {unit}: unit file not found")
        return False
    node = vfs.lookup(path)
    text = node.data.decode("utf-8", "replace") if node is not None else ""
    # Drop-ins can extend [Install]? (No — systemd ignores [Install] in drop-ins.)
    inst = parse_install_section(text)
    real_target = vfs.resolve(path, follow_last=True)
    if "@" in unit and not instance:
        default_inst = (inst.get("DefaultInstance") or [""])[0]
        if default_inst:
            unit = template.replace("@.", f"@{default_inst}.")
            instance = default_inst

    def subst(s: str) -> str:
        return s.replace("%i", instance).replace("%I", instance).replace("%n", unit).replace("%N", unit.rsplit(".", 1)[0])

    targets: List[Tuple[str, str]] = []
    if target_override:
        targets.append((target_override, "wants"))
    else:
        targets += [(t, "wants") for t in inst.get("WantedBy", [])]
        targets += [(t, "requires") for t in inst.get("RequiredBy", [])]
        targets += [(t, "upholds") for t in inst.get("UpheldBy", [])]
    aliases = [subst(a) for a in inst.get("Alias", [])]
    also = [subst(a) for a in inst.get("Also", [])]
    if not targets and not aliases and not also:
        log(f"  ⚠ {unit} has no [Install] section (static unit); nothing to enable")
        return False
    for tgt, kind in targets:
        d = f"{etc_dir}/{subst(tgt)}.{kind}"
        vfs.mkdir(d)
        vfs.add_symlink(f"{d}/{unit}", real_target)
    for a in aliases:
        vfs.mkdir(etc_dir)
        vfs.add_symlink(f"{etc_dir}/{a}", real_target)
    for a in also:
        enable_systemd_unit(vfs, a, user=user, log=log, _seen=seen)
    return True


def mask_systemd_unit(vfs: PosixVfs, name: str, user: bool = False) -> None:
    etc_dir = (USER_UNIT_DIRS if user else SYSTEM_UNIT_DIRS)[0]
    vfs.mkdir(etc_dir)
    vfs.add_symlink(f"{etc_dir}/{_unit_name(name)}", "/dev/null")


def set_default_target(vfs: PosixVfs, target: str) -> None:
    t = _unit_name(target) if target.endswith(".target") else target + ".target"
    path = _find_unit(vfs, t, SYSTEM_UNIT_DIRS) or f"/usr/lib/systemd/system/{t}"
    vfs.mkdir("/etc/systemd/system")
    vfs.add_symlink("/etc/systemd/system/default.target", vfs.resolve(path, follow_last=True))


def _enable_openrc_service(vfs: PosixVfs, svc: ServiceSpec) -> None:
    name = svc.name.replace(".service", "")
    rl = svc.runlevel or "default"
    vfs.mkdir(f"/etc/runlevels/{rl}")
    vfs.add_symlink(f"/etc/runlevels/{rl}/{name}", f"/etc/init.d/{name}")


def _enable_runit_service(vfs: PosixVfs, svc: ServiceSpec) -> None:
    name = svc.name.replace(".service", "")
    vfs.mkdir("/var/service")
    vfs.add_symlink(f"/var/service/{name}", f"/etc/sv/{name}")


def wire_services(vfs: PosixVfs, config: BuildConfig, log: Log = _nolog) -> None:
    for svc in config.services:
        if svc.init_system == "systemd":
            if svc.mask:
                mask_systemd_unit(vfs, svc.name, user=svc.user)
            else:
                enable_systemd_unit(vfs, svc.name, user=svc.user, target_override=svc.target, log=log)
        elif svc.init_system == "openrc":
            _enable_openrc_service(vfs, svc)
        elif svc.init_system == "runit":
            _enable_runit_service(vfs, svc)
        else:
            raise ValueError(f"Unknown init system: {svc.init_system!r}")
    if config.default_target:
        set_default_target(vfs, config.default_target)


# ---------------------------------------------------------------------------
# Package install-script emulation & deferred hooks
# ---------------------------------------------------------------------------

# Effects of well-known .INSTALL scripts that must exist before first boot.
_INSTALL_EMULATION: Dict[str, List[Tuple[str, str]]] = {
    "systemd": [("enable", "getty@tty1.service"), ("enable", "remote-fs.target")],
}

DEFERRED_HOOKS_SCRIPT = r"""#!/bin/sh
# Generated by Torito: package hooks that need the target's own binaries.
# Runs once per boot of the live image (state lives in the overlay), early,
# before udev and the display manager.
export PATH=/usr/local/sbin:/usr/local/bin:/usr/bin
log() { echo "torito-hooks: $*"; }
have() { command -v "$1" >/dev/null 2>&1; }

for kdir in /usr/lib/modules/*/; do
    kver=$(basename "$kdir")
    if [ ! -e "$kdir/modules.dep.bin" ] && have depmod; then
        log "depmod $kver"; depmod -a "$kver"
    fi
done
if [ -s /etc/locale.gen ] && have locale-gen && grep -q '^[^#]' /etc/locale.gen && [ ! -e /usr/lib/locale/locale-archive ]; then
    log "locale-gen"; locale-gen >/dev/null
fi
have ldconfig && ldconfig
[ -d /usr/share/glib-2.0/schemas ] && have glib-compile-schemas && glib-compile-schemas /usr/share/glib-2.0/schemas
[ -d /usr/lib/gio/modules ] && have gio-querymodules && gio-querymodules /usr/lib/gio/modules
for d in /usr/lib/gdk-pixbuf-2.0/*/loaders; do
    [ -d "$d" ] && have gdk-pixbuf-query-loaders && gdk-pixbuf-query-loaders --update-cache
    break
done
[ -d /usr/share/mime ] && have update-mime-database && update-mime-database /usr/share/mime
[ -d /usr/share/applications ] && have update-desktop-database && update-desktop-database -q /usr/share/applications
have update-ca-trust && update-ca-trust extract
have systemd-hwdb && [ ! -e /etc/udev/hwdb.bin ] && [ ! -e /usr/lib/udev/hwdb.bin ] && systemd-hwdb update
have dconf && [ -d /etc/dconf/db ] && dconf update
exit 0
"""

DEFERRED_LATE_SCRIPT = r"""#!/bin/sh
# Generated by Torito: slow, non-critical hooks run in the background.
export PATH=/usr/local/sbin:/usr/local/bin:/usr/bin
have() { command -v "$1" >/dev/null 2>&1; }
have fc-cache && fc-cache -s
for d in /usr/share/icons/*/; do
    [ -f "$d/index.theme" ] && have gtk-update-icon-cache && gtk-update-icon-cache -q -t -f "$d"
done
if have pacman-key && [ ! -f /etc/pacman.d/gnupg/trustdb.gpg ]; then
    pacman-key --init && pacman-key --populate
fi
exit 0
"""

DEFERRED_HOOKS_UNIT = """[Unit]
Description=Torito deferred package hooks
DefaultDependencies=no
After=systemd-remount-fs.service
Before=sysinit.target systemd-udevd.service systemd-udev-trigger.service systemd-modules-load.service kmod-static-nodes.service systemd-tmpfiles-setup-dev-early.service
ConditionPathExists=!/run/torito-hooks.done

[Service]
Type=oneshot
ExecStart=/usr/lib/torito/torito-hooks
ExecStartPost=/usr/bin/touch /run/torito-hooks.done
RemainAfterExit=yes
StandardOutput=journal+console

[Install]
WantedBy=sysinit.target
"""

DEFERRED_LATE_UNIT = """[Unit]
Description=Torito deferred background hooks (fonts, icons, pacman keyring)
After=multi-user.target

[Service]
Type=oneshot
Nice=10
IOSchedulingClass=idle
ExecStart=/usr/lib/torito/torito-hooks-late
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
"""


def emulate_install_scripts(vfs: PosixVfs, installed: Iterable[str], scripts: Dict[str, bytes], log: Log = _nolog) -> None:
    names = set(installed)
    for pkg, actions in _INSTALL_EMULATION.items():
        if pkg not in names:
            continue
        for action, arg in actions:
            if action == "enable":
                enable_systemd_unit(vfs, arg, log=log)
    with_scripts = sorted(n for n, s in scripts.items() if s and n not in _INSTALL_EMULATION)
    if with_scripts:
        log(f"  install scriptlets deferred/skipped for {len(with_scripts)} packages")


def install_deferred_hooks(vfs: PosixVfs, log: Log = _nolog) -> None:
    if not vfs.is_dir("/usr/lib/systemd/system"):
        return
    vfs.mkdir("/usr/lib/torito")
    vfs.add_file("/usr/lib/torito/torito-hooks", DEFERRED_HOOKS_SCRIPT.encode(), mode=0o755)
    vfs.add_file("/usr/lib/torito/torito-hooks-late", DEFERRED_LATE_SCRIPT.encode(), mode=0o755)
    vfs.add_file("/usr/lib/systemd/system/torito-hooks.service", DEFERRED_HOOKS_UNIT.encode())
    vfs.add_file("/usr/lib/systemd/system/torito-hooks-late.service", DEFERRED_LATE_UNIT.encode())
    enable_systemd_unit(vfs, "torito-hooks.service", log=log)
    enable_systemd_unit(vfs, "torito-hooks-late.service", log=log)
    # hwdb.bin is compiled at first boot (systemd-hwdb-update.service), which
    # runs after generators; the cloud IMDS generator needs it and would log a
    # spurious failure on every boot.  Mask it (meaningless on live media).
    gen = "/usr/lib/systemd/system-generators/systemd-imds-generator"
    if vfs.lookup(gen) is not None and vfs.lookup("/usr/lib/udev/hwdb.bin") is None:
        vfs.mkdir("/etc/systemd/system-generators")
        vfs.add_symlink("/etc/systemd/system-generators/systemd-imds-generator", "/dev/null")


# ---------------------------------------------------------------------------
# System configuration
# ---------------------------------------------------------------------------


def synthesise_system_config(vfs: PosixVfs, config: BuildConfig, log: Log = _nolog) -> None:
    vfs.mkdir("/etc")
    vfs.add_file("/etc/hostname", (config.hostname + "\n").encode())
    vfs.add_file(
        "/etc/hosts",
        (
            "127.0.0.1   localhost\n"
            "::1         localhost\n"
            f"127.0.1.1   {config.hostname}.localdomain {config.hostname}\n"
        ).encode(),
    )
    vfs.add_file("/etc/locale.conf", f"LANG={config.locale}\n".encode())
    vfs.add_file("/etc/vconsole.conf", f"KEYMAP={config.keymap}\n".encode())
    zone = f"/usr/share/zoneinfo/{config.timezone}"
    vfs.add_symlink("/etc/localtime", ".." + zone)

    # locale.gen: uncomment the requested locale in glibc's template.
    loc = config.locale
    charset = loc.split(".", 1)[1] if "." in loc else "UTF-8"
    wanted = f"{loc} {charset}"
    existing = vfs.read_file("/etc/locale.gen")
    if existing:
        lines = existing.decode("utf-8", "replace").splitlines()
        found = False
        for i, line in enumerate(lines):
            if line.lstrip("#").strip() == wanted:
                lines[i] = wanted
                found = True
        if not found:
            lines.append(wanted)
        vfs.add_file("/etc/locale.gen", ("\n".join(lines) + "\n").encode())
    else:
        vfs.add_file("/etc/locale.gen", (wanted + "\n").encode())

    # os-release: keep an overlay-provided regular file, else generate one.
    node = vfs.get("/etc/os-release")
    if node is None or node.node_type != VfsNodeType.REGULAR_FILE or config.os_release:
        slug = re.sub(r"[^a-z0-9._-]", "-", config.name.lower())
        fields = OrderedDict(
            [
                ("NAME", config.name),
                ("PRETTY_NAME", f"{config.name} {config.version}"),
                ("ID", slug),
                ("VERSION", config.version),
                ("VERSION_ID", config.version),
                ("BUILD_ID", config.version),
            ]
        )
        if vfs.exists("/var/lib/pacman/local"):
            fields["ID_LIKE"] = "arch"
        fields.update(config.os_release)
        text = "".join(f'{k}="{v}"\n' for k, v in fields.items())
        vfs.add_file("/usr/lib/os-release", text.encode())
        vfs.add_symlink("/etc/os-release", "../usr/lib/os-release")

    # machine-id: empty → systemd treats the boot as first boot and generates one.
    vfs.add_file("/etc/machine-id", b"", mode=0o444)
    if not vfs.exists("/etc/fstab"):
        vfs.add_file("/etc/fstab", b"# /etc/fstab: static file system information (live system)\n")


_NETWORK_MANAGERS = (
    "NetworkManager.service", "systemd-networkd.service", "connman.service", "dhcpcd.service",
    "netctl.service", "wicd.service", "iwd.service",
)

WIRED_DHCP_NETWORK = """# Generated by Torito: DHCP on every wired interface of the live system.
[Match]
Type=ether
Kind=!*

[Link]
RequiredForOnline=routable

[Network]
DHCP=yes
MulticastDNS=yes

[DHCPv4]
RouteMetric=100

[IPv6AcceptRA]
RouteMetric=100
"""


def _enabled_network_manager(vfs: PosixVfs) -> Optional[str]:
    etc = "/etc/systemd/system"
    for d in vfs.list_dir(etc):
        if not d.endswith((".wants", ".requires")):
            continue
        for unit in vfs.list_dir(f"{etc}/{d}"):
            if unit in _NETWORK_MANAGERS or unit.startswith(("dhcpcd@", "netctl@")):
                return unit
    for alias in ("dbus-org.freedesktop.NetworkManager.service", "dbus-org.freedesktop.network1.service"):
        if vfs.lookup(f"{etc}/{alias}") is not None:
            return alias
    return None


def configure_network(vfs: PosixVfs, config: BuildConfig, log: Log = _nolog) -> None:
    """
    A live system without networking is the most common "it boots but is
    useless" surprise.  When the manifest enables no network manager, wire
    up systemd-networkd (DHCP on Ethernet) + systemd-resolved, both of which
    ship with ``systemd`` itself.
    """
    if not config.network_auto:
        return
    existing = _enabled_network_manager(vfs)
    if existing:
        return
    if _find_unit(vfs, "systemd-networkd.service", SYSTEM_UNIT_DIRS) is None:
        return
    vfs.mkdir("/etc/systemd/network")
    if not vfs.list_dir("/etc/systemd/network"):
        vfs.add_file("/etc/systemd/network/20-wired.network", WIRED_DHCP_NETWORK.encode())
    enable_systemd_unit(vfs, "systemd-networkd.service", log=log)
    if _find_unit(vfs, "systemd-resolved.service", SYSTEM_UNIT_DIRS) is not None:
        enable_systemd_unit(vfs, "systemd-resolved.service", log=log)
        # Point resolv.conf at resolved's stub unless an overlay supplied real nameservers.
        node = vfs.get("/etc/resolv.conf")
        hand_written = node is not None and node.node_type == VfsNodeType.REGULAR_FILE and b"nameserver" in node.data
        if not hand_written:
            if node is not None:
                vfs.remove("/etc/resolv.conf")
            vfs.add_symlink("/etc/resolv.conf", "../run/systemd/resolve/stub-resolv.conf")
    log("  network: no network manager enabled — using systemd-networkd (DHCP) + systemd-resolved")


def configure_pacman_mirrors(vfs: PosixVfs, config: BuildConfig, log: Log = _nolog) -> None:
    """
    ``pacman-mirrorlist`` ships with every server commented out, so ``pacman
    -Sy`` in the booted image fails. Enable the mirrors the image was built
    from, unless the mirrorlist (e.g. from an overlay) already has servers.
    """
    path = "/etc/pacman.d/mirrorlist"
    if vfs.lookup("/etc/pacman.conf") is None:
        return
    current = vfs.read_file(path)
    text = current.decode("utf-8", "replace") if current else ""
    if any(line.strip().startswith("Server") for line in text.splitlines()):
        return
    servers: List[str] = []
    for repo in config.repositories:
        if repo.name in ("core", "extra", "multilib"):
            for s in repo.servers:
                if s not in servers:
                    servers.append(s)
    if not servers:
        return
    head = "## Added by Torito: the mirrors this image was built from.\n" + "".join(f"Server = {s}\n" for s in servers)
    vfs.mkdir("/etc/pacman.d")
    vfs.add_file(path, (head + "\n" + text).encode(), mode=0o644)
    log(f"  pacman: enabled {len(servers)} mirrors in {path}")


def apply_file_permissions(vfs: PosixVfs, perms: Dict[str, str], acc: Optional[Accounts], log: Log = _nolog) -> None:
    uids = acc.uids() if acc else {"root": 0}
    gids = acc.gids() if acc else {"root": 0}
    for path, spec in perms.items():
        parts = spec.split(":")
        if len(parts) != 3:
            log(f"  ⚠ bad permission spec for {path}: {spec}")
            continue
        u, g, m = parts
        node = vfs.lookup(path)
        if node is None:
            log(f"  ⚠ file_permissions: {path} does not exist")
            continue
        node.uid = int(u) if u.isdigit() else uids.get(u, 0)
        node.gid = int(g) if g.isdigit() else gids.get(g, 0)
        node.uname = node.gname = ""
        node.mode = int(m, 8)


def remove_paths(vfs: PosixVfs, patterns: Sequence[str], log: Log = _nolog) -> int:
    import fnmatch

    removed = 0
    for pat in patterns:
        if any(ch in pat for ch in "*?["):
            base = pat.split("*", 1)[0].rsplit("/", 1)[0] or "/"
            for p, _ in list(vfs.iter_subtree(base)):
                if fnmatch.fnmatch(p, pat) and vfs.exists(p):
                    vfs.remove(p)
                    removed += 1
        elif vfs.exists(pat):
            vfs.remove(pat)
            removed += 1
    if removed:
        log(f"  removed {removed} paths")
    return removed


def apply_all_mutations(vfs: PosixVfs, config: BuildConfig, log: Log = _nolog) -> Accounts:
    """
    System config → accounts → owner resolution → services → permissions.
    Returns the final account database.
    """
    synthesise_system_config(vfs, config, log)
    acc = synthesise_users_and_groups(vfs, config, log)
    vfs.resolve_owners(acc.uids(), acc.gids(), log)
    wire_services(vfs, config, log)
    configure_network(vfs, config, log)
    configure_pacman_mirrors(vfs, config, log)
    apply_file_permissions(vfs, config.file_permissions, acc, log)
    return acc
