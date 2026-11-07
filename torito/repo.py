"""
torito.repo — Pacman Repository Client & Dependency Resolver
=============================================================
Pure-Python replacement for ``pacman -Sy`` + ``pacman -Sw``:

* downloads and parses sync databases (``core.db``, ``extra.db`` …)
* resolves a package set with full dependency closure, honouring
  ``provides`` (virtual packages), ``replaces`` and user preferences
* downloads package archives into a shared cache, verifying SHA-256
  against the database, with mirror fail-over and parallel transfers.

No pacman, no libalpm, no root — just HTTP and tar parsing.
"""

from __future__ import annotations

import gzip
import hashlib
import io
import lzma
import os
import re
import tarfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Set, Tuple

DEFAULT_MIRRORS: List[str] = [
    "https://fastly.mirror.pkgbuild.com/$repo/os/$arch",
    "https://geo.mirror.pkgbuild.com/$repo/os/$arch",
    "https://mirror.rackspace.com/archlinux/$repo/os/$arch",
    "https://mirrors.edge.kernel.org/archlinux/$repo/os/$arch",
]

def _user_agent() -> str:
    from . import __version__

    return f"torito/{__version__} (+https://github.com/DeadFromInside-skibidi/torito)"


USER_AGENT = _user_agent()

# When several packages provide the same virtual dependency, these win
# unless the manifest says otherwise.  Mirrors the answers most people give
# to pacman's provider prompts.
DEFAULT_PROVIDER_PREFERENCES: Dict[str, str] = {
    "sh": "bash",
    "initramfs": "mkinitcpio",
    "jack": "pipewire-jack",
    "libjack.so": "pipewire-jack",
    "libjack.so=0-64": "pipewire-jack",
    "pipewire-session-manager": "wireplumber",
    "pulse-native-provider": "pipewire-pulse",
    "ttf-font": "noto-fonts",
    "java-runtime": "jre-openjdk",
    "java-environment": "jdk-openjdk",
    "phonon-qt6-backend": "phonon-qt6-vlc",
    "libgl": "mesa",
    "opengl-driver": "mesa",
    "vulkan-driver": "vulkan-swrast",
    "libva-driver": "libva-mesa-driver",
    "emacs": "emacs",
    "man": "man-db",
    "cron": "cronie",
    "smtp-forwarder": "msmtp-mta",
    "dbus-units": "dbus-broker-units",
    "mkinitcpio": "mkinitcpio",
    "iptables": "iptables",
    "libxtables.so": "iptables",
    "linux-headers": "linux-headers",
    "awk": "gawk",
    "rust": "rust",
    "tls-client": "gnutls",
}

_DEP_SPLIT = re.compile(r"(<=|>=|=|<|>)")


def dep_name(dep: str) -> str:
    """Strip version constraints and descriptions: ``foo>=1.2: why`` → ``foo``."""
    dep = dep.split(": ", 1)[0].strip()
    return _DEP_SPLIT.split(dep, 1)[0].strip()


def dep_constraint(dep: str) -> Tuple[str, str, str]:
    """``foo>=1.2`` → (``foo``, ``>=``, ``1.2``); no constraint → (name, "", "")."""
    dep = dep.split(": ", 1)[0].strip()
    parts = _DEP_SPLIT.split(dep, 1)
    if len(parts) == 3:
        return parts[0].strip(), parts[1], parts[2].strip()
    return dep, "", ""


def _rpmvercmp(a: str, b: str) -> int:
    """libalpm's rpmvercmp for the version (no epoch / pkgrel) part."""
    if a == b:
        return 0

    def isalnum(c: str) -> bool:
        return c.isascii() and c.isalnum()

    one = two = 0  # cursors
    p1 = p2 = 0  # end of previous segment
    la, lb = len(a), len(b)
    while one < la and two < lb:
        while one < la and not isalnum(a[one]):
            one += 1
        while two < lb and not isalnum(b[two]):
            two += 1
        if not (one < la and two < lb):
            break
        if (one - p1) != (two - p2):  # different separator lengths
            return -1 if (one - p1) < (two - p2) else 1
        p1, p2 = one, two
        isnum = a[p1].isdigit()
        if isnum:
            while p1 < la and a[p1].isdigit():
                p1 += 1
            while p2 < lb and b[p2].isdigit():
                p2 += 1
        else:
            while p1 < la and a[p1].isalpha():
                p1 += 1
            while p2 < lb and b[p2].isalpha():
                p2 += 1
        sa, sb = a[one:p1], b[two:p2]
        if not sb:
            return 1 if isnum else -1
        if isnum:
            sa, sb = sa.lstrip("0"), sb.lstrip("0")
            if len(sa) != len(sb):
                return 1 if len(sa) > len(sb) else -1
        if sa != sb:
            return -1 if sa < sb else 1
        one, two = p1, p2
    if one >= la and two >= lb:
        return 0
    if (one >= la and not (two < lb and b[two].isalpha())) or (one < la and a[one].isalpha()):
        return -1
    return 1


def vercmp(a: str, b: str) -> int:
    """Compare pacman versions ``[epoch:]ver[-rel]`` (like ``vercmp``)."""
    def split(v: str) -> Tuple[str, str, Optional[str]]:
        ep = "0"
        if ":" in v:
            ep, v = v.split(":", 1)
        rel: Optional[str] = None
        if "-" in v:
            v, rel = v.rsplit("-", 1)
        return ep or "0", v, rel

    ea, va, ra = split(a)
    eb, vb, rb = split(b)
    r = _rpmvercmp(ea, eb) or _rpmvercmp(va, vb)
    if r == 0 and ra is not None and rb is not None:
        r = _rpmvercmp(ra, rb)
    return r


def satisfies(version: str, op: str, want: str) -> bool:
    if not op:
        return True
    # A constraint without pkgrel matches any pkgrel.
    v = version if "-" in want else version.rsplit("-", 1)[0]
    c = vercmp(v, want)
    return {"=": c == 0, ">=": c >= 0, "<=": c <= 0, ">": c > 0, "<": c < 0}.get(op, True)


def local_filename(filename: str) -> str:
    """Package file names contain ':' (epochs) — illegal on NTFS (alternate data streams!)."""
    return filename.replace(":", "%3A")


@dataclass
class PackageInfo:
    """One entry of a sync database."""

    name: str
    version: str
    repo: str
    filename: str
    sha256: str = ""
    csize: int = 0
    isize: int = 0
    desc: str = ""
    base: str = ""
    url: str = ""
    arch: str = ""
    builddate: int = 0
    packager: str = ""
    licenses: List[str] = field(default_factory=list)
    groups: List[str] = field(default_factory=list)
    depends: List[str] = field(default_factory=list)
    optdepends: List[str] = field(default_factory=list)
    provides: List[str] = field(default_factory=list)
    conflicts: List[str] = field(default_factory=list)
    replaces: List[str] = field(default_factory=list)

    @property
    def ident(self) -> str:
        return f"{self.name}-{self.version}"


@dataclass
class RepoSpec:
    name: str
    servers: List[str] = field(default_factory=list)


class RepoError(RuntimeError):
    pass


def _open_db_tar(raw: bytes) -> tarfile.TarFile:
    if raw[:4] == b"\x28\xb5\x2f\xfd":
        import zstandard

        raw = zstandard.ZstdDecompressor().decompressobj().decompress(raw)
        return tarfile.open(fileobj=io.BytesIO(raw), mode="r:")
    if raw[:2] == b"\x1f\x8b":
        return tarfile.open(fileobj=io.BytesIO(gzip.decompress(raw)), mode="r:")
    if raw[:6] == b"\xfd7zXZ\x00":
        return tarfile.open(fileobj=io.BytesIO(lzma.decompress(raw)), mode="r:")
    return tarfile.open(fileobj=io.BytesIO(raw), mode="r:*")


def parse_desc(text: str) -> Dict[str, List[str]]:
    """Parse a pacman ``desc`` file (``%KEY%`` sections)."""
    out: Dict[str, List[str]] = {}
    key: Optional[str] = None
    for line in text.splitlines():
        if line.startswith("%") and line.endswith("%") and len(line) > 2:
            key = line[1:-1]
            out[key] = []
        elif line == "":
            key = None
        elif key is not None:
            out[key].append(line)
    return out


def parse_sync_db(raw: bytes, repo: str) -> List[PackageInfo]:
    pkgs: List[PackageInfo] = []
    tf = _open_db_tar(raw)
    for m in tf:
        if not m.isfile() or not m.name.endswith("/desc"):
            continue
        fh = tf.extractfile(m)
        if fh is None:
            continue
        d = parse_desc(fh.read().decode("utf-8", "replace"))

        def one(k: str, default: str = "") -> str:
            v = d.get(k)
            return v[0] if v else default

        pkgs.append(
            PackageInfo(
                name=one("NAME"),
                version=one("VERSION"),
                repo=repo,
                filename=one("FILENAME"),
                sha256=one("SHA256SUM"),
                csize=int(one("CSIZE", "0") or 0),
                isize=int(one("ISIZE", "0") or 0),
                desc=one("DESC"),
                base=one("BASE"),
                url=one("URL"),
                arch=one("ARCH"),
                builddate=int(one("BUILDDATE", "0") or 0),
                packager=one("PACKAGER"),
                licenses=d.get("LICENSE", []),
                groups=d.get("GROUPS", []),
                depends=d.get("DEPENDS", []),
                optdepends=d.get("OPTDEPENDS", []),
                provides=d.get("PROVIDES", []),
                conflicts=d.get("CONFLICTS", []),
                replaces=d.get("REPLACES", []),
            )
        )
    tf.close()
    return pkgs


def _expand_server(server: str, repo: str, arch: str) -> str:
    return server.replace("$repo", repo).replace("$arch", arch).rstrip("/")


def _http_get(url: str, timeout: float = 60.0) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def _http_download(url: str, dest: str, timeout: float = 120.0) -> None:
    tmp = dest + ".part"
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as resp, open(tmp, "wb") as out:
        while True:
            chunk = resp.read(1 << 20)
            if not chunk:
                break
            out.write(chunk)
    os.replace(tmp, dest)


class PackageDatabase:
    """
    The union of several sync databases, with provider lookup.
    Repositories listed first win on name collisions (pacman semantics).
    """

    def __init__(
        self,
        repos: Sequence[RepoSpec],
        arch: str = "x86_64",
        cache_dir: str = ".torito-cache",
        log: Optional[Callable[[str], None]] = None,
        db_max_age: int = 6 * 3600,
    ) -> None:
        self.repos = list(repos)
        self.arch = arch
        self.cache_dir = os.path.abspath(cache_dir)
        self.db_dir = os.path.join(self.cache_dir, "sync")
        self.pkg_dir = os.path.join(self.cache_dir, "pkg")
        self.log = log or (lambda m: None)
        self.db_max_age = db_max_age
        self.by_name: Dict[str, PackageInfo] = {}
        self.providers: Dict[str, List[PackageInfo]] = {}
        self.groups: Dict[str, List[PackageInfo]] = {}
        self.replacers: Dict[str, List[PackageInfo]] = {}
        os.makedirs(self.db_dir, exist_ok=True)
        os.makedirs(self.pkg_dir, exist_ok=True)

    # ------------------------------------------------------------------
    def refresh(self, force: bool = False) -> None:
        for spec in self.repos:
            path = os.path.join(self.db_dir, f"{spec.name}.db")
            fresh = (
                os.path.isfile(path)
                and not force
                and time.time() - os.path.getmtime(path) < self.db_max_age
            )
            if not fresh:
                last_err: Optional[Exception] = None
                for server in spec.servers:
                    url = _expand_server(server, spec.name, self.arch) + f"/{spec.name}.db"
                    try:
                        self.log(f"  sync {spec.name} ← {url}")
                        data = _http_get(url)
                        with open(path + ".part", "wb") as fh:
                            fh.write(data)
                        os.replace(path + ".part", path)
                        last_err = None
                        break
                    except (urllib.error.URLError, OSError) as exc:
                        last_err = exc
                        self.log(f"    mirror failed: {exc}")
                if last_err is not None:
                    if os.path.isfile(path):
                        self.log(f"  using stale {spec.name}.db (all mirrors failed)")
                    else:
                        raise RepoError(f"cannot download {spec.name}.db: {last_err}")
            with open(path, "rb") as fh:
                pkgs = parse_sync_db(fh.read(), spec.name)
            self.log(f"  {spec.name}: {len(pkgs)} packages")
            for p in pkgs:
                if p.name in self.by_name:
                    continue  # earlier repo wins
                self.by_name[p.name] = p
                for prov in p.provides:
                    self.providers.setdefault(dep_name(prov), []).append(p)
                for g in p.groups:
                    self.groups.setdefault(g, []).append(p)
                for r in p.replaces:
                    self.replacers.setdefault(dep_name(r), []).append(p)

    # ------------------------------------------------------------------
    def find_satisfier(
        self,
        dep: str,
        selected: Dict[str, PackageInfo],
        preferences: Dict[str, str],
    ) -> Optional[PackageInfo]:
        name = dep_name(dep)
        # Already satisfied by something we picked (by name or provides)?
        if name in selected:
            return selected[name]
        for p in selected.values():
            for prov in p.provides:
                if dep_name(prov) == name:
                    return p
        pref = preferences.get(name) or preferences.get(dep.strip())
        if pref and pref in self.by_name:
            return self.by_name[pref]
        if name in self.by_name:
            return self.by_name[name]
        cands = self.providers.get(name, [])
        if not cands:
            return None
        # Prefer a candidate whose name equals a preference value for any
        # dependency, else repo order (core before extra), then name.
        repo_rank = {r.name: i for i, r in enumerate(self.repos)}
        cands = sorted(cands, key=lambda p: (repo_rank.get(p.repo, 99), p.name))
        return cands[0]

    def resolve(
        self,
        targets: Iterable[str],
        preferences: Optional[Dict[str, str]] = None,
        ignore: Iterable[str] = (),
        no_deps_for: Iterable[str] = (),
    ) -> List[PackageInfo]:
        """
        Resolve *targets* (package names, virtual names or group names) to an
        ordered list of packages, dependencies before dependents.
        """
        prefs = dict(DEFAULT_PROVIDER_PREFERENCES)
        prefs.update(preferences or {})
        ignored = set(ignore)
        skip_deps = set(no_deps_for)
        selected: Dict[str, PackageInfo] = {}
        order: List[PackageInfo] = []
        missing: List[str] = []

        # Expand groups first.
        queue: List[Tuple[str, Optional[str]]] = []
        for t in targets:
            t = t.strip()
            if not t:
                continue
            if t not in self.by_name and t in self.groups and t not in self.providers:
                for p in sorted(self.groups[t], key=lambda x: x.name):
                    queue.append((p.name, None))
            else:
                queue.append((t, None))

        # Depth-first so that dependencies end up before dependents.
        visiting: Set[str] = set()

        def visit(dep: str, parent: Optional[str]) -> None:
            if dep_name(dep) in ignored:
                return
            pkg = self.find_satisfier(dep, selected, prefs)
            if pkg is None:
                hint = ""
                if parent is None:
                    import difflib

                    close = difflib.get_close_matches(dep_name(dep), list(self.by_name) + list(self.groups), n=3, cutoff=0.75)
                    if close:
                        hint = " — did you mean " + " / ".join(f"'{c}'" for c in close) + "?"
                missing.append(f"{dep} (required by {parent or 'manifest'}){hint}")
                return
            if pkg.name in selected or pkg.name in visiting:
                return
            visiting.add(pkg.name)
            if pkg.name not in skip_deps:
                for d in pkg.depends:
                    visit(d, pkg.name)
            visiting.discard(pkg.name)
            if pkg.name not in selected:
                selected[pkg.name] = pkg
                order.append(pkg)

        for dep, parent in queue:
            visit(dep, parent)

        if missing:
            raise RepoError(
                "these packages are not in the configured repositories:\n  " + "\n  ".join(missing)
                + "\n  (search https://archlinux.org/packages/ for the exact name; AUR packages must be"
                " built elsewhere and listed as local .pkg.tar.zst files)"
            )

        # Conflict sanity check (report, do not fail on self-provides).
        provided: Dict[str, List[Tuple[str, str]]] = {}
        for p in order:
            provided.setdefault(p.name, []).append((p.name, p.version))
            for prov in p.provides:
                n, op, ver = dep_constraint(prov)
                provided.setdefault(n, []).append((p.name, ver if op == "=" else p.version))
        for p in order:
            for c in p.conflicts:
                cn, op, ver = dep_constraint(c)
                for owner, ov in provided.get(cn, []):
                    if owner != p.name and satisfies(ov, op, ver):
                        self.log(f"  ⚠ {p.name} conflicts with {owner} ({c})")
        return order

    # ------------------------------------------------------------------
    def download(
        self,
        pkgs: Sequence[PackageInfo],
        workers: int = 6,
        progress: Optional[Callable[[int, int, PackageInfo], None]] = None,
    ) -> Dict[str, str]:
        """Download (or reuse cached) package files. Returns name → local path."""
        servers = {r.name: r.servers for r in self.repos}
        result: Dict[str, str] = {}
        lock = threading.Lock()
        done = [0]

        def verify(path: str, pkg: PackageInfo) -> bool:
            if not os.path.isfile(path):
                return False
            if pkg.csize and os.path.getsize(path) != pkg.csize:
                return False
            if not pkg.sha256:
                return True
            h = hashlib.sha256()
            with open(path, "rb") as fh:
                for chunk in iter(lambda: fh.read(1 << 20), b""):
                    h.update(chunk)
            return h.hexdigest() == pkg.sha256

        def fetch(pkg: PackageInfo) -> Tuple[str, str]:
            dest = os.path.join(self.pkg_dir, local_filename(pkg.filename))
            if not verify(dest, pkg):
                last: Optional[Exception] = None
                for attempt in range(3):
                    for server in servers.get(pkg.repo, []):
                        url = _expand_server(server, pkg.repo, self.arch) + "/" + urllib.parse.quote(pkg.filename, safe=":+@~")
                        try:
                            _http_download(url, dest)
                            if verify(dest, pkg):
                                last = None
                                break
                            last = RepoError(f"checksum mismatch for {pkg.filename} from {url}")
                        except (urllib.error.URLError, OSError) as exc:
                            last = exc
                    if last is None:
                        break
                    time.sleep(1 + attempt)
                if last is not None:
                    raise RepoError(f"failed to download {pkg.filename}: {last}")
            with lock:
                done[0] += 1
                if progress:
                    progress(done[0], len(pkgs), pkg)
            return pkg.name, dest

        with ThreadPoolExecutor(max_workers=max(1, workers)) as ex:
            futs = [ex.submit(fetch, p) for p in pkgs]
            for f in as_completed(futs):
                name, path = f.result()
                result[name] = path
        return result
