"""
torito.ingest — Package Archive & Overlay Ingestion
===================================================
Streams ``.pkg.tar.{zst,xz,gz}`` (pacman), ``.deb`` and ``.apk`` packages
directly into the POSIX VFS — no extraction to NTFS, no permission loss,
no case-folding collisions.  Large payloads are spooled into the VFS blob
store so memory stays flat no matter how big the root filesystem gets.

For pacman packages a faithful local database
(``/var/lib/pacman/local/<pkg>-<ver>/{desc,files,mtree}``) is written so the
booted system's ``pacman -Q`` knows exactly what is installed.
"""

from __future__ import annotations

import gzip
import hashlib
import io
import lzma
import os
import tarfile
from dataclasses import dataclass, field
from typing import Callable, Dict, IO, Iterator, List, Optional, Tuple

from .vfs import PosixVfs, VfsError, VfsNodeType

PACMAN_META = {".PKGINFO", ".BUILDINFO", ".MTREE", ".INSTALL", ".CHANGELOG"}


@dataclass
class PackageRecord:
    """What we learned while ingesting one package."""

    name: str
    version: str = ""
    path: str = ""
    pkginfo: Dict[str, List[str]] = field(default_factory=dict)
    files: List[str] = field(default_factory=list)
    install_script: bytes = b""
    mtree: bytes = b""
    nodes: int = 0
    reason_explicit: bool = True


def _detect_format(path: str) -> str:
    lower = path.lower()
    if ".pkg.tar" in lower:
        return "pacman"
    if lower.endswith(".deb"):
        return "deb"
    if lower.endswith(".apk"):
        return "apk"
    if lower.endswith((".tar", ".tar.zst", ".tar.xz", ".tar.gz", ".tgz")):
        return "tar"
    try:
        with open(path, "rb") as fh:
            magic = fh.read(8)
        if magic[:7] == b"!<arch>":
            return "deb"
        if magic[:4] == b"\x28\xb5\x2f\xfd":
            return "pacman"
    except OSError:
        pass
    return "tar"


def _decompressing_reader(fh: IO[bytes]) -> IO[bytes]:
    """Wrap a binary stream in the right streaming decompressor (by magic)."""
    head = fh.read(6)
    fh.seek(0)
    if head[:4] == b"\x28\xb5\x2f\xfd":
        import zstandard

        return zstandard.ZstdDecompressor(max_window_size=1 << 31).stream_reader(fh, read_across_frames=True)
    if head[:6] == b"\xfd7zXZ\x00":
        return lzma.LZMAFile(fh)  # type: ignore[return-value]
    if head[:2] == b"\x1f\x8b":
        return gzip.GzipFile(fileobj=fh)  # type: ignore[return-value]
    if head[:3] == b"BZh":
        import bz2

        return bz2.BZ2File(fh)  # type: ignore[return-value]
    return fh


def _open_stream(path: str) -> Tuple[IO[bytes], tarfile.TarFile]:
    raw = open(path, "rb")
    reader = _decompressing_reader(raw)
    return raw, tarfile.open(fileobj=reader, mode="r|")


def _open_bytes_stream(data: bytes) -> tarfile.TarFile:
    return tarfile.open(fileobj=_decompressing_reader(io.BytesIO(data)), mode="r|")


def _xattrs_of(member: tarfile.TarInfo) -> Optional[Dict[str, bytes]]:
    xa: Dict[str, bytes] = {}
    for k, v in (member.pax_headers or {}).items():
        if k.startswith("SCHILY.xattr."):
            name = k[len("SCHILY.xattr."):]
            if name.startswith("security.") or name.startswith("user.") or name.startswith("trusted."):
                xa[name] = v.encode("utf-8", "surrogateescape") if isinstance(v, str) else v
    return xa or None


def _stream_tar_into_vfs(
    tf: tarfile.TarFile,
    vfs: PosixVfs,
    prefix: str = "/",
    keep_meta: Optional[Dict[str, bytes]] = None,
    files: Optional[List[str]] = None,
    progress: Optional[Callable[[str], None]] = None,
) -> int:
    """
    Copy every entry of a (streaming) tar archive into the VFS.
    Top-level dot-files listed in ``PACMAN_META`` go to *keep_meta*.
    """
    count = 0
    pfx = prefix.rstrip("/")
    for member in tf:
        name = member.name
        while name.startswith("./"):
            name = name[2:]
        name = name.lstrip("/").rstrip("/")
        if not name or name == ".":
            continue
        if keep_meta is not None and "/" not in name and name in PACMAN_META:
            fh = tf.extractfile(member)
            keep_meta[name] = fh.read() if fh else b""
            continue

        vfs_path = pfx + "/" + name
        mode = member.mode & 0o7777
        mtime = int(member.mtime) if member.mtime else vfs._epoch
        uname, gname = member.uname or "", member.gname or ""
        uid, gid = member.uid, member.gid
        try:
            if member.isdir():
                vfs.mkdir(vfs_path, mode=mode or 0o755, uid=uid, gid=gid, mtime=mtime, uname=uname, gname=gname)
                if files is not None:
                    files.append(name + "/")
            elif member.isreg():
                fh = tf.extractfile(member)
                if vfs.blob_store is not None and member.size >= vfs.inline_limit and fh is not None:
                    blob = vfs.blob_store.put_stream(fh)
                    vfs.add_file(vfs_path, b"", mode=mode, uid=uid, gid=gid, mtime=mtime, blob=blob, uname=uname, gname=gname)
                else:
                    data = fh.read() if fh else b""
                    vfs.add_file(vfs_path, data, mode=mode, uid=uid, gid=gid, mtime=mtime, uname=uname, gname=gname)
                xa = _xattrs_of(member)
                if xa:
                    node = vfs.get(vfs.resolve(vfs_path))
                    if node is not None:
                        node.xattrs = xa
                if files is not None:
                    files.append(name)
            elif member.issym():
                vfs.add_symlink(vfs_path, member.linkname, uid=uid, gid=gid, mtime=mtime, uname=uname, gname=gname)
                if files is not None:
                    files.append(name)
            elif member.islnk():
                target = member.linkname
                while target.startswith("./"):
                    target = target[2:]
                try:
                    vfs.add_hardlink(vfs_path, pfx + "/" + target.lstrip("/"), mtime=mtime)
                except VfsError:
                    vfs.add_file(vfs_path, b"", mode=mode, uid=uid, gid=gid, mtime=mtime, uname=uname, gname=gname)
                if files is not None:
                    files.append(name)
            elif member.ischr():
                vfs.add_char_device(vfs_path, member.devmajor, member.devminor, mode=mode, uid=uid, gid=gid)
            elif member.isblk():
                vfs.add_block_device(vfs_path, member.devmajor, member.devminor, mode=mode, uid=uid, gid=gid)
            elif member.isfifo():
                vfs.add_fifo(vfs_path, mode=mode, uid=uid, gid=gid)
            else:
                continue
        except VfsError:
            continue
        count += 1
        if progress:
            progress(vfs_path)
    return count


def parse_pkginfo(raw: bytes) -> Dict[str, List[str]]:
    info: Dict[str, List[str]] = {}
    for line in raw.decode("utf-8", "replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or " = " not in line:
            continue
        k, v = line.split(" = ", 1)
        info.setdefault(k.strip(), []).append(v.strip())
    return info


# ---------------------------------------------------------------------------
# Package formats
# ---------------------------------------------------------------------------


def ingest_pacman_package(
    vfs: PosixVfs,
    pkg_path: str,
    progress: Optional[Callable[[str], None]] = None,
    record: Optional[PackageRecord] = None,
) -> int:
    """Stream a pacman package into the VFS. Returns the node count."""
    meta: Dict[str, bytes] = {}
    files: List[str] = []
    raw, tf = _open_stream(pkg_path)
    try:
        count = _stream_tar_into_vfs(tf, vfs, "/", keep_meta=meta, files=files, progress=progress)
    finally:
        tf.close()
        raw.close()
    info = parse_pkginfo(meta.get(".PKGINFO", b""))
    rec = record if record is not None else PackageRecord(name="")
    rec.name = (info.get("pkgname") or [os.path.basename(pkg_path).rsplit("-", 3)[0]])[0]
    rec.version = (info.get("pkgver") or [""])[0]
    rec.path = pkg_path
    rec.pkginfo = info
    rec.files = files
    rec.install_script = meta.get(".INSTALL", b"")
    rec.mtree = meta.get(".MTREE", b"")
    rec.nodes = count
    return count


def _ar_members(data: bytes) -> Iterator[Tuple[str, bytes]]:
    if data[:8] != b"!<arch>\n":
        raise ValueError("Not a valid ar archive")
    offset = 8
    while offset + 60 <= len(data):
        header = data[offset: offset + 60]
        name = header[0:16].decode("ascii", "replace").strip().rstrip("/")
        size_str = header[48:58].decode("ascii", "replace").strip()
        if not size_str:
            break
        size = int(size_str)
        start = offset + 60
        yield name, data[start: start + size]
        offset = start + size + (size & 1)


def _extract_ar_member(data: bytes, member_name: str) -> Optional[bytes]:
    for name, payload in _ar_members(data):
        if name == member_name or name.startswith(member_name):
            return payload
    return None


def ingest_deb_package(vfs: PosixVfs, deb_path: str, progress: Optional[Callable[[str], None]] = None) -> int:
    """Ingest a Debian ``.deb`` (ar container with control/data tarballs)."""
    with open(deb_path, "rb") as fh:
        ar_data = fh.read()
    if ar_data[:8] != b"!<arch>\n":
        raise ValueError(f"Not a valid .deb file: {deb_path}")
    pkg_name = os.path.basename(deb_path).split("_")[0]
    count = 0
    for name, payload in _ar_members(ar_data):
        if name.startswith("data.tar"):
            tf = _open_bytes_stream(payload)
            count += _stream_tar_into_vfs(tf, vfs, "/", progress=progress)
            tf.close()
        elif name.startswith("control.tar"):
            tf = _open_bytes_stream(payload)
            vfs.mkdir("/var/lib/dpkg/info")
            for cm in tf:
                cname = cm.name.lstrip("./")
                if not cname or not cm.isreg():
                    continue
                fh2 = tf.extractfile(cm)
                vfs.add_file(f"/var/lib/dpkg/info/{pkg_name}.{cname}", fh2.read() if fh2 else b"", mode=cm.mode & 0o7777 or 0o644)
            tf.close()
    return count


def ingest_apk_package(vfs: PosixVfs, apk_path: str, progress: Optional[Callable[[str], None]] = None) -> int:
    """Ingest an Alpine ``.apk`` (concatenated gzip streams)."""
    import zlib

    with open(apk_path, "rb") as fh:
        raw = fh.read()
    streams: List[bytes] = []
    pos = 0
    while pos < len(raw) and raw[pos: pos + 2] == b"\x1f\x8b":
        d = zlib.decompressobj(16 + zlib.MAX_WBITS)
        out = d.decompress(raw[pos:])
        streams.append(out)
        consumed = len(raw) - pos - len(d.unused_data)
        if consumed <= 0:
            break
        pos += consumed
    pkg_name = os.path.basename(apk_path).rsplit("-", 2)[0]
    count = 0
    for data in streams:
        try:
            tf = tarfile.open(fileobj=io.BytesIO(data), mode="r:")
        except tarfile.TarError:
            continue
        members = tf.getmembers()
        fs_content = any(m.name.lstrip("./") and not m.name.lstrip("./").startswith(".") for m in members)
        tf.close()
        tf = tarfile.open(fileobj=io.BytesIO(data), mode="r|")
        if fs_content:
            count += _stream_tar_into_vfs(tf, vfs, "/", progress=progress)
        else:
            db_dir = f"/lib/apk/db/{pkg_name}"
            vfs.mkdir(db_dir)
            for m in tf:
                n = m.name.lstrip("./")
                if n and m.isreg():
                    fh2 = tf.extractfile(m)
                    vfs.add_file(f"{db_dir}/{n.lstrip('.')}", fh2.read() if fh2 else b"")
        tf.close()
    return count


def ingest_package(
    vfs: PosixVfs,
    pkg_path: str,
    fmt: str = "auto",
    progress: Optional[Callable[[str], None]] = None,
    record: Optional[PackageRecord] = None,
) -> int:
    """Ingest a package of any supported format into the VFS."""
    if fmt == "auto":
        fmt = _detect_format(pkg_path)
    if fmt == "pacman":
        return ingest_pacman_package(vfs, pkg_path, progress=progress, record=record)
    if fmt == "deb":
        return ingest_deb_package(vfs, pkg_path, progress=progress)
    if fmt == "apk":
        return ingest_apk_package(vfs, pkg_path, progress=progress)
    if fmt == "tar":
        raw, tf = _open_stream(pkg_path)
        try:
            return _stream_tar_into_vfs(tf, vfs, "/", progress=progress)
        finally:
            tf.close()
            raw.close()
    raise ValueError(f"Unsupported package format: {fmt!r}")


def ingest_overlay_directory(vfs: PosixVfs, host_dir: str, progress: Optional[Callable[[str], None]] = None) -> int:
    """Overlay a host directory onto ``/`` (files override existing entries)."""
    return vfs.ingest_host_directory(host_dir, vfs_prefix="/", progress=progress)


# ---------------------------------------------------------------------------
# pacman local database
# ---------------------------------------------------------------------------


def _desc_section(key: str, values: List[str]) -> str:
    vals = [v for v in values if v != ""]
    if not vals:
        return ""
    return f"%{key}%\n" + "\n".join(vals) + "\n\n"


def write_pacman_local_db(vfs: PosixVfs, records: List[PackageRecord], install_date: int) -> None:
    """Write ``/var/lib/pacman/local`` so pacman in the image sees installed packages."""
    root = "/var/lib/pacman/local"
    vfs.mkdir("/var/lib/pacman")
    vfs.mkdir(root)
    vfs.add_file(root + "/ALPM_DB_VERSION", b"9\n")
    for rec in records:
        if not rec.pkginfo:
            continue
        info = rec.pkginfo

        def g(k: str) -> List[str]:
            return info.get(k, [])

        d = ""
        d += _desc_section("NAME", g("pkgname"))
        d += _desc_section("VERSION", g("pkgver"))
        d += _desc_section("BASE", g("pkgbase"))
        d += _desc_section("DESC", g("pkgdesc"))
        d += _desc_section("URL", g("url"))
        d += _desc_section("ARCH", g("arch"))
        d += _desc_section("BUILDDATE", g("builddate"))
        d += _desc_section("INSTALLDATE", [str(install_date)])
        d += _desc_section("PACKAGER", g("packager"))
        d += _desc_section("SIZE", g("size"))
        if not rec.reason_explicit:
            d += _desc_section("REASON", ["1"])
        d += _desc_section("GROUPS", g("group"))
        d += _desc_section("LICENSE", g("license"))
        d += _desc_section("VALIDATION", ["pgp"])
        d += _desc_section("REPLACES", g("replaces"))
        d += _desc_section("DEPENDS", g("depend"))
        d += _desc_section("OPTDEPENDS", g("optdepend"))
        d += _desc_section("CONFLICTS", g("conflict"))
        d += _desc_section("PROVIDES", g("provides"))
        name = rec.name
        ver = rec.version
        pdir = f"{root}/{name}-{ver}"
        vfs.mkdir(pdir)
        vfs.add_file(pdir + "/desc", d.encode("utf-8"))
        files_txt = "%FILES%\n" + "\n".join(sorted(rec.files)) + "\n\n"
        backups = g("backup")
        if backups:
            lines = []
            for b in backups:
                content = vfs.read_file("/" + b)
                md5 = hashlib.md5(content).hexdigest() if content is not None else ""
                lines.append(f"{b}\t{md5}")
            files_txt += "%BACKUP%\n" + "\n".join(lines) + "\n\n"
        vfs.add_file(pdir + "/files", files_txt.encode("utf-8"))
        if rec.mtree:
            vfs.add_file(pdir + "/mtree", rec.mtree)
        if rec.install_script:
            vfs.add_file(pdir + "/install", rec.install_script)
