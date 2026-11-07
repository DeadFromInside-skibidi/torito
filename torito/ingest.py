"""
torito.ingest — Package Archive & Overlay Ingestion
======================================================
Extracts ``.pkg.tar.zst``, ``.deb``, and ``.apk`` package archives
directly into the POSIX VFS without touching NTFS.  Also handles
directory overlays from the host filesystem.
"""

from __future__ import annotations

import io
import os
import struct
import tarfile
from pathlib import PurePosixPath
from typing import Callable, List, Optional, Tuple

from .vfs import PosixVfs, VfsNodeType, _is_text_payload, sanitise_crlf


def _detect_format(path: str) -> str:
    """Auto-detect the package format from the file extension or magic bytes."""
    lower = path.lower()
    if lower.endswith(".pkg.tar.zst") or lower.endswith(".pkg.tar.xz"):
        return "pacman"
    if lower.endswith(".deb"):
        return "deb"
    if lower.endswith(".apk"):
        return "apk"
    if lower.endswith(".tar.zst") or lower.endswith(".tar.xz") or lower.endswith(".tar.gz"):
        return "tar"
    # Probe magic bytes
    try:
        with open(path, "rb") as fh:
            magic = fh.read(8)
        if magic[:7] == b"!<arch>\n":
            return "deb"
        if magic[:4] == b"\x28\xb5\x2f\xfd":
            return "pacman"  # zstd-compressed tar
    except OSError:
        pass
    return "tar"


def _open_tar_zstd(path: str) -> tarfile.TarFile:
    """Open a zstd-compressed tar archive using the zstandard library."""
    import zstandard as zstd

    with open(path, "rb") as fh:
        raw = fh.read()
    dctx = zstd.ZstdDecompressor()
    decompressed = dctx.decompress(raw, max_output_size=2 * 1024 * 1024 * 1024)
    return tarfile.open(fileobj=io.BytesIO(decompressed), mode="r:")


def _open_tar_auto(path: str) -> tarfile.TarFile:
    """Open a tar archive with automatic decompression detection."""
    lower = path.lower()
    if lower.endswith(".zst"):
        return _open_tar_zstd(path)
    # Let tarfile handle gz, xz, bz2
    return tarfile.open(path, mode="r:*")


def _ingest_tar_into_vfs(
    tf: tarfile.TarFile,
    vfs: PosixVfs,
    prefix: str = "/",
    uid_override: Optional[int] = None,
    gid_override: Optional[int] = None,
    progress: Optional[Callable[[str], None]] = None,
) -> int:
    """
    Stream every entry from a tar archive into the VFS.

    Returns the number of nodes ingested.
    """
    count = 0
    for member in tf:
        # Normalise the path
        name = member.name.lstrip("./")
        if not name:
            continue
        vfs_path = prefix.rstrip("/") + "/" + name

        uid = uid_override if uid_override is not None else member.uid
        gid = gid_override if gid_override is not None else member.gid
        mode = member.mode & 0o7777 if member.mode else 0o644
        mtime = int(member.mtime) if member.mtime else vfs._epoch

        if member.isdir():
            vfs.mkdir(vfs_path, mode=mode, uid=uid, gid=gid)
            node = vfs.get(vfs_path)
            if node:
                node.mtime = mtime
        elif member.isfile() or member.type == tarfile.REGTYPE:
            reader = tf.extractfile(member)
            data = reader.read() if reader else b""
            # CRLF sanitisation for text files
            basename = os.path.basename(name)
            if _is_text_payload(basename, data):
                data = sanitise_crlf(data)
            vfs.add_file(vfs_path, data, mode=mode, uid=uid, gid=gid, mtime=mtime)
        elif member.issym():
            vfs.add_symlink(vfs_path, member.linkname, uid=uid, gid=gid, mtime=mtime)
        elif member.islnk():
            # Hard links: copy the data from the link target
            link_target = prefix.rstrip("/") + "/" + member.linkname.lstrip("./")
            target_node = vfs.get(link_target)
            if target_node and target_node.node_type == VfsNodeType.REGULAR_FILE:
                vfs.add_file(vfs_path, target_node.data, mode=mode, uid=uid, gid=gid, mtime=mtime)
            else:
                # Fallback: create an empty file
                vfs.add_file(vfs_path, b"", mode=mode, uid=uid, gid=gid, mtime=mtime)
        elif member.ischr():
            vfs.add_char_device(
                vfs_path,
                major=os.major(member.devmajor) if hasattr(os, "major") else member.devmajor,
                minor=os.minor(member.devminor) if hasattr(os, "minor") else member.devminor,
                mode=mode,
                uid=uid,
                gid=gid,
            )
        elif member.isblk():
            vfs.add_block_device(
                vfs_path,
                major=member.devmajor,
                minor=member.devminor,
                mode=mode,
                uid=uid,
                gid=gid,
            )

        count += 1
        if progress:
            progress(vfs_path)

    return count


def ingest_pacman_package(
    vfs: PosixVfs,
    pkg_path: str,
    progress: Optional[Callable[[str], None]] = None,
) -> int:
    """
    Ingest a Pacman ``.pkg.tar.zst`` or ``.pkg.tar.xz`` package into the VFS.

    Pacman packages are plain tar archives rooted at ``/``, so entries
    are mapped directly.  The ``.PKGINFO``, ``.BUILDINFO``, and ``.MTREE``
    metadata files are stored under ``/var/lib/pacman/local/`` in the VFS.
    """
    tf = _open_tar_auto(pkg_path)
    meta_entries: List[Tuple[str, bytes]] = []
    count = 0

    # Extract package name from .PKGINFO if present
    pkg_name = os.path.basename(pkg_path).rsplit("-", 2)[0]

    for member in tf:
        name = member.name.lstrip("./")
        if not name:
            continue

        # Pacman metadata files start with '.'
        if name.startswith("."):
            reader = tf.extractfile(member)
            if reader:
                data = reader.read()
                meta_entries.append((name, data))
                if name == ".PKGINFO":
                    for line in data.decode("utf-8", errors="replace").splitlines():
                        if line.startswith("pkgname"):
                            pkg_name = line.split("=", 1)[1].strip()
                            break
            continue

        uid = member.uid
        gid = member.gid
        mode = member.mode & 0o7777 if member.mode else 0o644
        mtime = int(member.mtime) if member.mtime else vfs._epoch
        vfs_path = "/" + name

        if member.isdir():
            vfs.mkdir(vfs_path, mode=mode, uid=uid, gid=gid)
            node = vfs.get(vfs_path)
            if node:
                node.mtime = mtime
        elif member.isfile():
            reader = tf.extractfile(member)
            data = reader.read() if reader else b""
            basename = os.path.basename(name)
            if _is_text_payload(basename, data):
                data = sanitise_crlf(data)
            vfs.add_file(vfs_path, data, mode=mode, uid=uid, gid=gid, mtime=mtime)
        elif member.issym():
            vfs.add_symlink(vfs_path, member.linkname, uid=uid, gid=gid, mtime=mtime)
        elif member.islnk():
            link_target = "/" + member.linkname.lstrip("./")
            target_node = vfs.get(link_target)
            if target_node and target_node.node_type == VfsNodeType.REGULAR_FILE:
                vfs.add_file(vfs_path, target_node.data, mode=mode, uid=uid, gid=gid, mtime=mtime)
            else:
                vfs.add_file(vfs_path, b"", mode=mode, uid=uid, gid=gid, mtime=mtime)
        elif member.ischr():
            vfs.add_char_device(vfs_path, member.devmajor, member.devminor, mode=mode, uid=uid, gid=gid)
        elif member.isblk():
            vfs.add_block_device(vfs_path, member.devmajor, member.devminor, mode=mode, uid=uid, gid=gid)

        count += 1
        if progress:
            progress(vfs_path)

    tf.close()

    # Store metadata in VFS
    pkg_db_dir = f"/var/lib/pacman/local/{pkg_name}"
    vfs.mkdir(pkg_db_dir, mode=0o755)
    for meta_name, meta_data in meta_entries:
        clean_name = meta_name.lstrip(".")
        vfs.add_file(f"{pkg_db_dir}/{clean_name}", meta_data, mode=0o644)

    return count


def _extract_ar_member(data: bytes, member_name: str) -> Optional[bytes]:
    """
    Extract a named member from an ``ar`` archive (the container format
    used by ``.deb`` packages).
    """
    if data[:8] != b"!<arch>\n":
        raise ValueError("Not a valid ar archive")

    offset = 8
    while offset < len(data):
        if offset + 60 > len(data):
            break
        header = data[offset : offset + 60]
        name = header[0:16].decode("ascii").strip().rstrip("/")
        size_str = header[48:58].decode("ascii").strip()
        if not size_str:
            break
        size = int(size_str)
        content_start = offset + 60
        content_end = content_start + size

        if name == member_name or name.startswith(member_name):
            return data[content_start:content_end]

        offset = content_end
        if offset % 2:
            offset += 1  # ar entries are 2-byte aligned

    return None


def ingest_deb_package(
    vfs: PosixVfs,
    deb_path: str,
    progress: Optional[Callable[[str], None]] = None,
) -> int:
    """
    Ingest a Debian ``.deb`` package into the VFS.

    A ``.deb`` is an ``ar`` archive containing:
    - ``debian-binary``: version string
    - ``control.tar.*``: package metadata
    - ``data.tar.*``: the actual files rooted at ``/``
    """
    with open(deb_path, "rb") as fh:
        ar_data = fh.read()

    if ar_data[:8] != b"!<arch>\n":
        raise ValueError(f"Not a valid .deb file: {deb_path}")

    # Parse ar members
    members: List[Tuple[str, bytes]] = []
    offset = 8
    while offset < len(ar_data):
        if offset + 60 > len(ar_data):
            break
        header = ar_data[offset : offset + 60]
        name = header[0:16].decode("ascii").strip().rstrip("/")
        size_str = header[48:58].decode("ascii").strip()
        if not size_str:
            break
        size = int(size_str)
        content_start = offset + 60
        content_end = content_start + size
        members.append((name, ar_data[content_start:content_end]))
        offset = content_end
        if offset % 2:
            offset += 1

    count = 0
    pkg_name = os.path.basename(deb_path).split("_")[0]

    for member_name, member_data in members:
        if member_name.startswith("data.tar"):
            # Decompress data archive
            if member_name.endswith(".zst"):
                import zstandard as zstd

                dctx = zstd.ZstdDecompressor()
                decompressed = dctx.decompress(member_data, max_output_size=2 * 1024 * 1024 * 1024)
                tf = tarfile.open(fileobj=io.BytesIO(decompressed), mode="r:")
            else:
                tf = tarfile.open(fileobj=io.BytesIO(member_data), mode="r:*")

            count += _ingest_tar_into_vfs(tf, vfs, prefix="/", progress=progress)
            tf.close()

        elif member_name.startswith("control.tar"):
            # Store control metadata
            if member_name.endswith(".zst"):
                import zstandard as zstd

                dctx = zstd.ZstdDecompressor()
                decompressed = dctx.decompress(member_data, max_output_size=64 * 1024 * 1024)
                tf = tarfile.open(fileobj=io.BytesIO(decompressed), mode="r:")
            else:
                tf = tarfile.open(fileobj=io.BytesIO(member_data), mode="r:*")

            dpkg_dir = f"/var/lib/dpkg/info/{pkg_name}"
            vfs.mkdir("/var/lib/dpkg/info", mode=0o755)

            for cm in tf:
                cm_name = cm.name.lstrip("./")
                if not cm_name:
                    continue
                reader = tf.extractfile(cm)
                if reader:
                    cm_data = reader.read()
                    vfs.add_file(
                        f"/var/lib/dpkg/info/{pkg_name}.{cm_name}",
                        cm_data,
                        mode=cm.mode & 0o7777 if cm.mode else 0o644,
                    )
            tf.close()

    return count


def ingest_apk_package(
    vfs: PosixVfs,
    apk_path: str,
    progress: Optional[Callable[[str], None]] = None,
) -> int:
    """
    Ingest an Alpine ``.apk`` package into the VFS.

    Alpine ``.apk`` packages are gzip-compressed tar archives with
    a special structure: signature data, control data, and filesystem
    data concatenated.
    """
    # APK files are concatenated gzip streams; we read them all
    with open(apk_path, "rb") as fh:
        raw = fh.read()

    count = 0
    pkg_name = os.path.basename(apk_path).rsplit("-", 2)[0]

    # Split concatenated gzip streams
    streams: List[bytes] = []
    pos = 0
    while pos < len(raw):
        if raw[pos : pos + 2] != b"\x1f\x8b":
            break
        # Find the end of this gzip stream by decompressing it
        import gzip

        try:
            stream_buf = io.BytesIO(raw[pos:])
            with gzip.GzipFile(fileobj=stream_buf) as gz:
                decompressed = gz.read()
            streams.append(decompressed)
            consumed = stream_buf.tell()
            if consumed == 0:
                break
            pos += consumed
        except Exception:
            # Fall back: treat entire remainder as one stream
            try:
                stream_buf = io.BytesIO(raw[pos:])
                with gzip.GzipFile(fileobj=stream_buf) as gz:
                    decompressed = gz.read()
                streams.append(decompressed)
            except Exception:
                pass
            break

    for stream_data in streams:
        try:
            tf = tarfile.open(fileobj=io.BytesIO(stream_data), mode="r:")
        except tarfile.TarError:
            continue

        has_filesystem_content = False
        for member in tf.getmembers():
            name = member.name.lstrip("./")
            if name and not name.startswith(".") and member.isfile():
                has_filesystem_content = True
                break
        tf.close()

        tf = tarfile.open(fileobj=io.BytesIO(stream_data), mode="r:")
        if has_filesystem_content:
            count += _ingest_tar_into_vfs(tf, vfs, prefix="/", progress=progress)
        else:
            # Control/signature data → store as APK metadata
            apk_db_dir = f"/lib/apk/db/{pkg_name}"
            vfs.mkdir("/lib/apk/db", mode=0o755)
            vfs.mkdir(apk_db_dir, mode=0o755)
            for member in tf:
                name = member.name.lstrip("./")
                if not name:
                    continue
                reader = tf.extractfile(member)
                if reader:
                    data = reader.read()
                    clean = name.lstrip(".")
                    vfs.add_file(
                        f"{apk_db_dir}/{clean}",
                        data,
                        mode=member.mode & 0o7777 if member.mode else 0o644,
                    )
        tf.close()

    return count


def ingest_package(
    vfs: PosixVfs,
    pkg_path: str,
    fmt: str = "auto",
    progress: Optional[Callable[[str], None]] = None,
) -> int:
    """
    Ingest a package of any supported format into the VFS.

    Parameters
    ----------
    vfs : PosixVfs
        Target virtual filesystem.
    pkg_path : str
        Path to the package archive on the host filesystem.
    fmt : str
        Package format (``auto``, ``pacman``, ``deb``, ``apk``, ``tar``).
    progress : callable, optional
        Progress callback receiving the current VFS path being ingested.

    Returns
    -------
    int
        Number of filesystem nodes ingested.
    """
    if fmt == "auto":
        fmt = _detect_format(pkg_path)

    if fmt == "pacman":
        return ingest_pacman_package(vfs, pkg_path, progress=progress)
    elif fmt == "deb":
        return ingest_deb_package(vfs, pkg_path, progress=progress)
    elif fmt == "apk":
        return ingest_apk_package(vfs, pkg_path, progress=progress)
    elif fmt == "tar":
        tf = _open_tar_auto(pkg_path)
        count = _ingest_tar_into_vfs(tf, vfs, prefix="/", progress=progress)
        tf.close()
        return count
    else:
        raise ValueError(f"Unsupported package format: {fmt!r}")


def ingest_overlay_directory(
    vfs: PosixVfs,
    host_dir: str,
    progress: Optional[Callable[[str], None]] = None,
) -> int:
    """
    Ingest a host directory tree as a rootfs overlay (files override
    existing VFS entries).

    The directory structure maps directly to the Linux root: a file at
    ``<host_dir>/etc/motd`` becomes ``/etc/motd`` in the VFS.
    """
    return vfs.ingest_host_directory(host_dir, vfs_prefix="/", progress=progress)

