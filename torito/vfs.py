"""
torito.vfs — Pure In-Memory POSIX Virtual Filesystem
=====================================================
Maintains a sorted tree of POSIX inodes (UID/GID, octal modes, symlinks,
device nodes) entirely in Python memory, independent of any host filesystem.
Windows NTFS metadata is never consulted; all Linux semantics live here.
"""

from __future__ import annotations

import os
import stat
import time
from dataclasses import dataclass, field
from enum import IntEnum, auto
from pathlib import PurePosixPath
from typing import (
    BinaryIO,
    Callable,
    Dict,
    Iterator,
    List,
    Optional,
    Set,
    Tuple,
    Union,
)


class VfsNodeType(IntEnum):
    """Enumeration of POSIX inode types stored in the virtual filesystem."""

    REGULAR_FILE = 1
    DIRECTORY = 2
    SYMLINK = 3
    CHAR_DEVICE = 4
    BLOCK_DEVICE = 5
    FIFO = 6
    SOCKET = 7


# Map VfsNodeType to the POSIX stat mode bits used in CPIO / SquashFS headers
POSIX_TYPE_BITS: Dict[VfsNodeType, int] = {
    VfsNodeType.REGULAR_FILE: 0o100000,
    VfsNodeType.DIRECTORY: 0o040000,
    VfsNodeType.SYMLINK: 0o120000,
    VfsNodeType.CHAR_DEVICE: 0o020000,
    VfsNodeType.BLOCK_DEVICE: 0o060000,
    VfsNodeType.FIFO: 0o010000,
    VfsNodeType.SOCKET: 0o140000,
}


@dataclass
class VfsNode:
    """
    A single inode in the POSIX virtual filesystem.

    Stores the node type, ownership, permission bits, content payload
    (file data, symlink target, or device numbers), and metadata timestamps.
    """

    node_type: VfsNodeType
    uid: int = 0
    gid: int = 0
    mode: int = 0o644
    data: bytes = b""
    link_target: str = ""
    dev_major: int = 0
    dev_minor: int = 0
    mtime: int = 0
    nlink: int = 1
    ino: int = 0

    @property
    def size(self) -> int:
        """Return the logical size of this node for archive headers."""
        if self.node_type == VfsNodeType.REGULAR_FILE:
            return len(self.data)
        if self.node_type == VfsNodeType.SYMLINK:
            return len(self.link_target.encode("utf-8"))
        return 0

    @property
    def full_mode(self) -> int:
        """Return the complete POSIX mode word (type bits | permission bits)."""
        return POSIX_TYPE_BITS.get(self.node_type, 0) | (self.mode & 0o7777)

    @property
    def rdev(self) -> int:
        """Return the device number in Linux kernel format (major << 8 | minor)."""
        return (self.dev_major << 8) | (self.dev_minor & 0xFF)

    def is_executable(self) -> bool:
        """Check if any execute bit is set."""
        return bool(self.mode & 0o111)


# File extensions that are always treated as text for CRLF sanitisation
TEXT_EXTENSIONS: Set[str] = {
    "sh",
    "bash",
    "zsh",
    "fish",
    "conf",
    "cfg",
    "ini",
    "toml",
    "json",
    "yaml",
    "yml",
    "xml",
    "service",
    "timer",
    "socket",
    "mount",
    "target",
    "path",
    "py",
    "pl",
    "rb",
    "lua",
    "desktop",
    "rules",
    "txt",
    "md",
    "csv",
    "list",
    "repo",
    "fstab",
    "profile",
    "bashrc",
    "login",
    "logout",
    "env",
    "rc",
    "local",
    "cron",
    "sudoers",
    "hosts",
    "hostname",
    "resolv",
    "network",
    "interfaces",
    "sysctl",
    "modules",
    "grub",
    "loader",
    "entries",
}


def sanitise_crlf(raw: bytes) -> bytes:
    """
    Strip Windows ``\\r\\n`` (CRLF) sequences to Unix ``\\n`` (LF).

    Only removes ``\\r`` bytes that directly precede ``\\n`` — standalone
    ``\\r`` (classic Mac line endings) are preserved.
    """
    return raw.replace(b"\r\n", b"\n")


def _is_text_payload(filename: str, data: bytes) -> bool:
    """Heuristic: decide whether *data* read from *filename* is a text file."""
    # Check extension
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else filename.lower()
    if ext in TEXT_EXTENSIONS:
        return True
    # Shebang line
    if data[:2] == b"#!":
        return True
    # Quick binary probe: NUL bytes in the first 8 KB almost always mean binary
    probe = data[:8192]
    if b"\x00" in probe:
        return False
    # High-ASCII ratio heuristic (> 30 % non-ASCII ⇒ probably binary)
    if len(probe) > 0:
        high = sum(1 for b in probe if b > 127)
        if high / len(probe) > 0.30:
            return False
    return True


class PosixVfs:
    """
    An ordered, in-memory POSIX filesystem tree.

    Every path is stored as a ``/``-rooted POSIX string.  The backing
    dictionary is kept sorted so that archive serialisation is deterministic
    and reproducible across platforms.
    """

    def __init__(self, source_date_epoch: Optional[int] = None) -> None:
        self._tree: Dict[str, VfsNode] = {}
        self._epoch: int = source_date_epoch if source_date_epoch is not None else int(time.time())
        self._ino_counter: int = 1

    # ------------------------------------------------------------------
    # Inode allocation
    # ------------------------------------------------------------------

    def _next_ino(self) -> int:
        ino = self._ino_counter
        self._ino_counter += 1
        return ino

    # ------------------------------------------------------------------
    # Primitive insertion helpers
    # ------------------------------------------------------------------

    def _normalise(self, path: str) -> str:
        """Canonicalise a path to ``/absolute/posix/form`` with no trailing slash."""
        p = path.replace("\\", "/")
        if not p.startswith("/"):
            p = "/" + p
        parts = []
        for seg in p.split("/"):
            if seg == "" or seg == ".":
                continue
            if seg == "..":
                if parts:
                    parts.pop()
                continue
            parts.append(seg)
        return "/" + "/".join(parts) if parts else "/"

    def _ensure_parents(self, path: str) -> None:
        """Create all ancestor directories of *path* if they do not exist."""
        parts = path.strip("/").split("/")
        for i in range(1, len(parts)):
            ancestor = "/" + "/".join(parts[:i])
            if ancestor not in self._tree:
                self._tree[ancestor] = VfsNode(
                    node_type=VfsNodeType.DIRECTORY,
                    uid=0,
                    gid=0,
                    mode=0o755,
                    mtime=self._epoch,
                    ino=self._next_ino(),
                )

    def mkdir(self, path: str, mode: int = 0o755, uid: int = 0, gid: int = 0) -> None:
        """Create a directory node (and any missing ancestors)."""
        norm = self._normalise(path)
        self._ensure_parents(norm)
        self._tree[norm] = VfsNode(
            node_type=VfsNodeType.DIRECTORY,
            uid=uid,
            gid=gid,
            mode=mode,
            mtime=self._epoch,
            ino=self._next_ino(),
        )

    def add_file(
        self,
        path: str,
        data: bytes,
        mode: int = 0o644,
        uid: int = 0,
        gid: int = 0,
        mtime: Optional[int] = None,
    ) -> None:
        """Insert a regular file with the given byte content."""
        norm = self._normalise(path)
        self._ensure_parents(norm)
        self._tree[norm] = VfsNode(
            node_type=VfsNodeType.REGULAR_FILE,
            uid=uid,
            gid=gid,
            mode=mode,
            data=data,
            mtime=mtime if mtime is not None else self._epoch,
            ino=self._next_ino(),
        )

    def add_symlink(
        self,
        path: str,
        target: str,
        uid: int = 0,
        gid: int = 0,
        mtime: Optional[int] = None,
    ) -> None:
        """Insert a symbolic link pointing at *target*."""
        norm = self._normalise(path)
        self._ensure_parents(norm)
        self._tree[norm] = VfsNode(
            node_type=VfsNodeType.SYMLINK,
            uid=uid,
            gid=gid,
            mode=0o777,
            link_target=target,
            mtime=mtime if mtime is not None else self._epoch,
            ino=self._next_ino(),
        )

    def add_char_device(
        self,
        path: str,
        major: int,
        minor: int,
        mode: int = 0o666,
        uid: int = 0,
        gid: int = 0,
    ) -> None:
        """Insert a character device node (replaces ``mknod``)."""
        norm = self._normalise(path)
        self._ensure_parents(norm)
        self._tree[norm] = VfsNode(
            node_type=VfsNodeType.CHAR_DEVICE,
            uid=uid,
            gid=gid,
            mode=mode,
            dev_major=major,
            dev_minor=minor,
            mtime=self._epoch,
            ino=self._next_ino(),
        )

    def add_block_device(
        self,
        path: str,
        major: int,
        minor: int,
        mode: int = 0o660,
        uid: int = 0,
        gid: int = 0,
    ) -> None:
        """Insert a block device node."""
        norm = self._normalise(path)
        self._ensure_parents(norm)
        self._tree[norm] = VfsNode(
            node_type=VfsNodeType.BLOCK_DEVICE,
            uid=uid,
            gid=gid,
            mode=mode,
            dev_major=major,
            dev_minor=minor,
            mtime=self._epoch,
            ino=self._next_ino(),
        )

    # ------------------------------------------------------------------
    # Bulk ingestion from Windows host filesystem
    # ------------------------------------------------------------------

    def ingest_host_file(
        self,
        host_path: str,
        vfs_path: str,
        force_executable: bool = False,
    ) -> None:
        """
        Read a file from the Windows host and insert it into the VFS.

        Text files (detected by extension or shebang) have CRLF line endings
        automatically converted to LF.  ELF binaries and shebang scripts are
        marked executable (``0o755``).
        """
        with open(host_path, "rb") as fh:
            raw = fh.read()

        filename = os.path.basename(host_path)
        if _is_text_payload(filename, raw):
            raw = sanitise_crlf(raw)

        is_exec = force_executable or raw[:2] == b"#!" or raw[:4] == b"\x7fELF"
        mode = 0o755 if is_exec else 0o644

        self.add_file(vfs_path, raw, mode=mode)

    def ingest_host_directory(
        self,
        host_dir: str,
        vfs_prefix: str = "/",
        progress: Optional[Callable[[str], None]] = None,
    ) -> int:
        """
        Recursively ingest an entire Windows directory tree into the VFS.

        Returns the number of nodes ingested.
        """
        count = 0
        host_dir_path = os.path.normpath(host_dir)
        for dirpath, dirnames, filenames in os.walk(host_dir_path):
            rel = os.path.relpath(dirpath, host_dir_path).replace("\\", "/")
            if rel == ".":
                vfs_dir = self._normalise(vfs_prefix)
            else:
                vfs_dir = self._normalise(vfs_prefix + "/" + rel)
            self.mkdir(vfs_dir)
            count += 1

            for fname in sorted(filenames):
                host_file = os.path.join(dirpath, fname)
                vfs_file = vfs_dir.rstrip("/") + "/" + fname
                self.ingest_host_file(host_file, vfs_file)
                count += 1
                if progress:
                    progress(vfs_file)

        return count

    # ------------------------------------------------------------------
    # Query & iteration
    # ------------------------------------------------------------------

    def exists(self, path: str) -> bool:
        return self._normalise(path) in self._tree

    def get(self, path: str) -> Optional[VfsNode]:
        return self._tree.get(self._normalise(path))

    def remove(self, path: str) -> bool:
        norm = self._normalise(path)
        if norm in self._tree:
            del self._tree[norm]
            return True
        return False

    def list_dir(self, path: str) -> List[str]:
        """Return the immediate children of a directory (basenames only)."""
        norm = self._normalise(path)
        prefix = norm.rstrip("/") + "/"
        children: List[str] = []
        seen: Set[str] = set()
        for key in self._tree:
            if key.startswith(prefix):
                remainder = key[len(prefix):]
                top = remainder.split("/")[0]
                if top and top not in seen:
                    seen.add(top)
                    children.append(top)
        return sorted(children)

    def walk_sorted(self) -> Iterator[Tuple[str, VfsNode]]:
        """Yield ``(path, node)`` pairs in deterministic sorted order."""
        for key in sorted(self._tree.keys()):
            yield key, self._tree[key]

    def node_count(self) -> int:
        return len(self._tree)

    # ------------------------------------------------------------------
    # Nlink fixup (must be called before serialisation)
    # ------------------------------------------------------------------

    def fixup_nlinks(self) -> None:
        """
        Recompute ``nlink`` for every directory to equal ``2 + number of
        immediate child subdirectories`` (standard POSIX semantics).
        Regular files and symlinks get ``nlink = 1``.
        """
        child_dir_counts: Dict[str, int] = {}
        for path, node in self._tree.items():
            if node.node_type == VfsNodeType.DIRECTORY:
                parent = str(PurePosixPath(path).parent)
                if parent != path:
                    child_dir_counts[parent] = child_dir_counts.get(parent, 0) + 1
        for path, node in self._tree.items():
            if node.node_type == VfsNodeType.DIRECTORY:
                node.nlink = 2 + child_dir_counts.get(path, 0)
            else:
                node.nlink = 1

    # ------------------------------------------------------------------
    # Base filesystem hierarchy initialisation
    # ------------------------------------------------------------------

    def init_base_hierarchy(self) -> None:
        """
        Create the essential FHS directory skeleton and device nodes that
        a minimal Linux rootfs requires.
        """
        base_dirs = [
            ("/", 0o755),
            ("/bin", 0o755),
            ("/boot", 0o755),
            ("/dev", 0o755),
            ("/etc", 0o755),
            ("/home", 0o755),
            ("/lib", 0o755),
            ("/lib64", 0o755),
            ("/media", 0o755),
            ("/mnt", 0o755),
            ("/opt", 0o755),
            ("/proc", 0o555),
            ("/root", 0o700),
            ("/run", 0o755),
            ("/sbin", 0o755),
            ("/srv", 0o755),
            ("/sys", 0o555),
            ("/tmp", 0o1777),
            ("/usr", 0o755),
            ("/usr/bin", 0o755),
            ("/usr/lib", 0o755),
            ("/usr/lib64", 0o755),
            ("/usr/sbin", 0o755),
            ("/usr/share", 0o755),
            ("/usr/local", 0o755),
            ("/usr/local/bin", 0o755),
            ("/usr/local/lib", 0o755),
            ("/var", 0o755),
            ("/var/cache", 0o755),
            ("/var/log", 0o755),
            ("/var/lib", 0o755),
            ("/var/tmp", 0o1777),
            ("/var/run", 0o755),
        ]
        for dirpath, mode in base_dirs:
            self.mkdir(dirpath, mode=mode)

        # Forge standard Linux device nodes in metadata only
        device_nodes = [
            ("/dev/null", 1, 3, 0o666),
            ("/dev/zero", 1, 5, 0o666),
            ("/dev/full", 1, 7, 0o666),
            ("/dev/random", 1, 8, 0o666),
            ("/dev/urandom", 1, 9, 0o666),
            ("/dev/tty", 5, 0, 0o666),
            ("/dev/console", 5, 1, 0o600),
            ("/dev/ptmx", 5, 2, 0o666),
        ]
        for dev_path, major, minor, mode in device_nodes:
            self.add_char_device(dev_path, major, minor, mode=mode)

        # Standard symlinks
        self.add_symlink("/dev/stdin", "/proc/self/fd/0")
        self.add_symlink("/dev/stdout", "/proc/self/fd/1")
        self.add_symlink("/dev/stderr", "/proc/self/fd/2")

    # ------------------------------------------------------------------
    # UID/GID table extraction (needed by SquashFS ID table)
    # ------------------------------------------------------------------

    def collect_id_table(self) -> Tuple[List[int], Dict[int, int]]:
        """
        Collect the deduplicated list of all UID and GID values used in the
        tree.  Returns ``(id_list, id_to_index)`` where *id_to_index* maps
        each raw ID to its position in *id_list*.
        """
        ids: Set[int] = set()
        for node in self._tree.values():
            ids.add(node.uid)
            ids.add(node.gid)
        id_list = sorted(ids)
        id_to_index = {v: i for i, v in enumerate(id_list)}
        return id_list, id_to_index

