"""
torito.vfs — In-Memory POSIX Virtual Filesystem
================================================
Maintains a tree of POSIX inodes (UID/GID, octal modes, symlinks, device
nodes, owner names) entirely in Python, independent of the host filesystem.
Windows NTFS metadata is never consulted; all Linux semantics live here.

File *contents* can live either inline (``bytes``) or in a :class:`BlobStore`
— an append-only pack file on disk — so that multi-gigabyte root filesystems
can be assembled without holding every byte in RAM.

Path handling follows the kernel: intermediate symlinks are resolved when a
node is inserted (so a package that ships ``/lib/foo`` lands in
``/usr/lib/foo`` on a usr-merged tree), while the final component is never
followed.
"""

from __future__ import annotations

import os
import threading
import time
from enum import IntEnum
from typing import Callable, Dict, Iterator, List, NamedTuple, Optional, Set, Tuple


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


# ---------------------------------------------------------------------------
# Blob storage
# ---------------------------------------------------------------------------


class BlobRef(NamedTuple):
    """A slice of a :class:`BlobStore` pack file."""

    store: "BlobStore"
    offset: int
    size: int

    def read(self) -> bytes:
        return self.store.read(self.offset, self.size)


class BlobStore:
    """
    Append-only pack file holding file payloads.

    Writes are sequential (fast on NTFS, no per-file overhead, no case
    folding problems); reads seek into the pack.  Thread-safe.
    """

    def __init__(self, path: str) -> None:
        self.path = os.path.abspath(path)
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        self._w = open(self.path, "w+b")
        self._r = open(self.path, "rb")
        self._lock = threading.Lock()
        self._size = 0

    @property
    def size(self) -> int:
        return self._size

    def put(self, data: bytes) -> BlobRef:
        with self._lock:
            off = self._size
            self._w.write(data)
            self._size += len(data)
            return BlobRef(self, off, len(data))

    def put_stream(self, reader, chunk: int = 1 << 20) -> BlobRef:
        """Copy a file-like object into the store without buffering it whole."""
        with self._lock:
            off = self._size
            total = 0
            while True:
                buf = reader.read(chunk)
                if not buf:
                    break
                self._w.write(buf)
                total += len(buf)
            self._size += total
            return BlobRef(self, off, total)

    def read(self, offset: int, size: int) -> bytes:
        if size == 0:
            return b""
        with self._lock:
            self._w.flush()
            self._r.seek(offset)
            return self._r.read(size)

    def close(self) -> None:
        try:
            self._w.close()
            self._r.close()
        except OSError:
            pass

    def delete(self) -> None:
        self.close()
        try:
            os.remove(self.path)
        except OSError:
            pass


# ---------------------------------------------------------------------------
# Inodes
# ---------------------------------------------------------------------------


class VfsNode:
    """
    A single inode in the POSIX virtual filesystem.

    ``data`` transparently reads from the blob store when the payload is
    stored out of line.  ``uname``/``gname`` record symbolic ownership (from
    package archives) which is resolved to numeric IDs once ``/etc/passwd``
    and ``/etc/group`` are final.
    """

    __slots__ = (
        "node_type", "uid", "gid", "mode", "_data", "blob", "link_target",
        "dev_major", "dev_minor", "mtime", "nlink", "ino", "uname", "gname",
        "xattrs",
    )

    def __init__(
        self,
        node_type: VfsNodeType,
        uid: int = 0,
        gid: int = 0,
        mode: int = 0o644,
        data: bytes = b"",
        link_target: str = "",
        dev_major: int = 0,
        dev_minor: int = 0,
        mtime: int = 0,
        nlink: int = 1,
        ino: int = 0,
        blob: Optional[BlobRef] = None,
        uname: str = "",
        gname: str = "",
        xattrs: Optional[Dict[str, bytes]] = None,
    ) -> None:
        self.node_type = node_type
        self.uid = uid
        self.gid = gid
        self.mode = mode
        self._data = data
        self.blob = blob
        self.link_target = link_target
        self.dev_major = dev_major
        self.dev_minor = dev_minor
        self.mtime = mtime
        self.nlink = nlink
        self.ino = ino
        self.uname = uname
        self.gname = gname
        self.xattrs = xattrs

    @property
    def data(self) -> bytes:
        if self.blob is not None:
            return self.blob.read()
        return self._data

    @data.setter
    def data(self, value: bytes) -> None:
        self._data = bytes(value)
        self.blob = None

    @property
    def size(self) -> int:
        """Return the logical size of this node for archive headers."""
        if self.node_type == VfsNodeType.REGULAR_FILE:
            return self.blob.size if self.blob is not None else len(self._data)
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
        return bool(self.mode & 0o111)

    def same_content(self, other: "VfsNode") -> bool:
        if self.blob is not None and other.blob is not None:
            return self.blob == other.blob
        return False

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"VfsNode({self.node_type.name}, mode={oct(self.mode)}, uid={self.uid}, gid={self.gid}, size={self.size})"


# ---------------------------------------------------------------------------
# CRLF sanitisation
# ---------------------------------------------------------------------------

# File extensions treated as text for CRLF sanitisation of *host* overlays.
TEXT_EXTENSIONS: Set[str] = {
    "sh", "bash", "zsh", "fish", "conf", "cfg", "ini", "toml", "json", "yaml",
    "yml", "xml", "service", "timer", "socket", "mount", "target", "path",
    "py", "pl", "rb", "lua", "desktop", "rules", "txt", "md", "csv", "list",
    "repo", "fstab", "profile", "bashrc", "login", "logout", "env", "rc",
    "local", "cron", "sudoers", "hosts", "hostname", "resolv", "network",
    "interfaces", "sysctl", "modules", "grub", "loader", "entries", "policy",
    "preset", "rules", "html", "css", "js", "mjs", "svg",
}


def sanitise_crlf(raw: bytes) -> bytes:
    """Convert Windows ``\\r\\n`` line endings to ``\\n``."""
    return raw.replace(b"\r\n", b"\n")


def _is_text_payload(filename: str, data: bytes) -> bool:
    """Heuristic: decide whether *data* read from *filename* is a text file."""
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else filename.lower()
    if ext in TEXT_EXTENSIONS:
        return b"\x00" not in data[:8192]
    if data[:2] == b"#!":
        return True
    probe = data[:8192]
    if b"\x00" in probe:
        return False
    if len(probe) > 0:
        high = sum(1 for b in probe if b > 127)
        if high / len(probe) > 0.30:
            return False
    return True


# ---------------------------------------------------------------------------
# The filesystem tree
# ---------------------------------------------------------------------------


class VfsError(Exception):
    pass


class PosixVfs:
    """
    An in-memory POSIX filesystem tree.

    Every path is stored as a ``/``-rooted POSIX string.  A child index keeps
    directory listings O(children); serialisation order is always sorted so
    output is deterministic.
    """

    def __init__(self, source_date_epoch: Optional[int] = None, blob_store: Optional[BlobStore] = None) -> None:
        self._tree: Dict[str, VfsNode] = {}
        self._children: Dict[str, Set[str]] = {}
        self._epoch: int = source_date_epoch if source_date_epoch is not None else int(time.time())
        self._ino_counter: int = 1
        self.blob_store = blob_store
        # Blobs at least this large go to the store (when one is attached).
        self.inline_limit = 16 * 1024
        self._tree["/"] = VfsNode(VfsNodeType.DIRECTORY, mode=0o755, mtime=self._epoch, ino=self._next_ino())
        self._children["/"] = set()

    # ------------------------------------------------------------------
    def _next_ino(self) -> int:
        ino = self._ino_counter
        self._ino_counter += 1
        return ino

    @staticmethod
    def _normalise(path: str) -> str:
        """Canonicalise a path to ``/absolute/posix/form`` with no trailing slash."""
        p = path.replace("\\", "/")
        if not p.startswith("/"):
            p = "/" + p
        parts: List[str] = []
        for seg in p.split("/"):
            if seg == "" or seg == ".":
                continue
            if seg == "..":
                if parts:
                    parts.pop()
                continue
            parts.append(seg)
        return "/" + "/".join(parts) if parts else "/"

    @staticmethod
    def _parent(path: str) -> str:
        if path == "/":
            return "/"
        idx = path.rfind("/")
        return path[:idx] if idx > 0 else "/"

    @staticmethod
    def _basename(path: str) -> str:
        return path.rsplit("/", 1)[-1]

    def resolve(self, path: str, follow_last: bool = False) -> str:
        """
        Resolve symlinks in *path* (all intermediate components, and the last
        one when *follow_last*), returning the canonical path.  Missing
        components are kept literally.
        """
        norm = self._normalise(path)
        parts = [p for p in norm.split("/") if p]
        resolved = "/"
        hops = 0
        i = 0
        while i < len(parts):
            comp = parts[i]
            cand = (resolved.rstrip("/") + "/" + comp) if resolved != "/" else "/" + comp
            node = self._tree.get(cand)
            is_last = i == len(parts) - 1
            if node is not None and node.node_type == VfsNodeType.SYMLINK and (not is_last or follow_last):
                hops += 1
                if hops > 40:
                    raise VfsError(f"too many levels of symbolic links: {path}")
                tgt = node.link_target
                base = "/" if tgt.startswith("/") else resolved
                rest = parts[i + 1:]
                new = self._normalise(base.rstrip("/") + "/" + tgt) if base != "/" else self._normalise(tgt if tgt.startswith("/") else "/" + tgt)
                parts = [p for p in new.split("/") if p] + rest
                resolved = "/"
                i = 0
                continue
            resolved = cand
            i += 1
        return resolved

    def _place(self, path: str) -> str:
        """Resolve where a new node for *path* should live (parents resolved)."""
        norm = self._normalise(path)
        if norm == "/":
            return "/"
        parent = self.resolve(self._parent(norm), follow_last=True)
        return (parent.rstrip("/") + "/" + self._basename(norm)) if parent != "/" else "/" + self._basename(norm)

    def _ensure_dir(self, path: str) -> None:
        """Create *path* and its ancestors as directories if missing."""
        if path in self._tree:
            return
        self._ensure_dir(self._parent(path))
        self._tree[path] = VfsNode(VfsNodeType.DIRECTORY, mode=0o755, mtime=self._epoch, ino=self._next_ino())
        self._children[path] = set()
        self._children[self._parent(path)].add(self._basename(path))

    def _insert(self, path: str, node: VfsNode) -> None:
        if path == "/":
            if node.node_type != VfsNodeType.DIRECTORY:
                raise VfsError("root must be a directory")
            old = self._tree["/"]
            node.ino = old.ino
            self._tree["/"] = node
            return
        parent = self._parent(path)
        pnode = self._tree.get(parent)
        if pnode is None:
            self._ensure_dir(parent)
        elif pnode.node_type != VfsNodeType.DIRECTORY:
            # A non-directory sits where we need a directory: replace it.
            self.remove(parent)
            self._ensure_dir(parent)
        existing = self._tree.get(path)
        if existing is not None and existing.node_type == VfsNodeType.DIRECTORY and node.node_type != VfsNodeType.DIRECTORY:
            self.remove(path)
        if node.ino == 0:
            node.ino = existing.ino if existing is not None else self._next_ino()
        self._tree[path] = node
        self._children[parent].add(self._basename(path))
        if node.node_type == VfsNodeType.DIRECTORY:
            self._children.setdefault(path, set())

    # ------------------------------------------------------------------
    # Public mutators
    # ------------------------------------------------------------------

    def mkdir(
        self,
        path: str,
        mode: int = 0o755,
        uid: int = 0,
        gid: int = 0,
        mtime: Optional[int] = None,
        uname: str = "",
        gname: str = "",
    ) -> str:
        """
        Create (or update the metadata of) a directory.  If *path* is a
        symlink to a directory the link is kept (pacman semantics).
        Returns the canonical path of the directory.
        """
        target = self._place(path)
        existing = self._tree.get(target)
        if existing is not None and existing.node_type == VfsNodeType.SYMLINK:
            real = self.resolve(target, follow_last=True)
            rnode = self._tree.get(real)
            if rnode is not None and rnode.node_type == VfsNodeType.DIRECTORY:
                return real
            if rnode is None:
                self._ensure_dir(real)
                return real
            self.remove(target)
            existing = None
        if existing is not None and existing.node_type == VfsNodeType.DIRECTORY:
            existing.mode = mode
            existing.uid, existing.gid = uid, gid
            existing.uname, existing.gname = uname, gname
            if mtime is not None:
                existing.mtime = mtime
            return target
        self._insert(
            target,
            VfsNode(
                VfsNodeType.DIRECTORY, uid=uid, gid=gid, mode=mode,
                mtime=self._epoch if mtime is None else mtime, uname=uname, gname=gname,
            ),
        )
        return target

    def make_payload(self, data: bytes) -> Tuple[bytes, Optional[BlobRef]]:
        if self.blob_store is not None and len(data) >= self.inline_limit:
            return b"", self.blob_store.put(data)
        return data, None

    def add_file(
        self,
        path: str,
        data: bytes = b"",
        mode: int = 0o644,
        uid: int = 0,
        gid: int = 0,
        mtime: Optional[int] = None,
        blob: Optional[BlobRef] = None,
        uname: str = "",
        gname: str = "",
    ) -> str:
        """Insert a regular file with the given byte content (or blob)."""
        target = self._place(path)
        if blob is None:
            data, blob = self.make_payload(bytes(data))
        self._insert(
            target,
            VfsNode(
                VfsNodeType.REGULAR_FILE, uid=uid, gid=gid, mode=mode, data=data, blob=blob,
                mtime=self._epoch if mtime is None else mtime, uname=uname, gname=gname,
            ),
        )
        return target

    def add_symlink(
        self,
        path: str,
        target: str,
        uid: int = 0,
        gid: int = 0,
        mtime: Optional[int] = None,
        uname: str = "",
        gname: str = "",
    ) -> str:
        """Insert a symbolic link pointing at *target*."""
        where = self._place(path)
        existing = self._tree.get(where)
        if existing is not None and existing.node_type == VfsNodeType.DIRECTORY and self._children.get(where):
            # pacman refuses to replace a populated directory with a symlink;
            # do the same and keep the directory.
            return where
        self._insert(
            where,
            VfsNode(
                VfsNodeType.SYMLINK, uid=uid, gid=gid, mode=0o777, link_target=target,
                mtime=self._epoch if mtime is None else mtime, uname=uname, gname=gname,
            ),
        )
        return where

    def add_hardlink(self, path: str, existing_path: str, mtime: Optional[int] = None) -> str:
        try:
            src = self.get(self.resolve(existing_path))
        except VfsError:
            src = None
        if src is None or src.node_type != VfsNodeType.REGULAR_FILE:
            raise VfsError(f"hard link target missing: {existing_path}")
        where = self._place(path)
        self._insert(
            where,
            VfsNode(
                VfsNodeType.REGULAR_FILE, uid=src.uid, gid=src.gid, mode=src.mode,
                data=src._data, blob=src.blob, mtime=src.mtime if mtime is None else mtime,
                uname=src.uname, gname=src.gname, xattrs=src.xattrs,
            ),
        )
        return where

    def _add_dev(self, path: str, ntype: VfsNodeType, major: int, minor: int, mode: int, uid: int, gid: int) -> str:
        where = self._place(path)
        self._insert(
            where,
            VfsNode(ntype, uid=uid, gid=gid, mode=mode, dev_major=major, dev_minor=minor, mtime=self._epoch),
        )
        return where

    def add_char_device(self, path: str, major: int, minor: int, mode: int = 0o666, uid: int = 0, gid: int = 0) -> str:
        """Insert a character device node (replaces ``mknod``)."""
        return self._add_dev(path, VfsNodeType.CHAR_DEVICE, major, minor, mode, uid, gid)

    def add_block_device(self, path: str, major: int, minor: int, mode: int = 0o660, uid: int = 0, gid: int = 0) -> str:
        """Insert a block device node."""
        return self._add_dev(path, VfsNodeType.BLOCK_DEVICE, major, minor, mode, uid, gid)

    def add_fifo(self, path: str, mode: int = 0o644, uid: int = 0, gid: int = 0) -> str:
        return self._add_dev(path, VfsNodeType.FIFO, 0, 0, mode, uid, gid)

    def remove(self, path: str) -> bool:
        """Remove a node (and its whole subtree for directories)."""
        norm = self._normalise(path)
        if norm == "/" or norm not in self._tree:
            return False
        stack = [norm]
        while stack:
            p = stack.pop()
            kids = self._children.pop(p, None)
            if kids:
                prefix = p.rstrip("/") + "/"
                stack.extend(prefix + k for k in kids)
            self._tree.pop(p, None)
        parent = self._parent(norm)
        if parent in self._children:
            self._children[parent].discard(self._basename(norm))
        return True

    # ------------------------------------------------------------------
    # Host ingestion (Windows overlays)
    # ------------------------------------------------------------------

    def ingest_host_file(self, host_path: str, vfs_path: str, force_executable: bool = False) -> None:
        """
        Read a file from the host and insert it into the VFS.  Text files have
        CRLF line endings converted; ELF binaries and scripts become 0755.
        """
        with open(host_path, "rb") as fh:
            raw = fh.read()
        filename = os.path.basename(host_path)
        if _is_text_payload(filename, raw):
            raw = sanitise_crlf(raw)
        is_exec = force_executable or raw[:2] == b"#!" or raw[:4] == b"\x7fELF"
        self.add_file(vfs_path, raw, mode=0o755 if is_exec else 0o644)

    def ingest_host_directory(
        self,
        host_dir: str,
        vfs_prefix: str = "/",
        progress: Optional[Callable[[str], None]] = None,
    ) -> int:
        """Recursively ingest a host directory tree. Returns the node count."""
        count = 0
        host_dir_path = os.path.normpath(host_dir)
        for dirpath, dirnames, filenames in os.walk(host_dir_path):
            dirnames.sort()
            rel = os.path.relpath(dirpath, host_dir_path).replace("\\", "/")
            vfs_dir = self._normalise(vfs_prefix if rel == "." else vfs_prefix + "/" + rel)
            existing = self.get(vfs_dir)
            if existing is None or existing.node_type != VfsNodeType.DIRECTORY:
                real = self.resolve(vfs_dir, follow_last=True)
                if real not in self._tree:
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
    # Queries
    # ------------------------------------------------------------------

    def exists(self, path: str) -> bool:
        return self._normalise(path) in self._tree

    def get(self, path: str) -> Optional[VfsNode]:
        return self._tree.get(self._normalise(path))

    def lookup(self, path: str) -> Optional[VfsNode]:
        """Like :meth:`get` but follows symlinks."""
        try:
            return self._tree.get(self.resolve(path, follow_last=True))
        except VfsError:
            return None

    def read_file(self, path: str) -> Optional[bytes]:
        node = self.lookup(path)
        if node is None or node.node_type != VfsNodeType.REGULAR_FILE:
            return None
        return node.data

    def is_dir(self, path: str) -> bool:
        node = self.lookup(path)
        return node is not None and node.node_type == VfsNodeType.DIRECTORY

    def list_dir(self, path: str) -> List[str]:
        """Return the immediate children of a directory (basenames, sorted)."""
        return sorted(self._children.get(self._normalise(path), ()))

    def iter_subtree(self, path: str) -> Iterator[Tuple[str, VfsNode]]:
        """Yield every node under *path* (inclusive), sorted."""
        root = self._normalise(path)
        if root not in self._tree:
            return
        stack = [root]
        out: List[str] = []
        while stack:
            p = stack.pop()
            out.append(p)
            prefix = p.rstrip("/") + "/" if p != "/" else "/"
            for k in self._children.get(p, ()):
                stack.append(prefix + k)
        for p in sorted(out):
            yield p, self._tree[p]

    def walk_sorted(self) -> Iterator[Tuple[str, VfsNode]]:
        """Yield ``(path, node)`` pairs in deterministic sorted order."""
        for key in sorted(self._tree.keys()):
            yield key, self._tree[key]

    def node_count(self) -> int:
        return len(self._tree)

    def total_file_bytes(self) -> int:
        return sum(n.size for n in self._tree.values() if n.node_type == VfsNodeType.REGULAR_FILE)

    # ------------------------------------------------------------------
    # Fixups
    # ------------------------------------------------------------------

    def fixup_nlinks(self) -> None:
        """Directories get ``2 + subdirs``; everything else 1."""
        for path, node in self._tree.items():
            if node.node_type == VfsNodeType.DIRECTORY:
                prefix = path.rstrip("/") + "/" if path != "/" else "/"
                sub = 0
                for k in self._children.get(path, ()):
                    c = self._tree.get(prefix + k)
                    if c is not None and c.node_type == VfsNodeType.DIRECTORY:
                        sub += 1
                node.nlink = 2 + sub
            else:
                node.nlink = 1

    def resolve_owners(self, users: Dict[str, int], groups: Dict[str, int], log: Optional[Callable[[str], None]] = None) -> int:
        """Map recorded ``uname``/``gname`` to numeric IDs. Returns unresolved count."""
        unresolved: Set[str] = set()
        for path, node in self._tree.items():
            if node.uname:
                if node.uname in users:
                    node.uid = users[node.uname]
                elif node.uname != "root":
                    unresolved.add("user " + node.uname)
            if node.gname:
                if node.gname in groups:
                    node.gid = groups[node.gname]
                elif node.gname != "root":
                    unresolved.add("group " + node.gname)
        if unresolved and log:
            log("  ⚠ unknown owners kept numeric: " + ", ".join(sorted(unresolved)))
        return len(unresolved)

    # ------------------------------------------------------------------
    # Base filesystem hierarchy
    # ------------------------------------------------------------------

    def init_base_hierarchy(self, usrmerge: bool = True, device_nodes: bool = True) -> None:
        """
        Create the FHS skeleton.  With *usrmerge* (Arch, Fedora, Debian ≥12)
        ``/bin``, ``/sbin``, ``/lib``, ``/lib64`` and ``/usr/sbin`` are
        symlinks into ``/usr`` exactly like the ``filesystem`` package ships.
        """
        dirs = [
            ("/boot", 0o755), ("/dev", 0o755), ("/etc", 0o755), ("/home", 0o755),
            ("/mnt", 0o755), ("/opt", 0o755), ("/proc", 0o555), ("/root", 0o750),
            ("/run", 0o755), ("/srv", 0o755), ("/sys", 0o555), ("/tmp", 0o1777),
            ("/usr", 0o755), ("/usr/bin", 0o755), ("/usr/lib", 0o755),
            ("/usr/include", 0o755), ("/usr/share", 0o755), ("/usr/local", 0o755),
            ("/usr/local/bin", 0o755), ("/usr/local/lib", 0o755), ("/usr/local/share", 0o755),
            ("/var", 0o755), ("/var/cache", 0o755), ("/var/lib", 0o755), ("/var/log", 0o755),
            ("/var/spool", 0o755), ("/var/tmp", 0o1777), ("/var/empty", 0o755),
        ]
        for d, m in dirs:
            self.mkdir(d, mode=m)
        if usrmerge:
            self.add_symlink("/bin", "usr/bin")
            self.add_symlink("/sbin", "usr/bin")
            self.add_symlink("/lib", "usr/lib")
            self.add_symlink("/lib64", "usr/lib")
            self.add_symlink("/usr/sbin", "bin")
            self.add_symlink("/usr/lib64", "lib")
        else:
            for d in ("/bin", "/sbin", "/lib", "/lib64", "/usr/sbin", "/usr/lib64"):
                self.mkdir(d)
        self.add_symlink("/var/run", "../run")
        self.add_symlink("/var/lock", "../run/lock")
        if device_nodes:
            for dev_path, major, minor, mode in (
                ("/dev/null", 1, 3, 0o666), ("/dev/zero", 1, 5, 0o666),
                ("/dev/full", 1, 7, 0o666), ("/dev/random", 1, 8, 0o666),
                ("/dev/urandom", 1, 9, 0o666), ("/dev/tty", 5, 0, 0o666),
                ("/dev/console", 5, 1, 0o600), ("/dev/ptmx", 5, 2, 0o666),
            ):
                self.add_char_device(dev_path, major, minor, mode=mode)
            self.add_symlink("/dev/stdin", "/proc/self/fd/0")
            self.add_symlink("/dev/stdout", "/proc/self/fd/1")
            self.add_symlink("/dev/stderr", "/proc/self/fd/2")

    # ------------------------------------------------------------------
    # UID/GID table (SquashFS ID table)
    # ------------------------------------------------------------------

    def collect_id_table(self) -> Tuple[List[int], Dict[int, int]]:
        ids: Set[int] = set()
        for node in self._tree.values():
            ids.add(node.uid)
            ids.add(node.gid)
        id_list = sorted(ids)
        return id_list, {v: i for i, v in enumerate(id_list)}
