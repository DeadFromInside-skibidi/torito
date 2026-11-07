"""
torito.squashfs — SquashFS 4.0 Image Writer
============================================
Serialises a :class:`~torito.vfs.PosixVfs` into a SquashFS 4.0 image that the
Linux kernel mounts directly (``mount -t squashfs``) — a pure-Python
``mksquashfs``.

* zstd (id 6), gzip/zlib (id 1) and xz (id 4) compression
* parallel block compression (``zstandard`` releases the GIL)
* streaming output — the image is written to disk as it is produced
* fragments for small files and file tails, sparse (all-zero) blocks
* basic *and* extended inodes (large directories, files ≥ 4 GiB, xattrs)
* xattr tables (``security.capability`` etc.)
* table layout ordered exactly as the kernel's sanity checks expect:
  data → inode table → directory table → fragment table → id table → xattrs
"""

from __future__ import annotations

import hashlib
import io
import lzma
import math
import os
import struct
import threading
import time
import zlib
from concurrent.futures import ThreadPoolExecutor
from typing import BinaryIO, Callable, Dict, List, Optional, Tuple

from .vfs import PosixVfs, VfsNode, VfsNodeType

try:
    import zstandard as zstd  # type: ignore[import-untyped]

    _HAS_ZSTD = True
except ImportError:  # pragma: no cover
    zstd = None  # type: ignore[assignment]
    _HAS_ZSTD = False

SQUASHFS_MAGIC = 0x73717368
SQUASHFS_MAJOR = 4
SQUASHFS_MINOR = 0

SQUASHFS_COMP_GZIP = 1
SQUASHFS_COMP_LZMA = 2
SQUASHFS_COMP_LZO = 3
SQUASHFS_COMP_XZ = 4
SQUASHFS_COMP_LZ4 = 5
SQUASHFS_COMP_ZSTD = 6

SQUASHFS_DIR_TYPE = 1
SQUASHFS_REG_TYPE = 2
SQUASHFS_SYMLINK_TYPE = 3
SQUASHFS_BLKDEV_TYPE = 4
SQUASHFS_CHRDEV_TYPE = 5
SQUASHFS_FIFO_TYPE = 6
SQUASHFS_SOCKET_TYPE = 7
SQUASHFS_LDIR_TYPE = 8
SQUASHFS_LREG_TYPE = 9
SQUASHFS_LSYMLINK_TYPE = 10
SQUASHFS_LBLKDEV_TYPE = 11
SQUASHFS_LCHRDEV_TYPE = 12
SQUASHFS_LFIFO_TYPE = 13
SQUASHFS_LSOCKET_TYPE = 14

VFS_TO_SQUASHFS_TYPE: Dict[VfsNodeType, int] = {
    VfsNodeType.DIRECTORY: SQUASHFS_DIR_TYPE,
    VfsNodeType.REGULAR_FILE: SQUASHFS_REG_TYPE,
    VfsNodeType.SYMLINK: SQUASHFS_SYMLINK_TYPE,
    VfsNodeType.BLOCK_DEVICE: SQUASHFS_BLKDEV_TYPE,
    VfsNodeType.CHAR_DEVICE: SQUASHFS_CHRDEV_TYPE,
    VfsNodeType.FIFO: SQUASHFS_FIFO_TYPE,
    VfsNodeType.SOCKET: SQUASHFS_SOCKET_TYPE,
}

SQUASHFS_FLAG_NO_FRAG = 0x0010
SQUASHFS_FLAG_DUPLICATE = 0x0040
SQUASHFS_FLAG_NO_XATTR = 0x0200

SQUASHFS_METADATA_SIZE = 8192
SQUASHFS_METADATA_UNCOMPRESSED_BIT = 0x8000
SQUASHFS_DATA_BLOCK_UNCOMPRESSED_BIT = 0x01000000
SQUASHFS_INVALID_FRAG = 0xFFFFFFFF
SQUASHFS_INVALID_XATTR = 0xFFFFFFFF
SQUASHFS_INVALID_BLK = 0xFFFFFFFFFFFFFFFF
SQUASHFS_MAX_DIR_HEADER_ENTRIES = 256
SQUASHFS_SECTOR_ALIGNMENT = 4096

_XATTR_PREFIXES = (("user.", 0), ("trusted.", 1), ("security.", 2))


# ---------------------------------------------------------------------------
# Compression
# ---------------------------------------------------------------------------


class _Compressor:
    def __init__(self, algo: str, level: int, block_size: int) -> None:
        algo = algo.lower()
        if algo in ("zstd", "zstandard") and not _HAS_ZSTD:
            algo = "gzip"
        if algo in ("zstd", "zstandard"):
            self.algo, self.comp_id = "zstd", SQUASHFS_COMP_ZSTD
        elif algo in ("gzip", "zlib", "gz"):
            self.algo, self.comp_id = "gzip", SQUASHFS_COMP_GZIP
        elif algo in ("xz", "lzma"):
            self.algo, self.comp_id = "xz", SQUASHFS_COMP_XZ
        else:
            raise ValueError(f"Unsupported squashfs compression {algo!r} (use zstd, gzip or xz)")
        self.level = level
        self.block_size = block_size
        self._local = threading.local()

    def compress(self, data: bytes) -> bytes:
        if self.algo == "zstd":
            c = getattr(self._local, "c", None)
            if c is None:
                c = zstd.ZstdCompressor(level=max(1, min(22, self.level)), write_content_size=False, write_checksum=False)
                self._local.c = c
            return c.compress(data)
        if self.algo == "gzip":
            return zlib.compress(data, max(1, min(9, self.level)))
        filters = [{"id": lzma.FILTER_LZMA2, "preset": max(0, min(9, self.level)), "dict_size": max(self.block_size, 8192)}]
        return lzma.compress(data, format=lzma.FORMAT_XZ, check=lzma.CHECK_CRC32, filters=filters)

    def pack(self, data: bytes) -> Tuple[bytes, bool]:
        """(payload, stored_uncompressed)."""
        if not data:
            return b"", True
        c = self.compress(data)
        if len(c) < len(data):
            return c, False
        return data, True


# ---------------------------------------------------------------------------
# Metadata streams (inode table, directory table, …)
# ---------------------------------------------------------------------------


class MetadataBuffer:
    """
    A metadata stream: uncompressed data is cut into 8 KiB blocks, each
    stored as ``u16 header + payload`` (bit 15 = stored uncompressed).
    Only the final block is ever short, exactly like mksquashfs.
    """

    def __init__(self, compressor: Callable[[bytes], Tuple[bytes, bool]]) -> None:
        self._compressor = compressor
        self._pending = bytearray()
        self._out = bytearray()

    @property
    def output_size(self) -> int:
        return len(self._out)

    def position(self) -> Tuple[int, int]:
        """(compressed offset of the current block, offset within it)."""
        return len(self._out), len(self._pending)

    def write(self, data: bytes) -> Tuple[int, int]:
        pos = self.position()
        self._pending.extend(data)
        while len(self._pending) >= SQUASHFS_METADATA_SIZE:
            self._emit(bytes(self._pending[:SQUASHFS_METADATA_SIZE]))
            del self._pending[:SQUASHFS_METADATA_SIZE]
        return pos

    def _emit(self, block: bytes) -> None:
        payload, raw = self._compressor(block)
        hdr = len(payload) | (SQUASHFS_METADATA_UNCOMPRESSED_BIT if raw else 0)
        self._out.extend(struct.pack("<H", hdr))
        self._out.extend(payload)

    def flush(self) -> bytes:
        if self._pending:
            self._emit(bytes(self._pending))
            self._pending.clear()
        return bytes(self._out)


def _pack_table(entries: bytes, comp: _Compressor, start: int) -> Tuple[bytes, bytes]:
    """
    Lay out a lookup table (fragment / id / xattr-id): metadata blocks
    followed by a u64 index of their absolute offsets.  Returns
    (blocks, index).
    """
    blocks = bytearray()
    index = bytearray()
    for i in range(0, len(entries), SQUASHFS_METADATA_SIZE):
        chunk = entries[i: i + SQUASHFS_METADATA_SIZE]
        payload, raw = comp.pack(chunk)
        index.extend(struct.pack("<Q", start + len(blocks)))
        blocks.extend(struct.pack("<H", len(payload) | (SQUASHFS_METADATA_UNCOMPRESSED_BIT if raw else 0)))
        blocks.extend(payload)
    return bytes(blocks), bytes(index)


# ---------------------------------------------------------------------------
# Writer
# ---------------------------------------------------------------------------


class _FileLayout:
    __slots__ = ("start", "blocks", "frag", "frag_off", "size")

    def __init__(self, size: int) -> None:
        self.start = 0
        self.blocks: List[int] = []
        self.frag = SQUASHFS_INVALID_FRAG
        self.frag_off = 0
        self.size = size


class SquashFSWriter:
    """Serialise a PosixVfs into a SquashFS 4.0 image."""

    def __init__(
        self,
        block_size: int = 131072,
        compression: str = "zstd",
        level: Optional[int] = None,
        workers: Optional[int] = None,
        log: Optional[Callable[[str], None]] = None,
        progress: Optional[Callable[[float], None]] = None,
    ) -> None:
        if block_size < 4096 or block_size > 1048576 or block_size & (block_size - 1):
            raise ValueError(f"block_size must be a power of 2 between 4096 and 1048576, got {block_size}")
        self.block_size = block_size
        self.block_log = int(math.log2(block_size))
        if level is None:
            level = 15 if compression.lower().startswith("z") else (9 if compression.lower().startswith("g") else 6)
        self._comp = _Compressor(compression, level, block_size)
        self.compression = self._comp.algo
        self.compression_id = self._comp.comp_id
        self.workers = workers or max(1, (os.cpu_count() or 2))
        self.log = log or (lambda m: None)
        self.progress = progress

    # Backwards-compatible helper used by older callers/tests
    def _compress_data(self, data: bytes) -> Tuple[bytes, bool]:
        return self._comp.pack(data)

    # ------------------------------------------------------------------
    def build(self, vfs: PosixVfs, out: Optional[BinaryIO] = None) -> bytes:
        """
        Write the image to *out* (a binary file opened for writing) and
        return ``b""``; without *out*, return the image bytes.
        """
        if out is None:
            buf = io.BytesIO()
            self._build(vfs, buf)
            return buf.getvalue()
        self._build(vfs, out)
        return b""

    def build_to_file(self, vfs: PosixVfs, path: str) -> int:
        with open(path, "wb") as fh:
            self._build(vfs, fh)
            return fh.tell()

    # ------------------------------------------------------------------
    def _build(self, vfs: PosixVfs, out: BinaryIO) -> None:
        t0 = time.monotonic()
        vfs.fixup_nlinks()
        nodes: Dict[str, VfsNode] = dict(vfs.walk_sorted())
        id_list, id_to_index = vfs.collect_id_table()
        if len(id_list) > 65535:
            raise ValueError("too many distinct uid/gid values for squashfs")

        out.write(b"\x00" * 96)  # superblock placeholder
        pos = 96

        # ---------------- data blocks & fragments ----------------
        layouts: Dict[str, _FileLayout] = {}
        dedupe: Dict[object, _FileLayout] = {}
        frag_entries: List[Tuple[int, int]] = []
        frag_buf = bytearray()
        bs = self.block_size
        total_bytes = max(1, sum(n.size for n in nodes.values() if n.node_type == VfsNodeType.REGULAR_FILE))
        done_bytes = 0
        zero_block = bytes(bs)

        pool = ThreadPoolExecutor(max_workers=self.workers)
        # Pending work: list of (kind, payload, target) in output order.
        pending: List[Tuple[str, bytes, object]] = []
        pending_bytes = 0
        batch_limit = max(32 << 20, bs * self.workers * 8)

        def drain() -> None:
            nonlocal pos, pending, pending_bytes
            if not pending:
                return
            jobs = [p for p in pending]
            results = list(pool.map(lambda item: self._comp.pack(item[1]) if item[0] != "sparse" else (b"", False), jobs))
            for (kind, payload, target), (data, raw) in zip(jobs, results):
                if kind == "block":
                    lay = target  # type: ignore[assignment]
                    if not lay.blocks:
                        lay.start = pos
                    lay.blocks.append(len(data) | (SQUASHFS_DATA_BLOCK_UNCOMPRESSED_BIT if raw else 0))
                    out.write(data)
                    pos += len(data)
                elif kind == "sparse":
                    lay = target  # type: ignore[assignment]
                    if not lay.blocks:
                        lay.start = pos
                    lay.blocks.append(0)
                else:  # fragment
                    idx = target  # type: ignore[assignment]
                    frag_entries[idx] = (pos, len(data) | (SQUASHFS_DATA_BLOCK_UNCOMPRESSED_BIT if raw else 0))
                    out.write(data)
                    pos += len(data)
            pending = []
            pending_bytes = 0

        def queue(kind: str, payload: bytes, target: object) -> None:
            nonlocal pending_bytes
            pending.append((kind, payload, target))
            pending_bytes += len(payload)
            if pending_bytes >= batch_limit:
                drain()

        def flush_fragment() -> None:
            nonlocal frag_buf
            if frag_buf:
                frag_entries.append((0, 0))
                queue("frag", bytes(frag_buf), len(frag_entries) - 1)
                frag_buf = bytearray()

        def add_tail(lay: _FileLayout, tail: bytes) -> None:
            nonlocal frag_buf
            if len(frag_buf) + len(tail) > bs:
                flush_fragment()
            lay.frag = len(frag_entries)  # index of the fragment being filled
            lay.frag_off = len(frag_buf)
            frag_buf.extend(tail)

        for path, node in nodes.items():
            if node.node_type != VfsNodeType.REGULAR_FILE:
                continue
            size = node.size
            if node.blob is not None:
                key: object = ("blob", node.blob.offset, node.blob.size, id(node.blob.store))
            elif size <= 4096:
                key = ("inline", hashlib.sha1(node._data).digest(), size)
            else:
                key = None
            if key is not None and key in dedupe:
                layouts[path] = dedupe[key]
                continue
            lay = _FileLayout(size)
            layouts[path] = lay
            if key is not None:
                dedupe[key] = lay
            if size == 0:
                continue
            data = node.data
            full = size // bs
            for b in range(full):
                chunk = data[b * bs:(b + 1) * bs]
                if chunk == zero_block:
                    queue("sparse", b"", lay)
                else:
                    queue("block", chunk, lay)
            tail = data[full * bs:]
            if tail:
                add_tail(lay, tail)
            done_bytes += size
            if self.progress:
                self.progress(min(0.95, done_bytes / total_bytes))
        flush_fragment()
        drain()
        pool.shutdown()
        # Fix fragment indices of files whose tail landed in a fragment that
        # was opened after the file was laid out (index captured at insert).
        data_end = pos
        self.log(f"    data: {data_end / 1048576:.1f} MiB in {time.monotonic() - t0:.1f}s, {len(frag_entries)} fragments")

        # ---------------- xattrs ----------------
        xattr_kv = MetadataBuffer(self._comp.pack)
        xattr_ids: List[Tuple[int, int, int]] = []
        xattr_index: Dict[Tuple[Tuple[str, bytes], ...], int] = {}

        def xattr_id_for(node: VfsNode) -> int:
            if not node.xattrs:
                return SQUASHFS_INVALID_XATTR
            items = tuple(sorted(node.xattrs.items()))
            if items in xattr_index:
                return xattr_index[items]
            blk, off = xattr_kv.position()
            total = 0
            count = 0
            for name, value in items:
                for pfx, typ in _XATTR_PREFIXES:
                    if name.startswith(pfx):
                        short = name[len(pfx):].encode()
                        xattr_kv.write(struct.pack("<HH", typ, len(short)) + short)
                        xattr_kv.write(struct.pack("<I", len(value)) + value)
                        total += len(name) + 1 + len(value)
                        count += 1
                        break
            if count == 0:
                return SQUASHFS_INVALID_XATTR
            xattr_ids.append(((blk << 16) | off, count, total))
            xattr_index[items] = len(xattr_ids) - 1
            return xattr_index[items]

        # ---------------- inodes & directories ----------------
        inode_w = MetadataBuffer(self._comp.pack)
        dir_w = MetadataBuffer(self._comp.pack)
        refs: Dict[str, Tuple[int, int, int, int]] = {}  # path -> (blk, off, ino, type)
        next_ino = [1]

        def common(t: int, node: VfsNode, ino: int) -> bytes:
            return struct.pack(
                "<HHHHII", t, node.mode & 0o7777, id_to_index[node.uid], id_to_index[node.gid],
                int(node.mtime) & 0xFFFFFFFF, ino,
            )

        def write_leaf(path: str, node: VfsNode) -> None:
            ino = next_ino[0]
            next_ino[0] += 1
            t = node.node_type
            if t == VfsNodeType.REGULAR_FILE:
                lay = layouts[path]
                xid = xattr_id_for(node)
                blist = b"".join(struct.pack("<I", b) for b in lay.blocks)
                if lay.start < (1 << 32) and lay.size < (1 << 32) and xid == SQUASHFS_INVALID_XATTR:
                    body = common(SQUASHFS_REG_TYPE, node, ino) + struct.pack("<IIII", lay.start, lay.frag, lay.frag_off, lay.size) + blist
                    st = SQUASHFS_REG_TYPE
                else:
                    body = common(SQUASHFS_LREG_TYPE, node, ino) + struct.pack(
                        "<QQQIIII", lay.start, lay.size, 0, 1, lay.frag, lay.frag_off, xid
                    ) + blist
                    st = SQUASHFS_REG_TYPE
            elif t == VfsNodeType.SYMLINK:
                tgt = node.link_target.encode("utf-8")
                body = common(SQUASHFS_SYMLINK_TYPE, node, ino) + struct.pack("<II", 1, len(tgt)) + tgt
                st = SQUASHFS_SYMLINK_TYPE
            elif t in (VfsNodeType.CHAR_DEVICE, VfsNodeType.BLOCK_DEVICE):
                rdev = (node.dev_minor & 0xFF) | ((node.dev_major & 0xFFF) << 8) | ((node.dev_minor & ~0xFF) << 12)
                st = SQUASHFS_CHRDEV_TYPE if t == VfsNodeType.CHAR_DEVICE else SQUASHFS_BLKDEV_TYPE
                body = common(st, node, ino) + struct.pack("<II", 1, rdev)
            elif t in (VfsNodeType.FIFO, VfsNodeType.SOCKET):
                st = SQUASHFS_FIFO_TYPE if t == VfsNodeType.FIFO else SQUASHFS_SOCKET_TYPE
                body = common(st, node, ino) + struct.pack("<I", 1)
            else:
                raise ValueError(f"unsupported node type at {path}")
            blk, off = inode_w.write(body)
            refs[path] = (blk, off, ino, st)

        def dir_listing(children: List[Tuple[bytes, str]]) -> bytes:
            out_b = bytearray()
            i = 0
            while i < len(children):
                name0, p0 = children[i]
                blk0, _, ino0, _ = refs[p0]
                group = [(name0, p0)]
                j = i + 1
                while j < len(children) and len(group) < SQUASHFS_MAX_DIR_HEADER_ENTRIES:
                    n, p = children[j]
                    b, _, ino, _ = refs[p]
                    if b != blk0 or not (-32768 <= ino - ino0 <= 32767):
                        break
                    group.append((n, p))
                    j += 1
                out_b.extend(struct.pack("<III", len(group) - 1, blk0, ino0))
                for n, p in group:
                    _, off, ino, st = refs[p]
                    out_b.extend(struct.pack("<HhHH", off, ino - ino0, st, len(n) - 1))
                    out_b.extend(n)
                i = j
            return bytes(out_b)

        # Post-order traversal (children before parents, root last).  Directory
        # inode numbers are reserved up front so children know their parent.
        def walk2(dpath: str, parent_ino_num: int) -> None:
            my_ino = reserved[dpath]
            prefix = dpath.rstrip("/") + "/" if dpath != "/" else "/"
            names = sorted(vfs.list_dir(dpath), key=lambda s: s.encode("utf-8", "surrogateescape"))
            for name in names:
                cp = prefix + name
                cn = nodes.get(cp)
                if cn is not None and cn.node_type == VfsNodeType.DIRECTORY:
                    walk2(cp, my_ino)
            children: List[Tuple[bytes, str]] = []
            for name in names:
                cp = prefix + name
                cn = nodes.get(cp)
                if cn is None:
                    continue
                if cn.node_type != VfsNodeType.DIRECTORY:
                    write_leaf(cp, cn)
                nb = name.encode("utf-8", "surrogateescape")
                if 0 < len(nb) <= 256:
                    children.append((nb, cp))
            listing = dir_listing(children)
            if listing:
                dblk, doff = dir_w.write(listing)
            else:
                dblk, doff = dir_w.position()
            dnode = nodes[dpath]
            fsize = len(listing) + 3
            xid = xattr_id_for(dnode)
            if fsize <= 0xFFFF and xid == SQUASHFS_INVALID_XATTR:
                body = common(SQUASHFS_DIR_TYPE, dnode, my_ino) + struct.pack(
                    "<IIHHI", dblk, dnode.nlink, fsize, doff, parent_ino_num
                )
            else:
                body = common(SQUASHFS_LDIR_TYPE, dnode, my_ino) + struct.pack(
                    "<IIIIHHI", dnode.nlink, fsize, dblk, parent_ino_num, 0, doff, xid
                )
            blk, off = inode_w.write(body)
            refs[dpath] = (blk, off, my_ino, SQUASHFS_DIR_TYPE)

        # Inode numbers: directories get numbers up front (so parents are known),
        # leaves are numbered as they are written.
        reserved: Dict[str, int] = {}
        dir_paths = [p for p, n in nodes.items() if n.node_type == VfsNodeType.DIRECTORY]
        for p in dir_paths:
            reserved[p] = next_ino[0]
            next_ino[0] += 1
        root_count = len(nodes)
        walk2("/", root_count + 1)
        inode_count = next_ino[0] - 1

        inode_table = inode_w.flush()
        dir_table = dir_w.flush()
        root_blk, root_off, _, _ = refs["/"]

        inode_table_start = pos
        out.write(inode_table)
        pos += len(inode_table)
        directory_table_start = pos
        out.write(dir_table)
        pos += len(dir_table)

        # Fragment table
        if frag_entries:
            raw_frag = b"".join(struct.pack("<QII", s, z, 0) for s, z in frag_entries)
            blocks, index = _pack_table(raw_frag, self._comp, pos)
            out.write(blocks)
            pos += len(blocks)
            fragment_table_start = pos
            out.write(index)
            pos += len(index)
        else:
            fragment_table_start = SQUASHFS_INVALID_BLK

        # ID table
        raw_ids = b"".join(struct.pack("<I", i) for i in id_list)
        blocks, index = _pack_table(raw_ids, self._comp, pos)
        out.write(blocks)
        pos += len(blocks)
        id_table_start = pos
        out.write(index)
        pos += len(index)

        # Xattr tables
        if xattr_ids:
            kv = xattr_kv.flush()
            xattr_table_start = pos
            out.write(kv)
            pos += len(kv)
            raw_xid = b"".join(struct.pack("<QII", ref, cnt, sz) for ref, cnt, sz in xattr_ids)
            blocks, index = _pack_table(raw_xid, self._comp, pos)
            out.write(blocks)
            pos += len(blocks)
            xattr_id_table_start = pos
            out.write(struct.pack("<QII", xattr_table_start, len(xattr_ids), 0))
            out.write(index)
            pos += 16 + len(index)
        else:
            xattr_id_table_start = SQUASHFS_INVALID_BLK

        bytes_used = pos
        flags = SQUASHFS_FLAG_DUPLICATE
        if not frag_entries:
            flags |= SQUASHFS_FLAG_NO_FRAG
        if not xattr_ids:
            flags |= SQUASHFS_FLAG_NO_XATTR
        superblock = struct.pack(
            "<IIIIIHHHHHHQQQQQQQQ",
            SQUASHFS_MAGIC,
            inode_count,
            int(vfs._epoch) & 0xFFFFFFFF,
            self.block_size,
            len(frag_entries),
            self.compression_id,
            self.block_log,
            flags,
            len(id_list),
            SQUASHFS_MAJOR,
            SQUASHFS_MINOR,
            (root_blk << 16) | root_off,
            bytes_used,
            id_table_start,
            xattr_id_table_start,
            inode_table_start,
            directory_table_start,
            fragment_table_start,
            SQUASHFS_INVALID_BLK,
        )
        pad = (-pos) % SQUASHFS_SECTOR_ALIGNMENT
        if pad:
            out.write(b"\x00" * pad)
        end = out.tell()
        out.seek(0)
        out.write(superblock)
        out.seek(end)
        if self.progress:
            self.progress(1.0)
        self.log(
            f"    squashfs: {inode_count} inodes, {bytes_used / 1048576:.1f} MiB, "
            f"{self.compression}, {time.monotonic() - t0:.1f}s"
        )


def build_squashfs(
    vfs: PosixVfs,
    block_size: int = 131072,
    compression: str = "zstd",
    level: Optional[int] = None,
) -> bytes:
    """Serialise *vfs* into SquashFS bytes (convenience for small trees/tests)."""
    return SquashFSWriter(block_size=block_size, compression=compression, level=level).build(vfs)
