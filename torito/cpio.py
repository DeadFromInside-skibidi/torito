"""
torito.cpio — SVR4 New-ASCII (newc / 070701) CPIO Archive Packer & Parser
========================================================================
Implements the SVR4 portable ASCII format ("newc", magic 070701) used
by the Linux kernel for initramfs images. Converts an in-memory PosixVfs
hierarchy into deterministic, byte-aligned CPIO streams, and supports
compression with zstandard, gzip, xz, or uncompressed output.

Specification:
    - Fixed 110-byte ASCII header per entry (magic + 13 8-character hex fields).
    - Header is followed immediately by NUL-terminated pathname.
    - Pathname is padded with NUL bytes to a 4-byte boundary (offset 110 + namesize).
    - File payload follows, padded with NUL bytes to a 4-byte boundary.
    - Archive ends with a sentinel record named "TRAILER!!!".
    - Paths are relative (no leading '/'), with the root directory encoded as ".".
"""

from __future__ import annotations

import gzip
import io
import lzma
import struct
from dataclasses import dataclass
from typing import Dict, Iterator, List, Optional, Set, Tuple, Union

try:
    from .vfs import POSIX_TYPE_BITS, PosixVfs, VfsNode, VfsNodeType
except ImportError:
    from torito.vfs import POSIX_TYPE_BITS, PosixVfs, VfsNode, VfsNodeType


# ======================================================================
# CPIO Format Constants
# ======================================================================

CPIO_NEWC_MAGIC: bytes = b"070701"
CPIO_CRC_MAGIC: bytes = b"070702"
TRAILER_NAME: str = "TRAILER!!!"

# SVR4 newc header struct layout:
#  6s : c_magic    (6 bytes ASCII, "070701")
#  8s : c_ino      (8 bytes hex ASCII)
#  8s : c_mode     (8 bytes hex ASCII, full POSIX mode word)
#  8s : c_uid      (8 bytes hex ASCII)
#  8s : c_gid      (8 bytes hex ASCII)
#  8s : c_nlink    (8 bytes hex ASCII)
#  8s : c_mtime    (8 bytes hex ASCII)
#  8s : c_filesize (8 bytes hex ASCII)
#  8s : c_maj      (8 bytes hex ASCII, filesystem dev major)
#  8s : c_min      (8 bytes hex ASCII, filesystem dev minor)
#  8s : c_rmaj     (8 bytes hex ASCII, device node major)
#  8s : c_rmin     (8 bytes hex ASCII, device node minor)
#  8s : c_namesize (8 bytes hex ASCII, length of filename including trailing NUL)
#  8s : c_check    (8 bytes hex ASCII, CRC checksum or 0)
HEADER_FORMAT: str = "=6s8s8s8s8s8s8s8s8s8s8s8s8s8s"
HEADER_SIZE: int = struct.calcsize(HEADER_FORMAT)  # exactly 110 bytes


# ======================================================================
# Exceptions
# ======================================================================

class CpioError(Exception):
    """Base exception for all CPIO processing errors."""


class CpioCorruptError(CpioError):
    """Raised when an archive stream is malformed, truncated, or invalid."""


class CpioHeaderError(CpioError):
    """Raised when a CPIO entry header contains invalid fields or magic."""


# ======================================================================
# Data Structures
# ======================================================================

@dataclass
class CpioEntry:
    """
    In-memory representation of a single SVR4 CPIO archive entry.

    Stores all metadata fields decoded from the 110-byte header, along with
    the filename string and optional data payload.
    """

    name: str
    ino: int = 0
    mode: int = 0
    uid: int = 0
    gid: int = 0
    nlink: int = 1
    mtime: int = 0
    filesize: int = 0
    devmajor: int = 0
    devminor: int = 0
    rdevmajor: int = 0
    rdevminor: int = 0
    check: int = 0
    data: bytes = b""

    @property
    def is_trailer(self) -> bool:
        """Return True if this entry is the end-of-archive sentinel."""
        return self.name == TRAILER_NAME

    @property
    def is_regular_file(self) -> bool:
        """Return True if the entry represents a regular file."""
        return (self.mode & 0o170000) == POSIX_TYPE_BITS[VfsNodeType.REGULAR_FILE]

    @property
    def is_dir(self) -> bool:
        """Return True if the entry represents a directory."""
        return (self.mode & 0o170000) == POSIX_TYPE_BITS[VfsNodeType.DIRECTORY]

    @property
    def is_symlink(self) -> bool:
        """Return True if the entry represents a symbolic link."""
        return (self.mode & 0o170000) == POSIX_TYPE_BITS[VfsNodeType.SYMLINK]

    @property
    def is_char_dev(self) -> bool:
        """Return True if the entry represents a character device node."""
        return (self.mode & 0o170000) == POSIX_TYPE_BITS[VfsNodeType.CHAR_DEVICE]

    @property
    def is_block_dev(self) -> bool:
        """Return True if the entry represents a block device node."""
        return (self.mode & 0o170000) == POSIX_TYPE_BITS[VfsNodeType.BLOCK_DEVICE]

    @property
    def is_fifo(self) -> bool:
        """Return True if the entry represents a named FIFO pipe."""
        return (self.mode & 0o170000) == POSIX_TYPE_BITS[VfsNodeType.FIFO]

    @property
    def is_socket(self) -> bool:
        """Return True if the entry represents a POSIX domain socket."""
        return (self.mode & 0o170000) == POSIX_TYPE_BITS[VfsNodeType.SOCKET]


# ======================================================================
# Alignment Helpers
# ======================================================================

def _pad4(n: int) -> int:
    """
    Return the number of padding bytes needed to align an offset or length
    n to a 4-byte boundary.

    >>> _pad4(0)
    0
    >>> _pad4(1)
    3
    >>> _pad4(2)
    2
    >>> _pad4(3)
    1
    >>> _pad4(4)
    0
    """
    if n < 0:
        raise ValueError(f"Padding input must be non-negative, got {n}")
    return (4 - (n % 4)) % 4


# ======================================================================
# CPIO Archiver
# ======================================================================

class CpioArchiver:
    """
    Constructs SVR4 newc (070701) CPIO archives for Linux kernel initramfs.

    Guarantees deterministic output:
      - Path normalization (no leading slashes, root encoded as '.').
      - 4-byte alignment of pathname and payload segments.
      - 8-digit uppercase hexadecimal ASCII header encoding.
      - Proper sentinel trailer appended upon finalization.
    """

    def __init__(self) -> None:
        self._buffer: bytearray = bytearray()
        self._finalized: bool = False
        self._ino_counter: int = 1
        self._entry_count: int = 0

    @property
    def finalized(self) -> bool:
        """Return True if the archive has been closed with a TRAILER!!! entry."""
        return self._finalized

    @property
    def entry_count(self) -> int:
        """Return the number of entries written to the archive (excluding trailer)."""
        return self._entry_count

    def _alloc_ino(self) -> int:
        """Allocate a monotonic inode number if none was provided."""
        ino = self._ino_counter
        self._ino_counter += 1
        return ino

    @staticmethod
    def _format_path(path: str, prefix: str = "") -> str:
        """
        Normalize and format a VFS path for CPIO archive compliance.

        Rules:
          - Paths must NOT have a leading slash (e.g. 'etc/passwd').
          - The root directory '/' is stored as '.'.
          - If a non-empty prefix is supplied, it is prepended.
        """
        clean_prefix = prefix.strip("/")
        if path == "/" or not path:
            return clean_prefix if clean_prefix else "."

        rel = path.lstrip("/")
        if clean_prefix:
            return f"{clean_prefix}/{rel}"
        return rel

    def _add_entry(
        self,
        name: str,
        ino: int,
        mode: int,
        uid: int,
        gid: int,
        nlink: int,
        mtime: int,
        data: bytes,
        rdevmajor: int,
        rdevminor: int,
    ) -> None:
        """
        Serialize and append a single SVR4 newc entry into the archive buffer.

        Parameters:
            name: Archive relative pathname (e.g. 'bin/busybox' or '.').
            ino: Inode number (32-bit unsigned integer).
            mode: POSIX mode bits (file type + permissions).
            uid: User ID.
            gid: Group ID.
            nlink: Hard link count.
            mtime: Modification timestamp (seconds since Unix epoch).
            data: File content payload (for regular files) or symlink target bytes.
            rdevmajor: Device major number (for char/block devices, else 0).
            rdevminor: Device minor number (for char/block devices, else 0).
        """
        if self._finalized:
            raise RuntimeError("Cannot add entry to an already finalized CPIO archive.")

        # Ensure path complies with rule: no leading slash, root is '.'
        if name == "/":
            name = "."
        elif name.startswith("/") and name != ".":
            name = name.lstrip("/")

        # Filename encoded as UTF-8 with trailing NUL byte
        name_bytes = name.encode("utf-8") + b"\x00"
        namesize = len(name_bytes)
        filesize = len(data) if data else 0

        # Filesystem device numbers and check field are 0 in standard newc
        devmajor = 0
        devminor = 0
        check = 0

        # Pack the 110-byte fixed ASCII header using struct.pack
        header_bytes = struct.pack(
            HEADER_FORMAT,
            CPIO_NEWC_MAGIC,
            f"{ino & 0xFFFFFFFF:08X}".encode("ascii"),
            f"{mode & 0xFFFFFFFF:08X}".encode("ascii"),
            f"{uid & 0xFFFFFFFF:08X}".encode("ascii"),
            f"{gid & 0xFFFFFFFF:08X}".encode("ascii"),
            f"{nlink & 0xFFFFFFFF:08X}".encode("ascii"),
            f"{mtime & 0xFFFFFFFF:08X}".encode("ascii"),
            f"{filesize & 0xFFFFFFFF:08X}".encode("ascii"),
            f"{devmajor & 0xFFFFFFFF:08X}".encode("ascii"),
            f"{devminor & 0xFFFFFFFF:08X}".encode("ascii"),
            f"{rdevmajor & 0xFFFFFFFF:08X}".encode("ascii"),
            f"{rdevminor & 0xFFFFFFFF:08X}".encode("ascii"),
            f"{namesize & 0xFFFFFFFF:08X}".encode("ascii"),
            f"{check & 0xFFFFFFFF:08X}".encode("ascii"),
        )

        # Append header and filename
        self._buffer.extend(header_bytes)
        self._buffer.extend(name_bytes)

        # Pad filename to 4-byte boundary relative to header start (110 + namesize)
        name_pad = _pad4(HEADER_SIZE + namesize)
        if name_pad > 0:
            self._buffer.extend(b"\x00" * name_pad)

        # Append file data and align data to 4-byte boundary
        if filesize > 0 and data:
            self._buffer.extend(data)
            data_pad = _pad4(filesize)
            if data_pad > 0:
                self._buffer.extend(b"\x00" * data_pad)

        if name != TRAILER_NAME:
            self._entry_count += 1
            if ino >= self._ino_counter:
                self._ino_counter = ino + 1

    def add_from_vfs(self, vfs: PosixVfs, prefix: str = "") -> None:
        """
        Iterate over all nodes in the PosixVfs and append them to the archive.

        Parameters:
            vfs: The virtual filesystem tree to pack.
            prefix: Optional directory prefix to prepend to all archive paths.
        """
        if self._finalized:
            raise RuntimeError("Cannot add VFS nodes to an already finalized CPIO archive.")

        # Ensure nlink counts on directories reflect their child count
        vfs.fixup_nlinks()

        for path, node in vfs.walk_sorted():
            archive_path = self._format_path(path, prefix)

            # Determine payload and device numbers based on VfsNodeType
            if node.node_type == VfsNodeType.REGULAR_FILE:
                payload = node.data if node.data is not None else b""
                rdevmaj = 0
                rdevmin = 0
            elif node.node_type == VfsNodeType.SYMLINK:
                # For symlinks, payload is the target string, NOT NUL-terminated
                payload = node.link_target.encode("utf-8") if node.link_target else b""
                rdevmaj = 0
                rdevmin = 0
            elif node.node_type in (VfsNodeType.CHAR_DEVICE, VfsNodeType.BLOCK_DEVICE):
                payload = b""
                rdevmaj = node.dev_major
                rdevmin = node.dev_minor
            else:
                # DIRECTORY, FIFO, SOCKET have no data payload
                payload = b""
                rdevmaj = 0
                rdevmin = 0

            ino = node.ino if node.ino > 0 else self._alloc_ino()
            mode = node.full_mode
            uid = node.uid
            gid = node.gid
            nlink = node.nlink
            mtime = node.mtime if node.mtime is not None else vfs._epoch

            self._add_entry(
                name=archive_path,
                ino=ino,
                mode=mode,
                uid=uid,
                gid=gid,
                nlink=nlink,
                mtime=mtime,
                data=payload,
                rdevmajor=rdevmaj,
                rdevminor=rdevmin,
            )

    def finalize(self) -> bytes:
        """
        Append the sentinel TRAILER!!! entry if not already present,
        and return the complete, uncompressed CPIO archive bytes.
        """
        if not self._finalized:
            # Per SVR4 specification:
            # Trailer has filename 'TRAILER!!!', namesize 11, magic 070701,
            # and all other fields set to zero.
            self._add_entry(
                name=TRAILER_NAME,
                ino=0,
                mode=0,
                uid=0,
                gid=0,
                nlink=0,
                mtime=0,
                data=b"",
                rdevmajor=0,
                rdevminor=0,
            )
            self._finalized = True

        return bytes(self._buffer)

    @staticmethod
    def _compress(
        cpio_bytes: bytes,
        compression: str = "zstd",
        level: int = 19,
        threads: int = 0,
    ) -> bytes:
        """
        Compress uncompressed CPIO archive bytes using the requested algorithm.

        Supported algorithms:
          - 'zstd' / 'zstandard': Zstandard compression (default level 19).
          - 'gzip' / 'gz': Gzip compression (clamped to level 1..9).
          - 'xz' / 'lzma': LZMA / XZ compression (clamped to level 0..9).
          - 'none' / '': Uncompressed CPIO archive.
        """
        algo = compression.lower().strip() if compression else "none"

        if algo in ("zstd", "zstandard"):
            try:
                import zstandard as zstd
            except ImportError as exc:
                raise RuntimeError(
                    "The 'zstandard' Python package is required for zstd compression. "
                    "Install it via: pip install zstandard"
                ) from exc
            cctx = zstd.ZstdCompressor(level=level, threads=threads)
            return cctx.compress(cpio_bytes)

        if algo in ("gzip", "gz"):
            # Python gzip.compress takes compresslevel in 1..9
            gz_level = min(max(level, 1), 9) if level is not None else 9
            return gzip.compress(cpio_bytes, compresslevel=gz_level)

        if algo in ("xz", "lzma"):
            # Python lzma.compress takes preset in 0..9
            xz_level = min(max(level, 0), 9) if level is not None else 9
            return lzma.compress(cpio_bytes, preset=xz_level)

        if algo in ("none", "uncompressed", "raw"):
            return cpio_bytes

        raise ValueError(
            f"Unsupported compression algorithm: {compression!r}. "
            f"Supported options: 'zstd', 'gzip', 'xz', 'none'."
        )

    def to_initramfs(
        self,
        vfs: PosixVfs,
        compression: str = "zstd",
        level: int = 19,
        threads: int = 0,
    ) -> bytes:
        """
        Build a CPIO archive from the given PosixVfs, finalize it, and compress it.

        Parameters:
            vfs: The virtual filesystem containing the nodes to pack.
            compression: Compression algorithm ('zstd', 'gzip', 'xz', 'none').
            level: Compression level (default 19 for zstd, clamped for gzip/xz).
            threads: Worker threads for compression (0 = auto for zstd).

        Returns:
            The compressed (or raw) CPIO archive bytes suitable for kernel boot.
        """
        # If entries have not been added yet, add from the provided VFS
        if len(self._buffer) == 0 and not self._finalized:
            self.add_from_vfs(vfs)

        cpio_bytes = self.finalize()
        return self._compress(cpio_bytes, compression=compression, level=level, threads=threads)


# ======================================================================
# Standalone Builder Function
# ======================================================================

def build_initramfs(
    vfs: PosixVfs,
    compression: str = "zstd",
    level: int = 19,
    threads: int = 0,
) -> bytes:
    """
    Construct a complete, compressed SVR4 newc CPIO archive from a PosixVfs.

    Parameters:
        vfs: The PosixVfs holding the filesystem tree to serialize.
        compression: Compression format ('zstd', 'gzip', 'xz', or 'none').
        level: Compression level (default 19 for zstd).
        threads: Number of compression threads (0 = auto).

    Returns:
        The compressed binary initramfs image.
    """
    archiver = CpioArchiver()
    return archiver.to_initramfs(vfs, compression=compression, level=level, threads=threads)


# ======================================================================
# CPIO Parser & Deserializer
# ======================================================================

def decompress_initramfs(data: bytes) -> bytes:
    """
    Auto-detect the compression format of an initramfs payload and decompress it.

    Supports zstandard, gzip, xz, and uncompressed CPIO streams.
    """
    if len(data) < 6:
        raise CpioCorruptError("Data stream too short to identify format.")

    # Plain CPIO magic check
    if data[:6] in (CPIO_NEWC_MAGIC, CPIO_CRC_MAGIC):
        return data

    # Gzip magic: 1F 8B
    if data[:2] == b"\x1f\x8b":
        return gzip.decompress(data)

    # Zstandard magic: 28 B5 2F FD
    if data[:4] == b"\x28\xb5\x2f\xfd":
        try:
            import zstandard as zstd
        except ImportError as exc:
            raise RuntimeError(
                "The 'zstandard' library is required to decompress zstd initramfs."
            ) from exc
        dctx = zstd.ZstdDecompressor()
        return dctx.decompress(data, max_output_size=2 * 1024 * 1024 * 1024)

    # XZ magic: FD 37 7A 58 5A 00
    if data[:6] == b"\xfd7zXZ\x00":
        return lzma.decompress(data)

    raise CpioCorruptError(
        f"Unrecognised initramfs compression header: {data[:8].hex()} "
        "(expected zstd, gzip, xz, or raw 070701 CPIO)"
    )


def parse_cpio(data: bytes) -> List[CpioEntry]:
    """
    Parse an uncompressed SVR4 newc/crc CPIO byte stream into CpioEntry structures.

    Parameters:
        data: Raw uncompressed CPIO archive bytes.

    Returns:
        List of CpioEntry objects found in the archive, terminating at the TRAILER!!!.

    Raises:
        CpioCorruptError: If the archive data is truncated or corrupt.
        CpioHeaderError: If an entry has an invalid magic or cannot be parsed.
    """
    entries: List[CpioEntry] = []
    offset: int = 0
    total_len: int = len(data)

    while offset < total_len:
        # Check if remaining bytes can contain at least a header
        if offset + HEADER_SIZE > total_len:
            # Trailing zeros or padding at end of archive can be safely skipped
            tail = data[offset:]
            if tail == b"\x00" * len(tail):
                break
            raise CpioCorruptError(
                f"Truncated CPIO header at offset {offset}: "
                f"needed {HEADER_SIZE} bytes, available {len(tail)} bytes."
            )

        header_bytes = data[offset : offset + HEADER_SIZE]
        try:
            (
                magic,
                ino_hex,
                mode_hex,
                uid_hex,
                gid_hex,
                nlink_hex,
                mtime_hex,
                filesize_hex,
                devmaj_hex,
                devmin_hex,
                rdevmaj_hex,
                rdevmin_hex,
                namesize_hex,
                check_hex,
            ) = struct.unpack(HEADER_FORMAT, header_bytes)
        except struct.error as exc:
            raise CpioHeaderError(f"Malformed header struct at offset {offset}: {exc}") from exc

        if magic not in (CPIO_NEWC_MAGIC, CPIO_CRC_MAGIC):
            # Check for trailing zero padding
            if header_bytes == b"\x00" * HEADER_SIZE:
                break
            raise CpioHeaderError(
                f"Invalid CPIO magic at offset {offset}: {magic!r} "
                f"(expected {CPIO_NEWC_MAGIC!r} or {CPIO_CRC_MAGIC!r})"
            )

        try:
            ino = int(ino_hex, 16)
            mode = int(mode_hex, 16)
            uid = int(uid_hex, 16)
            gid = int(gid_hex, 16)
            nlink = int(nlink_hex, 16)
            mtime = int(mtime_hex, 16)
            filesize = int(filesize_hex, 16)
            devmaj = int(devmaj_hex, 16)
            devmin = int(devmin_hex, 16)
            rdevmaj = int(rdevmaj_hex, 16)
            rdevmin = int(rdevmin_hex, 16)
            namesize = int(namesize_hex, 16)
            check = int(check_hex, 16)
        except ValueError as exc:
            raise CpioHeaderError(f"Invalid hex integer in header at offset {offset}: {exc}") from exc

        offset += HEADER_SIZE

        # Validate and read filename
        if namesize <= 0:
            raise CpioCorruptError(f"Invalid namesize {namesize} at offset {offset}")

        if offset + namesize > total_len:
            raise CpioCorruptError(
                f"Truncated filename at offset {offset}: expected {namesize} bytes."
            )

        name_raw = data[offset : offset + namesize]
        offset += namesize

        # Skip filename padding
        name_pad = _pad4(HEADER_SIZE + namesize)
        offset += name_pad

        # Strip trailing NUL byte
        name_clean = name_raw.rstrip(b"\x00").decode("utf-8", errors="replace")

        # Check for TRAILER!!! sentinel
        if name_clean == TRAILER_NAME:
            entries.append(
                CpioEntry(
                    name=name_clean,
                    ino=ino,
                    mode=mode,
                    uid=uid,
                    gid=gid,
                    nlink=nlink,
                    mtime=mtime,
                    filesize=filesize,
                    devmajor=devmaj,
                    devminor=devmin,
                    rdevmajor=rdevmaj,
                    rdevminor=rdevmin,
                    check=check,
                    data=b"",
                )
            )
            break

        # Read file payload
        if filesize > 0:
            if offset + filesize > total_len:
                raise CpioCorruptError(
                    f"Truncated payload for '{name_clean}' at offset {offset}: "
                    f"expected {filesize} bytes, available {total_len - offset} bytes."
                )
            file_data = data[offset : offset + filesize]
            offset += filesize

            # Skip payload padding
            data_pad = _pad4(filesize)
            offset += data_pad
        else:
            file_data = b""

        entries.append(
            CpioEntry(
                name=name_clean,
                ino=ino,
                mode=mode,
                uid=uid,
                gid=gid,
                nlink=nlink,
                mtime=mtime,
                filesize=filesize,
                devmajor=devmaj,
                devminor=devmin,
                rdevmajor=rdevmaj,
                rdevminor=rdevmin,
                check=check,
                data=file_data,
            )
        )

    return entries


def extract_to_vfs(data: bytes, vfs: PosixVfs) -> int:
    """
    Extract entries from an uncompressed SVR4 CPIO stream directly into a PosixVfs.

    Parameters:
        data: Raw CPIO archive bytes.
        vfs: The PosixVfs tree into which files will be inserted.

    Returns:
        Number of nodes extracted into the VFS.
    """
    entries = parse_cpio(data)
    count = 0

    for entry in entries:
        if entry.is_trailer:
            continue

        # Normalise path back to leading slash
        vfs_path = "/" + entry.name.lstrip("./") if entry.name != "." else "/"

        type_bits = entry.mode & 0o170000
        perm_bits = entry.mode & 0o7777

        if type_bits == POSIX_TYPE_BITS[VfsNodeType.DIRECTORY]:
            vfs.mkdir(vfs_path, mode=perm_bits, uid=entry.uid, gid=entry.gid)
            node = vfs.get(vfs_path)
            if node:
                node.mtime = entry.mtime
                node.ino = entry.ino
                node.nlink = entry.nlink
            count += 1

        elif type_bits == POSIX_TYPE_BITS[VfsNodeType.REGULAR_FILE]:
            vfs.add_file(
                vfs_path,
                data=entry.data,
                mode=perm_bits,
                uid=entry.uid,
                gid=entry.gid,
                mtime=entry.mtime,
            )
            node = vfs.get(vfs_path)
            if node:
                node.ino = entry.ino
                node.nlink = entry.nlink
            count += 1

        elif type_bits == POSIX_TYPE_BITS[VfsNodeType.SYMLINK]:
            target = entry.data.decode("utf-8", errors="replace")
            vfs.add_symlink(
                vfs_path,
                target=target,
                uid=entry.uid,
                gid=entry.gid,
                mtime=entry.mtime,
            )
            node = vfs.get(vfs_path)
            if node:
                node.ino = entry.ino
                node.nlink = entry.nlink
            count += 1

        elif type_bits == POSIX_TYPE_BITS[VfsNodeType.CHAR_DEVICE]:
            vfs.add_char_device(
                vfs_path,
                major=entry.rdevmajor,
                minor=entry.rdevminor,
                mode=perm_bits,
                uid=entry.uid,
                gid=entry.gid,
            )
            node = vfs.get(vfs_path)
            if node:
                node.mtime = entry.mtime
                node.ino = entry.ino
            count += 1

        elif type_bits == POSIX_TYPE_BITS[VfsNodeType.BLOCK_DEVICE]:
            vfs.add_block_device(
                vfs_path,
                major=entry.rdevmajor,
                minor=entry.rdevminor,
                mode=perm_bits,
                uid=entry.uid,
                gid=entry.gid,
            )
            node = vfs.get(vfs_path)
            if node:
                node.mtime = entry.mtime
                node.ino = entry.ino
            count += 1

    return count
