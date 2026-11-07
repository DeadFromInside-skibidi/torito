"""
torito.squashfs — Complete SquashFS 4.0 Image Writer
=====================================================
Serializes a PosixVfs virtual filesystem tree into a production-grade,
spec-compliant SquashFS 4.0 filesystem binary image.

Features:
- Full SquashFS 4.0 superblock with all standard metadata tables.
- Compression support for zstd (compression_id=6) with automatic fallback
  to gzip/zlib (compression_id=1).
- Metadata block management (up to 8192 bytes uncompressed, 2-byte header
  with bit 15 indicating uncompressed payload).
- Inode table serialization for all POSIX types: regular files, directories,
  symbolic links, character devices, block devices, FIFOs, and sockets.
- Directory table layout with grouped directory headers and 16-bit deltas.
- Tail and small-file fragment packing to maximize space efficiency.
- ID table deduplication and indirect block pointer indexing.
- Export and xattr tables properly disabled with -1 sentinels.
- Deterministic, byte-level reproducibility with 4KB sector alignment.
"""

from __future__ import annotations

import math
import struct
import time
import zlib
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import (
    Any,
    Callable,
    Dict,
    List,
    Optional,
    Sequence,
    Set,
    Tuple,
    Union,
)

from torito.vfs import POSIX_TYPE_BITS, PosixVfs, VfsNode, VfsNodeType

try:
    import zstandard as zstd  # type: ignore[import-untyped]
    _HAS_ZSTD = True
except ImportError:
    zstd = None  # type: ignore[assignment]
    _HAS_ZSTD = False


# ==============================================================================
# SquashFS 4.0 On-Disk Constants & Bitmasks
# ==============================================================================

# Superblock Magic ('hsqs' in little-endian ASCII)
SQUASHFS_MAGIC: int = 0x73717368

# SquashFS 4.0 version numbers
SQUASHFS_MAJOR: int = 4
SQUASHFS_MINOR: int = 0

# Compression algorithm identifiers (Superblock.compression_id)
SQUASHFS_COMP_GZIP: int = 1
SQUASHFS_COMP_LZMA: int = 2
SQUASHFS_COMP_LZO: int = 3
SQUASHFS_COMP_XZ: int = 4
SQUASHFS_COMP_LZ4: int = 5
SQUASHFS_COMP_ZSTD: int = 6

# Inode and Directory Entry types
SQUASHFS_DIR_TYPE: int = 1
SQUASHFS_REG_TYPE: int = 2
SQUASHFS_SYMLINK_TYPE: int = 3
SQUASHFS_BLKDEV_TYPE: int = 4
SQUASHFS_CHRDEV_TYPE: int = 5
SQUASHFS_FIFO_TYPE: int = 6
SQUASHFS_SOCKET_TYPE: int = 7

# Extended Inode types (SquashFS 4.0 spec)
SQUASHFS_LDIR_TYPE: int = 8
SQUASHFS_LREG_TYPE: int = 9
SQUASHFS_LSYMLINK_TYPE: int = 10
SQUASHFS_LBLKDEV_TYPE: int = 11
SQUASHFS_LCHRDEV_TYPE: int = 12
SQUASHFS_LFIFO_TYPE: int = 13
SQUASHFS_LSOCKET_TYPE: int = 14

# Map VfsNodeType to SquashFS 4.0 Inode / Directory Entry types
VFS_TO_SQUASHFS_TYPE: Dict[VfsNodeType, int] = {
    VfsNodeType.DIRECTORY: SQUASHFS_DIR_TYPE,       # 1
    VfsNodeType.REGULAR_FILE: SQUASHFS_REG_TYPE,   # 2
    VfsNodeType.SYMLINK: SQUASHFS_SYMLINK_TYPE,     # 3
    VfsNodeType.BLOCK_DEVICE: SQUASHFS_BLKDEV_TYPE, # 4
    VfsNodeType.CHAR_DEVICE: SQUASHFS_CHRDEV_TYPE,   # 5
    VfsNodeType.FIFO: SQUASHFS_FIFO_TYPE,           # 6
    VfsNodeType.SOCKET: SQUASHFS_SOCKET_TYPE,       # 7
}

# Superblock flags
SQUASHFS_FLAG_UNCOMPRESSED_INODES: int = 0x0001
SQUASHFS_FLAG_UNCOMPRESSED_DATA: int = 0x0002
SQUASHFS_FLAG_CHECK: int = 0x0004
SQUASHFS_FLAG_UNCOMPRESSED_FRAGMENTS: int = 0x0008
SQUASHFS_FLAG_NO_FRAG: int = 0x0010
SQUASHFS_FLAG_ALWAYS_FRAG: int = 0x0020
SQUASHFS_FLAG_DUPLICATE: int = 0x0040
SQUASHFS_FLAG_EXPORT: int = 0x0080
SQUASHFS_FLAG_UNCOMPRESSED_XATTRS: int = 0x0100
SQUASHFS_FLAG_NO_XATTR: int = 0x0200
SQUASHFS_FLAG_COMP_OPT: int = 0x0400

# Metadata sizing & limits
SQUASHFS_METADATA_SIZE: int = 8192
SQUASHFS_METADATA_UNCOMPRESSED_BIT: int = 0x8000  # Bit 15 in metadata length

# Data block sizing & limits
SQUASHFS_DATA_BLOCK_UNCOMPRESSED_BIT: int = 0x01000000  # Bit 24 in data block length

# Sentinel constants
SQUASHFS_INVALID_FRAG: int = 0xFFFFFFFF
SQUASHFS_INVALID_BLK: int = -1

# Maximum directory entries per squashfs_dir_header
SQUASHFS_MAX_DIR_HEADER_ENTRIES: int = 256

# Alignment requirements
SQUASHFS_SECTOR_ALIGNMENT: int = 4096


# ==============================================================================
# Helper: MetadataBuffer
# ==============================================================================

class MetadataBuffer:
    """
    Manages a stream of SquashFS metadata blocks.

    SquashFS metadata is partitioned into uncompressed blocks of up to 8192 bytes.
    Each block on disk is preceded by a 2-byte little-endian header:
      - Bit 15: set if data is stored uncompressed
      - Bits 0-14: byte length of the payload following the header
    """

    def __init__(self, compressor: Callable[[bytes], Tuple[bytes, bool]]) -> None:
        self._compressor = compressor
        self._uncompressed: bytearray = bytearray()
        self._output: bytearray = bytearray()

    @property
    def output_size(self) -> int:
        """Current number of serialized bytes written to the metadata output stream."""
        return len(self._output)

    def write(self, data: bytes) -> Tuple[int, int]:
        """
        Append uncompressed metadata bytes, chunking into 8192-byte blocks as needed.

        Returns:
            Tuple[int, int]: (block_start_offset, offset_within_block)
            - block_start_offset: Byte offset relative to table start where the
              first metadata block containing this data begins.
            - offset_within_block: Byte offset within that uncompressed block.
        """
        if not data:
            return (len(self._output), len(self._uncompressed))

        # If data cannot fit in the remaining space of the current block, flush
        if len(self._uncompressed) + len(data) > SQUASHFS_METADATA_SIZE:
            self._flush_current()

        start_block = len(self._output)
        offset_within_block = len(self._uncompressed)

        # Handle data that may itself be larger than SQUASHFS_METADATA_SIZE
        remaining = data
        while remaining:
            space_left = SQUASHFS_METADATA_SIZE - len(self._uncompressed)
            chunk = remaining[:space_left]
            self._uncompressed.extend(chunk)
            remaining = remaining[space_left:]

            if len(self._uncompressed) == SQUASHFS_METADATA_SIZE and remaining:
                self._flush_current()

        return (start_block, offset_within_block)

    def _flush_current(self) -> None:
        """Compress and flush the active uncompressed buffer to output."""
        if not self._uncompressed:
            return

        raw_block = bytes(self._uncompressed)
        compressed, is_uncompressed = self._compressor(raw_block)

        if is_uncompressed:
            header_val = len(raw_block) | SQUASHFS_METADATA_UNCOMPRESSED_BIT
            payload = raw_block
        else:
            header_val = len(compressed)
            payload = compressed

        self._output.extend(struct.pack("<H", header_val))
        self._output.extend(payload)
        self._uncompressed.clear()

    def flush(self) -> bytes:
        """Flush any remaining buffered data and return the full compressed stream."""
        self._flush_current()
        return bytes(self._output)

    def clear(self) -> None:
        """Reset the buffer state to empty."""
        self._uncompressed.clear()
        self._output.clear()


# ==============================================================================
# Main SquashFSWriter Implementation
# ==============================================================================

class SquashFSWriter:
    """
    Serializes a PosixVfs tree into a complete SquashFS 4.0 filesystem image.
    """

    def __init__(self, block_size: int = 131072, compression: str = "zstd") -> None:
        """
        Initialize the SquashFS writer with block size and compression algorithm.

        Args:
            block_size: Data block size in bytes (must be power of 2 between 4KB and 1MB).
            compression: Compression algorithm ('zstd' or 'gzip').
        """
        # Validate block size
        if block_size < 4096 or block_size > 1048576 or (block_size & (block_size - 1)) != 0:
            raise ValueError(
                f"block_size must be a power of 2 between 4096 and 1048576, got {block_size}"
            )
        self.block_size: int = block_size
        self.block_log: int = int(math.log2(block_size))

        # Validate compression
        comp_lower = compression.lower()
        if comp_lower not in ("zstd", "gzip"):
            raise ValueError(
                f"Unsupported compression '{compression}', must be 'zstd' or 'gzip'"
            )

        # Fallback to gzip if zstandard library is not available
        if comp_lower == "zstd" and not _HAS_ZSTD:
            self.compression: str = "gzip"
            self.compression_id: int = SQUASHFS_COMP_GZIP
        elif comp_lower == "zstd":
            self.compression = "zstd"
            self.compression_id = SQUASHFS_COMP_ZSTD
            self._zstd_compressor = zstd.ZstdCompressor(level=3)
        else:
            self.compression = "gzip"
            self.compression_id = SQUASHFS_COMP_GZIP
            self._zstd_compressor = None

        # Internal active metadata writer for direct metadata block writes
        self._active_metadata_writer: MetadataBuffer = MetadataBuffer(self._compress_data)
        self._last_id_table_start: int = SQUASHFS_INVALID_BLK

    # --------------------------------------------------------------------------
    # Compression Helper
    # --------------------------------------------------------------------------

    def _compress_data(self, data: bytes) -> Tuple[bytes, bool]:
        """
        Compress a block of data using the configured compression algorithm.

        Returns:
            Tuple[bytes, bool]: (compressed_data, is_uncompressed_flag)
            - If compression fails to shrink the payload, returns (data, True).
            - Otherwise returns (compressed_bytes, False).
        """
        if not data:
            return (b"", True)

        try:
            if self.compression == "zstd" and _HAS_ZSTD and self._zstd_compressor is not None:
                compressed = self._zstd_compressor.compress(data)
            else:
                compressed = zlib.compress(data, level=9)
        except Exception:
            return (data, True)

        if len(compressed) < len(data):
            return (compressed, False)
        return (data, True)

    # --------------------------------------------------------------------------
    # Metadata Block Writing
    # --------------------------------------------------------------------------

    def _write_metadata_block(
        self,
        data: bytes,
        writer: Optional[MetadataBuffer] = None,
    ) -> Tuple[int, int]:
        """
        Write a metadata block to the metadata buffer.

        Returns:
            Tuple[int, int]: (block_start_offset, offset_within_block)
            Metadata blocks are max 8192 bytes uncompressed.
        """
        target_writer = writer if writer is not None else self._active_metadata_writer
        return target_writer.write(data)

    # --------------------------------------------------------------------------
    # Inode Serialization
    # --------------------------------------------------------------------------

    def _build_inode(
        self,
        path: str,
        node: VfsNode,
        inode_number: int = 1,
        id_to_index: Optional[Dict[int, int]] = None,
        parent_inode: int = 1,
        start_block: int = 0,
        offset: int = 0,
        fragment_index: int = SQUASHFS_INVALID_FRAG,
        file_size: Optional[int] = None,
        block_sizes: Optional[List[int]] = None,
    ) -> bytes:
        """
        Serialize a single VFS inode into SquashFS 4.0 binary representation.

        Args:
            path: Normalized path in the VFS tree.
            node: VfsNode to serialize.
            inode_number: Assigned unique inode number (>= 1).
            id_to_index: Mapping of raw UID/GID values to ID table indices.
            parent_inode: Inode number of parent directory (for directories).
            start_block: Starting block offset (data block offset or directory table offset).
            offset: Offset within uncompressed block (fragment offset or dir offset).
            fragment_index: Fragment table entry index (for regular files).
            file_size: Explicit file/entry size override.
            block_sizes: List of packed uint32 block sizes (for regular files).

        Returns:
            bytes: Serialized inode record.
        """
        id_map = id_to_index or {}
        uid_idx = id_map.get(node.uid, 0)
        gid_idx = id_map.get(node.gid, 0)
        permissions = node.mode & 0o7777
        mtime = int(node.mtime)

        # ----------------------------------------------------------------------
        # 1. Directory (Type 1)
        # ----------------------------------------------------------------------
        if node.node_type == VfsNodeType.DIRECTORY:
            sq_type = SQUASHFS_DIR_TYPE
            common_hdr = struct.pack(
                "<4H2I",
                sq_type,
                permissions,
                uid_idx,
                gid_idx,
                mtime,
                inode_number,
            )
            dir_fsize = file_size if file_size is not None else 3
            # Limit file_size to uint16 bounds as required by basic dir inode
            clamped_fsize = dir_fsize & 0xFFFF
            payload = struct.pack(
                "<2I2HI",
                start_block,
                node.nlink,
                clamped_fsize,
                offset & 0xFFFF,
                parent_inode,
            )
            return common_hdr + payload

        # ----------------------------------------------------------------------
        # 2. Regular File (Type 2)
        # ----------------------------------------------------------------------
        if node.node_type == VfsNodeType.REGULAR_FILE:
            sq_type = SQUASHFS_REG_TYPE
            common_hdr = struct.pack(
                "<4H2I",
                sq_type,
                permissions,
                uid_idx,
                gid_idx,
                mtime,
                inode_number,
            )
            actual_fsize = len(node.data) if file_size is None else file_size
            payload = struct.pack(
                "<4I",
                start_block,
                fragment_index,
                offset,
                actual_fsize,
            )
            if block_sizes:
                payload += b"".join(struct.pack("<I", sz) for sz in block_sizes)
            return common_hdr + payload

        # ----------------------------------------------------------------------
        # 3. Symlink (Type 3)
        # ----------------------------------------------------------------------
        if node.node_type == VfsNodeType.SYMLINK:
            sq_type = SQUASHFS_SYMLINK_TYPE
            common_hdr = struct.pack(
                "<4H2I",
                sq_type,
                permissions,
                uid_idx,
                gid_idx,
                mtime,
                inode_number,
            )
            target_bytes = node.link_target.encode("utf-8")
            payload = struct.pack("<2I", node.nlink, len(target_bytes)) + target_bytes
            return common_hdr + payload

        # ----------------------------------------------------------------------
        # 4. Block Device (Type 4)
        # ----------------------------------------------------------------------
        if node.node_type == VfsNodeType.BLOCK_DEVICE:
            sq_type = SQUASHFS_BLKDEV_TYPE
            common_hdr = struct.pack(
                "<4H2I",
                sq_type,
                permissions,
                uid_idx,
                gid_idx,
                mtime,
                inode_number,
            )
            rdev = (
                (node.dev_major << 8)
                | (node.dev_minor & 0xFF)
                | ((node.dev_minor & ~0xFF) << 12)
            )
            payload = struct.pack("<2I", node.nlink, rdev)
            return common_hdr + payload

        # ----------------------------------------------------------------------
        # 5. Character Device (Type 5)
        # ----------------------------------------------------------------------
        if node.node_type == VfsNodeType.CHAR_DEVICE:
            sq_type = SQUASHFS_CHRDEV_TYPE
            common_hdr = struct.pack(
                "<4H2I",
                sq_type,
                permissions,
                uid_idx,
                gid_idx,
                mtime,
                inode_number,
            )
            rdev = (
                (node.dev_major << 8)
                | (node.dev_minor & 0xFF)
                | ((node.dev_minor & ~0xFF) << 12)
            )
            payload = struct.pack("<2I", node.nlink, rdev)
            return common_hdr + payload

        # ----------------------------------------------------------------------
        # 6. FIFO (Type 6)
        # ----------------------------------------------------------------------
        if node.node_type == VfsNodeType.FIFO:
            sq_type = SQUASHFS_FIFO_TYPE
            common_hdr = struct.pack(
                "<4H2I",
                sq_type,
                permissions,
                uid_idx,
                gid_idx,
                mtime,
                inode_number,
            )
            payload = struct.pack("<I", node.nlink)
            return common_hdr + payload

        # ----------------------------------------------------------------------
        # 7. Socket (Type 7)
        # ----------------------------------------------------------------------
        if node.node_type == VfsNodeType.SOCKET:
            sq_type = SQUASHFS_SOCKET_TYPE
            common_hdr = struct.pack(
                "<4H2I",
                sq_type,
                permissions,
                uid_idx,
                gid_idx,
                mtime,
                inode_number,
            )
            payload = struct.pack("<I", node.nlink)
            return common_hdr + payload

        raise ValueError(f"Unsupported VfsNodeType: {node.node_type} for path '{path}'")

    # --------------------------------------------------------------------------
    # Directory Entries Serialization
    # --------------------------------------------------------------------------

    def _build_directory_entries(self, entries: List[Any]) -> bytes:
        """
        Build the directory entry table for a single directory.

        Entries can be provided as tuples or dictionaries:
          (name: str, entry_type: int, inode_number: int, inode_block: int, inode_offset: int)
        or
          {'name': ..., 'type': ..., 'inode_number': ..., 'inode_block': ..., 'inode_offset': ...}

        Returns:
            bytes: Serialized directory headers and entries.
        """
        if not entries:
            return b""

        # Normalize entries into (name, type, inode_number, inode_block, inode_offset)
        parsed: List[Tuple[str, int, int, int, int]] = []
        for e in entries:
            if isinstance(e, tuple):
                name, etype, ino, blk, off = e[0], int(e[1]), int(e[2]), int(e[3]), int(e[4])
            elif isinstance(e, dict):
                name = str(e["name"])
                etype = int(e.get("type", e.get("entry_type", 1)))
                ino = int(e.get("inode_number", e.get("ino", 1)))
                blk = int(e.get("inode_block", e.get("start_block", 0)))
                off = int(e.get("inode_offset", e.get("offset", 0)))
            else:
                name = str(getattr(e, "name"))
                etype = int(getattr(e, "type", getattr(e, "entry_type", 1)))
                ino = int(getattr(e, "inode_number", getattr(e, "ino", 1)))
                blk = int(getattr(e, "inode_block", getattr(e, "start_block", 0)))
                off = int(getattr(e, "inode_offset", getattr(e, "offset", 0)))
            parsed.append((name, etype, ino, blk, off))

        # Sort alphabetically by name
        parsed.sort(key=lambda item: item[0])

        # Group entries into squashfs_dir_header batches
        groups: List[List[Tuple[str, int, int, int, int]]] = []
        current_group: List[Tuple[str, int, int, int, int]] = []

        for item in parsed:
            name, etype, ino, blk, off = item
            if not current_group:
                current_group.append(item)
                continue

            base_blk = current_group[0][3]
            base_ino = current_group[0][2]

            # In SquashFS, entries under the same header must:
            # 1. Share the same inode metadata start_block
            # 2. Have inode_number delta that fits in a signed 16-bit integer
            # 3. Contain at most 256 entries per header
            can_add = (
                blk == base_blk
                and -32768 <= (ino - base_ino) <= 32767
                and len(current_group) < SQUASHFS_MAX_DIR_HEADER_ENTRIES
            )

            if can_add:
                current_group.append(item)
            else:
                groups.append(current_group)
                current_group = [item]

        if current_group:
            groups.append(current_group)

        # Serialize headers and entries
        out = bytearray()
        for grp in groups:
            count_minus_1 = len(grp) - 1
            base_blk = grp[0][3]
            base_ino = grp[0][2]

            # Header: uint32 count, uint32 start_block, uint32 inode_number (12 bytes)
            out.extend(struct.pack("<3I", count_minus_1, base_blk, base_ino))

            for name, etype, ino, blk, off in grp:
                name_bytes = name.encode("utf-8")
                if len(name_bytes) > 256:
                    name_bytes = name_bytes[:256]
                name_size_minus_1 = len(name_bytes) - 1
                inode_delta = ino - base_ino

                # Entry: uint16 offset, int16 inode_offset, uint16 type, uint16 name_size (8 bytes)
                entry_hdr = struct.pack(
                    "<HhHH",
                    off & 0xFFFF,
                    inode_delta,
                    etype,
                    name_size_minus_1,
                )
                out.extend(entry_hdr + name_bytes)

        return bytes(out)

    # --------------------------------------------------------------------------
    # ID Table Packing
    # --------------------------------------------------------------------------

    def _pack_id_table(self, id_list: List[int], start_offset: int = 0) -> bytes:
        """
        Pack the deduplicated UID/GID lookup table into metadata blocks
        and create the indirect block pointer array.

        Args:
            id_list: List of deduplicated integer UIDs/GIDs.
            start_offset: Physical byte offset in image where the ID table will begin.

        Returns:
            bytes: Serialized metadata blocks followed by uint64 index table.
        """
        clean_ids = sorted(set(id_list)) if id_list else [0]

        # Each ID is uint32 (4 bytes). An 8192-byte metadata block holds up to 2048 IDs.
        metadata_blocks: List[bytes] = []
        for i in range(0, len(clean_ids), 2048):
            chunk = clean_ids[i : i + 2048]
            chunk_raw = b"".join(struct.pack("<I", uid) for uid in chunk)
            comp, is_uncomp = self._compress_data(chunk_raw)

            if is_uncomp:
                hdr = len(chunk_raw) | SQUASHFS_METADATA_UNCOMPRESSED_BIT
                payload = chunk_raw
            else:
                hdr = len(comp)
                payload = comp

            metadata_blocks.append(struct.pack("<H", hdr) + payload)

        # Compute uint64 pointers to each metadata block
        curr_offset = start_offset
        block_pointers: List[int] = []
        for blk in metadata_blocks:
            block_pointers.append(curr_offset)
            curr_offset += len(blk)

        # The ID index table begins immediately after the metadata blocks
        self._last_id_table_start = curr_offset

        index_table = b"".join(struct.pack("<Q", ptr) for ptr in block_pointers)
        return b"".join(metadata_blocks) + index_table

    # --------------------------------------------------------------------------
    # Master Build Method
    # --------------------------------------------------------------------------

    def build(self, vfs: PosixVfs) -> bytes:
        """
        Serialize a PosixVfs tree into a complete SquashFS 4.0 binary image.

        Args:
            vfs: PosixVfs instance to serialize.

        Returns:
            bytes: Complete SquashFS 4.0 filesystem image aligned to 4KB.
        """
        # Ensure root directory exists and directory nlink counts are correct
        if not vfs.exists("/"):
            vfs.mkdir("/", mode=0o755)
        vfs.fixup_nlinks()

        # Step 1: Collect sorted nodes from VFS
        nodes = list(vfs.walk_sorted())
        if not nodes:
            vfs.mkdir("/", mode=0o755)
            nodes = list(vfs.walk_sorted())

        # Step 2: Collect UID/GID table and assign inode numbers
        id_list, id_to_index = vfs.collect_id_table()
        if not id_list:
            id_list = [0]
            id_to_index = {0: 0}

        # Inode numbers start at 1. Assign root inode number = 1.
        inode_numbers: Dict[str, int] = {"/": 1}
        next_ino = 2
        for path, node in nodes:
            if path != "/":
                inode_numbers[path] = next_ino
                next_ino += 1

        inode_count = len(nodes)

        # Step 3: Compress regular file data blocks and build fragment table
        # Preallocate image buffer with 96-byte placeholder for superblock
        image = bytearray(96)

        data_area_start = 96
        data_area = bytearray()

        fragment_entries: List[Tuple[int, int]] = []  # (start_offset, packed_size)
        current_frag_buf = bytearray()

        # Map file path -> (start_block, fragment_index, fragment_offset, file_size, block_sizes)
        file_data_map: Dict[str, Tuple[int, int, int, int, List[int]]] = {}

        for path, node in nodes:
            if node.node_type != VfsNodeType.REGULAR_FILE:
                continue

            file_data = node.data
            fsize = len(file_data)

            # Empty file (0 bytes) has no data blocks and invalid fragment
            if fsize == 0:
                file_data_map[path] = (0, SQUASHFS_INVALID_FRAG, 0, 0, [])
                continue

            # Small file (< block_size): pack completely into fragment buffer
            if fsize < self.block_size:
                if len(current_frag_buf) + fsize > self.block_size:
                    # Flush fragment buffer to data area
                    f_comp, f_uncomp = self._compress_data(bytes(current_frag_buf))
                    frag_sz_flag = len(f_comp) | (
                        SQUASHFS_DATA_BLOCK_UNCOMPRESSED_BIT if f_uncomp else 0
                    )
                    frag_start = data_area_start + len(data_area)
                    data_area.extend(f_comp)
                    fragment_entries.append((frag_start, frag_sz_flag))
                    current_frag_buf.clear()

                frag_idx = len(fragment_entries)
                frag_off = len(current_frag_buf)
                current_frag_buf.extend(file_data)
                file_data_map[path] = (0, frag_idx, frag_off, fsize, [])

            else:
                # Large file (>= block_size): split into full blocks + optional tail
                full_blocks = fsize // self.block_size
                tail_len = fsize % self.block_size
                file_start_block = data_area_start + len(data_area)
                block_sizes: List[int] = []

                for b_idx in range(full_blocks):
                    chunk = file_data[b_idx * self.block_size : (b_idx + 1) * self.block_size]
                    c_comp, c_uncomp = self._compress_data(chunk)
                    c_sz_flag = len(c_comp) | (
                        SQUASHFS_DATA_BLOCK_UNCOMPRESSED_BIT if c_uncomp else 0
                    )
                    block_sizes.append(c_sz_flag)
                    data_area.extend(c_comp)

                if tail_len > 0:
                    tail_data = file_data[full_blocks * self.block_size :]
                    if len(current_frag_buf) + tail_len > self.block_size:
                        f_comp, f_uncomp = self._compress_data(bytes(current_frag_buf))
                        frag_sz_flag = len(f_comp) | (
                            SQUASHFS_DATA_BLOCK_UNCOMPRESSED_BIT if f_uncomp else 0
                        )
                        frag_start = data_area_start + len(data_area)
                        data_area.extend(f_comp)
                        fragment_entries.append((frag_start, frag_sz_flag))
                        current_frag_buf.clear()

                    frag_idx = len(fragment_entries)
                    frag_off = len(current_frag_buf)
                    current_frag_buf.extend(tail_data)
                    file_data_map[path] = (
                        file_start_block,
                        frag_idx,
                        frag_off,
                        fsize,
                        block_sizes,
                    )
                else:
                    file_data_map[path] = (
                        file_start_block,
                        SQUASHFS_INVALID_FRAG,
                        0,
                        fsize,
                        block_sizes,
                    )

        # Flush any remaining fragments
        if current_frag_buf:
            f_comp, f_uncomp = self._compress_data(bytes(current_frag_buf))
            frag_sz_flag = len(f_comp) | (
                SQUASHFS_DATA_BLOCK_UNCOMPRESSED_BIT if f_uncomp else 0
            )
            frag_start = data_area_start + len(data_area)
            data_area.extend(f_comp)
            fragment_entries.append((frag_start, frag_sz_flag))
            current_frag_buf.clear()

        # Append data blocks to image immediately after superblock
        image.extend(data_area)

        # Step 4 & 5: Build Inode Table and Directory Table
        # Using post-order (depth-descending) traversal ensures child inodes are
        # committed and referenced before their parents need their locations.
        inode_writer = MetadataBuffer(self._compress_data)
        dir_writer = MetadataBuffer(self._compress_data)

        # Set active writer for internal methods
        self._active_metadata_writer = inode_writer

        # Track on-disk inode references: path -> (block_start, offset_within_block)
        inode_refs: Dict[str, Tuple[int, int]] = {}

        # Collect directories and sort by depth descending
        dir_paths = [p for p, n in nodes if n.node_type == VfsNodeType.DIRECTORY]
        dir_paths_sorted = sorted(
            dir_paths,
            key=lambda p: (-(len(p.strip("/").split("/")) if p != "/" else 0), p),
        )

        for dir_path in dir_paths_sorted:
            # 1. Process all immediate leaf children of this directory
            child_names = vfs.list_dir(dir_path)
            prefix = dir_path.rstrip("/") + "/"

            for cname in child_names:
                cpath = prefix + cname
                cnode = vfs.get(cpath)
                if cnode is None:
                    continue

                # If child is not a directory and hasn't been written yet, write its inode
                if cnode.node_type != VfsNodeType.DIRECTORY and cpath not in inode_refs:
                    c_ino = inode_numbers[cpath]

                    if cnode.node_type == VfsNodeType.REGULAR_FILE:
                        sb, fi, fo, fs, bs = file_data_map[cpath]
                        ino_bytes = self._build_inode(
                            cpath,
                            cnode,
                            inode_number=c_ino,
                            id_to_index=id_to_index,
                            start_block=sb,
                            offset=fo,
                            fragment_index=fi,
                            file_size=fs,
                            block_sizes=bs,
                        )
                    else:
                        ino_bytes = self._build_inode(
                            cpath,
                            cnode,
                            inode_number=c_ino,
                            id_to_index=id_to_index,
                        )

                    blk, off = self._write_metadata_block(ino_bytes, writer=inode_writer)
                    inode_refs[cpath] = (blk, off)

            # 2. Build directory entry table for dir_path
            dir_entries_payload: List[Tuple[str, int, int, int, int]] = []
            for cname in child_names:
                cpath = prefix + cname
                cnode = vfs.get(cpath)
                if cnode is None or cpath not in inode_refs:
                    continue
                c_ino = inode_numbers[cpath]
                c_blk, c_off = inode_refs[cpath]
                sq_type = VFS_TO_SQUASHFS_TYPE.get(cnode.node_type, SQUASHFS_REG_TYPE)
                dir_entries_payload.append(
                    (cname, sq_type, c_ino, c_blk, c_off)
                )

            if dir_entries_payload:
                dir_raw = self._build_directory_entries(dir_entries_payload)
                dir_blk, dir_off = self._write_metadata_block(dir_raw, writer=dir_writer)
                # SquashFS quirk: directory file_size is uncompressed entry table size + 3
                dir_fsize = len(dir_raw) + 3
            else:
                # Empty directory
                dir_blk = 0
                dir_off = 0
                dir_fsize = 3

            # 3. Build and write directory inode
            d_node = vfs.get(dir_path)
            d_ino = inode_numbers[dir_path]
            if dir_path == "/":
                parent_ino = d_ino
            else:
                parent_path = str(PurePosixPath(dir_path).parent)
                parent_ino = inode_numbers.get(parent_path, 1)

            dir_ino_bytes = self._build_inode(
                dir_path,
                d_node,  # type: ignore[arg-type]
                inode_number=d_ino,
                id_to_index=id_to_index,
                parent_inode=parent_ino,
                start_block=dir_blk,
                offset=dir_off,
                file_size=dir_fsize,
            )
            d_blk, d_off = self._write_metadata_block(dir_ino_bytes, writer=inode_writer)
            inode_refs[dir_path] = (d_blk, d_off)

        # Defensive check: ensure every node has an inode written
        for path, node in nodes:
            if path not in inode_refs:
                n_ino = inode_numbers.get(path, next_ino)
                ino_bytes = self._build_inode(
                    path,
                    node,
                    inode_number=n_ino,
                    id_to_index=id_to_index,
                )
                blk, off = self._write_metadata_block(ino_bytes, writer=inode_writer)
                inode_refs[path] = (blk, off)

        # Flush metadata tables
        inode_table_bytes = inode_writer.flush()
        directory_table_bytes = dir_writer.flush()

        # Step 6: Append Inode Table & Directory Table
        inode_table_start = len(image)
        image.extend(inode_table_bytes)

        directory_table_start = len(image)
        image.extend(directory_table_bytes)

        # Step 7: Build Fragment Table
        if not fragment_entries:
            fragment_table_start = SQUASHFS_INVALID_BLK
            fragment_entry_count = 0
        else:
            fragment_entry_count = len(fragment_entries)
            frag_meta_blocks: List[bytes] = []

            # 512 entries per 8192-byte metadata block (each entry is 16 bytes: <QII)
            for i in range(0, len(fragment_entries), 512):
                chunk = fragment_entries[i : i + 512]
                raw_chunk = b"".join(
                    struct.pack("<QII", fe[0], fe[1], 0) for fe in chunk
                )
                comp, is_uncomp = self._compress_data(raw_chunk)
                if is_uncomp:
                    hdr = len(raw_chunk) | SQUASHFS_METADATA_UNCOMPRESSED_BIT
                    payload = raw_chunk
                else:
                    hdr = len(comp)
                    payload = comp
                frag_meta_blocks.append(struct.pack("<H", hdr) + payload)

            # Record byte pointers to each fragment metadata block
            curr_pos = len(image)
            frag_block_ptrs: List[int] = []
            for blk in frag_meta_blocks:
                frag_block_ptrs.append(curr_pos)
                curr_pos += len(blk)

            # Append fragment metadata blocks
            for blk in frag_meta_blocks:
                image.extend(blk)

            # Fragment table start points to the uint64 index table
            fragment_table_start = len(image)
            image.extend(b"".join(struct.pack("<Q", ptr) for ptr in frag_block_ptrs))

        # Step 8: Build ID Table
        id_table_start_offset = len(image)
        id_table_data = self._pack_id_table(id_list, start_offset=id_table_start_offset)
        image.extend(id_table_data)
        id_table_start = self._last_id_table_start

        # Step 9: Export Table and Xattr Table (disabled)
        export_table_start = SQUASHFS_INVALID_BLK
        xattr_id_table_start = SQUASHFS_INVALID_BLK

        # Step 10: Compute root inode reference
        root_blk, root_off = inode_refs["/"]
        root_inode_ref = (root_blk << 16) | (root_off & 0xFFFF)

        # Step 11: Compute bytes used & assemble Superblock
        bytes_used = len(image)

        # Determine superblock flags
        flags = SQUASHFS_FLAG_NO_XATTR
        if fragment_entry_count == 0:
            flags |= SQUASHFS_FLAG_NO_FRAG

        superblock = struct.pack(
            "<5I 6H 8q",
            SQUASHFS_MAGIC,
            inode_count,
            vfs._epoch,
            self.block_size,
            fragment_entry_count,
            self.compression_id,
            self.block_log,
            flags,
            len(id_list),
            SQUASHFS_MAJOR,
            SQUASHFS_MINOR,
            root_inode_ref,
            bytes_used,
            id_table_start,
            xattr_id_table_start,
            inode_table_start,
            directory_table_start,
            fragment_table_start,
            export_table_start,
        )
        image[0:96] = superblock

        # Step 12: Pad to 4KB alignment at the end
        pad_remainder = len(image) % SQUASHFS_SECTOR_ALIGNMENT
        if pad_remainder != 0:
            image.extend(b"\x00" * (SQUASHFS_SECTOR_ALIGNMENT - pad_remainder))

        return bytes(image)


# ==============================================================================
# Standalone Builder Function
# ==============================================================================

def build_squashfs(
    vfs: PosixVfs,
    block_size: int = 131072,
    compression: str = "zstd",
) -> bytes:
    """
    Serialize a PosixVfs virtual filesystem into a valid SquashFS 4.0 binary image.

    Args:
        vfs: The PosixVfs tree to serialize.
        block_size: Uncompressed data block size in bytes (must be power of 2, default 128KB).
        compression: "zstd" (default) or "gzip".

    Returns:
        bytes: Complete SquashFS 4.0 filesystem image aligned to 4KB.
    """
    writer = SquashFSWriter(block_size=block_size, compression=compression)
    return writer.build(vfs)
