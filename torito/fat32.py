"""
torito.fat32 — Pure In-Memory FAT32 Filesystem Formatter and Writer
===================================================================
Constructs a complete, specification-compliant FAT32 disk image entirely
in memory (as a bytearray), without OS mount calls, loopback devices,
or external tools (mkfs.vfat/mtools).

Used primarily to build the EFI System Partition (ESP / efiboot.img)
required for UEFI-bootable ISOs (El Torito EFI boot catalog).
"""

from __future__ import annotations

import math
import os
import struct
import time
import zlib
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple, Union

from torito.vfs import POSIX_TYPE_BITS, PosixVfs, VfsNode, VfsNodeType

__all__ = [
    "ATTR_READ_ONLY",
    "ATTR_HIDDEN",
    "ATTR_SYSTEM",
    "ATTR_VOLUME_ID",
    "ATTR_DIRECTORY",
    "ATTR_ARCHIVE",
    "ATTR_LONG_NAME",
    "DirEntryInfo",
    "Fat32Image",
    "build_efi_esp",
]

# Standard FAT File Attribute Flags
ATTR_READ_ONLY: int = 0x01
ATTR_HIDDEN: int = 0x02
ATTR_SYSTEM: int = 0x04
ATTR_VOLUME_ID: int = 0x08
ATTR_DIRECTORY: int = 0x10
ATTR_ARCHIVE: int = 0x20
ATTR_LONG_NAME: int = 0x0F  # READ_ONLY | HIDDEN | SYSTEM | VOLUME_ID

# Characters valid in standard 8.3 short filenames (ASCII uppercase)
VALID_SHORT_CHARS: Set[int] = set(
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!#$%&'()-@^_`{}~"
)

# Struct format string for 512-byte FAT32 Boot Sector (BPB)
# Field Breakdown (Little Endian '<'):
# 0..3:   jmp_boot (3s)       -> b"\xeb\x58\x90"
# 3..11:  oem_name (8s)       -> b"MSWIN4.1"
# 11..13: bytes_per_sec (H)   -> 512
# 13..14: sec_per_clus (B)    -> 8 (or calculated)
# 14..16: rsvd_sec_cnt (H)    -> 32
# 16..17: num_fats (B)        -> 2
# 17..19: root_ent_cnt (H)    -> 0 (must be 0 for FAT32)
# 19..21: tot_sec_16 (H)      -> 0 (must be 0 for FAT32)
# 21..22: media (B)           -> 0xF8 (fixed disk)
# 22..24: fat_sz_16 (H)       -> 0 (must be 0 for FAT32)
# 24..26: sec_per_trk (H)     -> 63
# 26..28: num_heads (H)       -> 255
# 28..32: hidd_sec (I)        -> 0
# 32..36: tot_sec_32 (I)      -> total_sectors
# 36..40: fat_sz_32 (I)       -> fat_size_sectors
# 40..42: ext_flags (H)       -> 0x0000 (mirroring active)
# 42..44: fs_ver (H)          -> 0x0000 (0.0)
# 44..48: root_clus (I)       -> 2 (first data cluster)
# 48..50: fs_info (H)         -> 1
# 50..52: bk_boot_sec (H)     -> 6
# 52..64: reserved (12s)      -> zeros
# 64..65: drv_num (B)         -> 0x80
# 65..66: reserved1 (B)       -> 0
# 66..67: boot_sig (B)        -> 0x29
# 67..71: vol_id (I)          -> serial_number
# 71..82: vol_lab (11s)       -> volume label padded to 11 bytes
# 82..90: fil_sys_type (8s)   -> b"FAT32   "
# 90..510: boot_code (420s)   -> zeros
# 510..512: sig (H)           -> 0xAA55
BPB_FORMAT: str = "<3s8sHBHBHHBHHHIIIHHIHH12sBBBI11s8s420sH"

# Struct format string for 512-byte FSInfo Sector
# 0..4:     lead_sig (I)      -> 0x41615252 ("RRaA")
# 4..484:   reserved1 (480s)  -> zeros
# 484..488: struc_sig (I)     -> 0x61417272 ("rrAa")
# 488..492: free_count (I)    -> free cluster count
# 492..496: next_free (I)     -> next free cluster hint
# 496..508: reserved2 (12s)   -> zeros
# 508..512: trail_sig (I)     -> 0xAA550000
FSINFO_FORMAT: str = "<I480sIII12sI"

# Struct format string for 32-byte short directory entry
# 0..8:   name (8s)           -> short base name padded with spaces
# 8..11:  ext (3s)            -> short extension padded with spaces
# 11..12: attr (B)            -> attribute bitmask
# 12..13: reserved (B)        -> 0
# 13..14: ctime_tenth (B)     -> create time tenths (0-199)
# 14..16: ctime (H)           -> create time
# 16..18: cdate (H)           -> create date
# 18..20: adate (H)           -> last access date
# 20..22: cluster_hi (H)      -> first cluster high 16 bits
# 22..24: mtime (H)           -> write/modify time
# 24..26: mdate (H)           -> write/modify date
# 26..28: cluster_lo (H)      -> first cluster low 16 bits
# 28..32: file_size (I)       -> file size in bytes
DIR_ENTRY_FORMAT: str = "<8s3sBBBHHHHHHHI"

# Struct format string for 32-byte Long Filename (LFN) directory entry
# 0..1:   order (B)           -> sequence number (1-based, bit 6 (0x40) set for last)
# 1..11:  name1 (10s)         -> 5 UTF-16LE characters (chars 1-5)
# 11..12: attr (B)            -> 0x0F (ATTR_LONG_NAME)
# 12..13: type (B)            -> 0x00
# 13..14: checksum (B)        -> 8-bit checksum of the short name
# 14..26: name2 (12s)         -> 6 UTF-16LE characters (chars 6-11)
# 26..28: first_cluster (H)   -> 0x0000 (must be 0 for LFN)
# 28..32: name3 (4s)          -> 2 UTF-16LE characters (chars 12-13)
LFN_ENTRY_FORMAT: str = "<B10sBBB12sH4s"


@dataclass
class DirEntryInfo:
    """Metadata representing an existing directory entry parsed from disk."""

    name: str
    short_name: bytes
    attr: int
    first_cluster: int
    size: int
    entry_cluster: int
    entry_offset: int
    lfn_entries: List[Tuple[int, int]] = field(default_factory=list)


class Fat32Image:
    """
    Pure Python in-memory FAT32 filesystem formatter and writer.

    Constructs a valid, bootable FAT32 filesystem stored in a ``bytearray``,
    allowing creation of directories, files with long filenames (VFAT / LFN),
    and ingestion of ``PosixVfs`` trees.
    """

    def __init__(
        self,
        size_bytes: int = 67108864,
        volume_label: str = "TORITO_EFI",
        serial_number: int = 0,
        sectors_per_cluster: Optional[int] = None,
        epoch: Optional[int] = None,
    ) -> None:
        """
        Initialize and format a new FAT32 disk image in memory.

        Parameters
        ----------
        size_bytes : int, optional
            Total disk image size in bytes (default: 67108864 = 64 MB).
        volume_label : str, optional
            Volume label string, up to 11 characters (default: "TORITO_EFI").
        serial_number : int, optional
            32-bit volume serial number. If 0, a deterministic value is computed.
        sectors_per_cluster : int, optional
            Cluster size in sectors (512 bytes/sector). If None, chosen based on image size.
        epoch : int, optional
            Unix epoch timestamp for file timestamps (defaults to time.time()).
        """
        if size_bytes < 1024 * 1024:
            raise ValueError(f"Image size must be at least 1MB ({1024 * 1024} bytes), got {size_bytes}")

        # Align size to 512-byte sector boundary
        self.size_bytes: int = ((size_bytes + 511) // 512) * 512
        self.volume_label: str = volume_label.strip()[:11] if volume_label else "NO NAME"
        self._epoch: int = int(epoch) if epoch is not None else int(time.time())

        # Determine serial number
        if serial_number == 0:
            chk = zlib.crc32(self.volume_label.encode("utf-8") + struct.pack("<Q", self.size_bytes))
            self.serial_number: int = chk & 0xFFFFFFFF
            if self.serial_number == 0:
                self.serial_number = 0x12345678
        else:
            self.serial_number = serial_number & 0xFFFFFFFF

        # Fixed BPB constants
        self.bytes_per_sector: int = 512
        self.reserved_sectors: int = 32
        self.num_fats: int = 2
        self.root_cluster: int = 2
        self.fs_info_sector: int = 1
        self.backup_boot_sector: int = 6

        # Calculate filesystem geometry
        (
            self.total_sectors,
            self.sectors_per_cluster,
            self.fat_size_sectors,
            self._total_clusters,
        ) = self._calculate_geometry(self.size_bytes, sectors_per_cluster)

        self._cluster_size_bytes: int = self.sectors_per_cluster * self.bytes_per_sector
        self._fat1_byte_offset: int = self.reserved_sectors * self.bytes_per_sector
        self._fat2_byte_offset: int = (self.reserved_sectors + self.fat_size_sectors) * self.bytes_per_sector
        self._data_start_sector: int = self.reserved_sectors + (self.num_fats * self.fat_size_sectors)
        self._data_start_byte_offset: int = self._data_start_sector * self.bytes_per_sector

        # Backing disk storage
        self._image: bytearray = bytearray(self.size_bytes)

        # Free cluster tracking and hint
        self._free_clusters_count: int = self._total_clusters - 1  # Cluster 2 is root directory
        self._alloc_hint: int = 3

        # Write on-disk metadata
        self._format()

    def _calculate_geometry(
        self,
        size_bytes: int,
        sectors_per_cluster: Optional[int] = None,
    ) -> Tuple[int, int, int, int]:
        """
        Calculate total sectors, sectors per cluster, FAT size, and total clusters.
        """
        total_sectors = size_bytes // self.bytes_per_sector
        if sectors_per_cluster is None:
            size_mb = size_bytes // (1024 * 1024)
            if size_mb <= 32:
                sectors_per_cluster = 1
            elif size_mb <= 256:
                sectors_per_cluster = 8
            elif size_mb <= 512:
                sectors_per_cluster = 16
            else:
                sectors_per_cluster = 32

        # Direct mathematical formula solving the circular dependency:
        # fat_size * 512 >= ((total_sectors - reserved - num_fats * fat_size) / spc + 2) * 4
        rem = total_sectors - self.reserved_sectors
        num = 4 * rem + 8 * sectors_per_cluster
        den = self.bytes_per_sector * sectors_per_cluster + 4 * self.num_fats
        fat_size_sectors = math.ceil(num / den)

        # Iterative convergence refinement to verify exact capacity
        for _ in range(10):
            data_sectors = total_sectors - self.reserved_sectors - (self.num_fats * fat_size_sectors)
            total_clusters = data_sectors // sectors_per_cluster
            needed_bytes = (total_clusters + 2) * 4
            needed_sectors = math.ceil(needed_bytes / self.bytes_per_sector)
            if needed_sectors == fat_size_sectors:
                break
            if needed_sectors > fat_size_sectors:
                fat_size_sectors = needed_sectors
            else:
                test_data_sec = total_sectors - self.reserved_sectors - (self.num_fats * needed_sectors)
                test_clusters = test_data_sec // sectors_per_cluster
                if needed_sectors * self.bytes_per_sector >= (test_clusters + 2) * 4:
                    fat_size_sectors = needed_sectors
                break

        data_sectors = total_sectors - self.reserved_sectors - (self.num_fats * fat_size_sectors)
        total_clusters = data_sectors // sectors_per_cluster
        return total_sectors, sectors_per_cluster, fat_size_sectors, total_clusters

    def _format(self) -> None:
        """Write BPB, FSInfo, FAT tables, and root directory to image."""
        # 1. Sector 0: Boot Sector (BPB)
        vol_label_bytes = self.volume_label.upper().encode("ascii", errors="replace").ljust(11, b" ")[:11]
        bpb_bytes = struct.pack(
            BPB_FORMAT,
            b"\xeb\x58\x90",          # Jump instruction
            b"MSWIN4.1",              # OEM Name
            self.bytes_per_sector,    # Bytes per sector: 512
            self.sectors_per_cluster, # Sectors per cluster
            self.reserved_sectors,    # Reserved sectors: 32
            self.num_fats,            # Number of FATs: 2
            0,                        # Root entry count: 0 (FAT32)
            0,                        # Total sectors 16: 0
            0xF8,                     # Media: fixed disk
            0,                        # FAT size 16: 0
            63,                       # Sectors per track
            255,                      # Number of heads
            0,                        # Hidden sectors
            self.total_sectors,       # Total sectors 32
            self.fat_size_sectors,    # FAT size 32
            0x0000,                   # Ext flags: mirroring active
            0x0000,                   # FS version: 0.0
            self.root_cluster,        # Root cluster: 2
            self.fs_info_sector,      # FS Info sector: 1
            self.backup_boot_sector,  # Backup boot sector: 6
            b"\x00" * 12,             # Reserved
            0x80,                     # Drive number: fixed disk
            0x00,                     # Reserved
            0x29,                     # Boot signature
            self.serial_number,       # Volume serial number
            vol_label_bytes,          # Volume label (11 bytes)
            b"FAT32   ",              # FS Type
            b"\x00" * 420,            # Boot code
            0xAA55,                   # Signature: 0x55, 0xAA
        )
        self._image[0:512] = bpb_bytes

        # Sector 6: Backup Boot Sector
        bk_bpb_off = self.backup_boot_sector * self.bytes_per_sector
        self._image[bk_bpb_off : bk_bpb_off + 512] = bpb_bytes

        # 2. Sector 1: FSInfo Sector
        fsinfo_bytes = struct.pack(
            FSINFO_FORMAT,
            0x41615252,                               # Lead signature: "RRaA"
            b"\x00" * 480,                            # Reserved
            0x61417272,                               # Struct signature: "rrAa"
            self._free_clusters_count & 0xFFFFFFFF,   # Free cluster count
            self._alloc_hint & 0xFFFFFFFF,            # Next free cluster
            b"\x00" * 12,                             # Reserved
            0xAA550000,                               # Trail signature
        )
        fsinfo_off = self.fs_info_sector * self.bytes_per_sector
        self._image[fsinfo_off : fsinfo_off + 512] = fsinfo_bytes

        # Sector 7: Backup FSInfo Sector
        bk_fsinfo_off = (self.backup_boot_sector + 1) * self.bytes_per_sector
        self._image[bk_fsinfo_off : bk_fsinfo_off + 512] = fsinfo_bytes

        # Sector 2 & 8: Signature on boot code extension sectors
        struct.pack_into("<H", self._image, 2 * self.bytes_per_sector + 510, 0xAA55)
        struct.pack_into("<H", self._image, 8 * self.bytes_per_sector + 510, 0xAA55)

        # 3. Initialize FAT Tables
        # Entry 0: Media type marker 0x0FFFFFF8
        # Entry 1: EOC marker 0x0FFFFFFF
        # Entry 2: Root directory cluster (allocated as EOC)
        self._update_fat_entry(0, 0x0FFFFFF8)
        self._update_fat_entry(1, 0x0FFFFFFF)
        self._update_fat_entry(self.root_cluster, 0x0FFFFFFF)

        # 4. Clear Root directory cluster
        root_off = self._cluster_to_byte_offset(self.root_cluster)
        self._image[root_off : root_off + self._cluster_size_bytes] = b"\x00" * self._cluster_size_bytes

        # 5. Volume Label Entry in Root Directory
        if self.volume_label:
            ctime, cdate = self._fat_time_date()
            vol_entry = struct.pack(
                DIR_ENTRY_FORMAT,
                vol_label_bytes[:8],
                vol_label_bytes[8:11],
                ATTR_VOLUME_ID,
                0,
                0,
                ctime,
                cdate,
                cdate,
                0,
                ctime,
                cdate,
                0,
                0,
            )
            self._image[root_off : root_off + 32] = vol_entry

    def _cluster_to_sector(self, cluster: int) -> int:
        """Convert cluster number to absolute sector number."""
        if cluster < 2:
            raise ValueError(f"Cluster number {cluster} is invalid (must be >= 2)")
        return self._data_start_sector + (cluster - 2) * self.sectors_per_cluster

    def _cluster_to_byte_offset(self, cluster: int) -> int:
        """Convert cluster number to byte offset in disk image."""
        return self._cluster_to_sector(cluster) * self.bytes_per_sector

    def _update_fat_entry(self, cluster: int, value: int) -> None:
        """Write a FAT entry to both FAT table copies."""
        if cluster < 0 or cluster >= self._total_clusters + 2:
            raise ValueError(f"Cluster number {cluster} out of range [0, {self._total_clusters + 1}]")
        entry_offset = cluster * 4
        val = value & 0x0FFFFFFF

        # FAT 1
        pos1 = self._fat1_byte_offset + entry_offset
        exist1 = struct.unpack_from("<I", self._image, pos1)[0]
        struct.pack_into("<I", self._image, pos1, (exist1 & 0xF0000000) | val)

        # FAT 2
        pos2 = self._fat2_byte_offset + entry_offset
        exist2 = struct.unpack_from("<I", self._image, pos2)[0]
        struct.pack_into("<I", self._image, pos2, (exist2 & 0xF0000000) | val)

    def _get_fat_entry(self, cluster: int) -> int:
        """Read a FAT entry from FAT table 1."""
        if cluster < 0 or cluster >= self._total_clusters + 2:
            raise ValueError(f"Cluster number {cluster} out of range [0, {self._total_clusters + 1}]")
        pos = self._fat1_byte_offset + cluster * 4
        return struct.unpack_from("<I", self._image, pos)[0] & 0x0FFFFFFF

    def _update_fsinfo(self) -> None:
        """Update free cluster count and next free cluster hint in FSInfo."""
        for sec in (self.fs_info_sector, self.backup_boot_sector + 1):
            pos = sec * self.bytes_per_sector
            struct.pack_into("<I", self._image, pos + 488, self._free_clusters_count & 0xFFFFFFFF)
            struct.pack_into("<I", self._image, pos + 492, self._alloc_hint & 0xFFFFFFFF)

    def _allocate_cluster(self) -> int:
        """Find a free cluster, mark it as end-of-chain, clear its data, and return it."""
        if self._free_clusters_count <= 0:
            raise OSError("Disk full: no free clusters available in FAT32 image")

        max_cluster = self._total_clusters + 2
        start = self._alloc_hint if 2 <= self._alloc_hint < max_cluster else 2

        found = None
        for c in range(start, max_cluster):
            if self._get_fat_entry(c) == 0:
                found = c
                break
        if found is None:
            for c in range(2, start):
                if self._get_fat_entry(c) == 0:
                    found = c
                    break

        if found is None:
            self._free_clusters_count = 0
            raise OSError("Disk full: no free clusters available in FAT32 image")

        # Mark as End Of Chain
        self._update_fat_entry(found, 0x0FFFFFFF)

        # Zero cluster contents
        off = self._cluster_to_byte_offset(found)
        self._image[off : off + self._cluster_size_bytes] = b"\x00" * self._cluster_size_bytes

        self._free_clusters_count -= 1
        self._alloc_hint = found + 1 if (found + 1) < max_cluster else 2
        self._update_fsinfo()
        return found

    def _allocate_cluster_chain(self, num_clusters: int) -> List[int]:
        """Allocate a chain of clusters and link them in the FAT."""
        if num_clusters <= 0:
            return []
        if num_clusters > self._free_clusters_count:
            raise OSError(f"Disk full: requested {num_clusters} clusters, only {self._free_clusters_count} available")

        chain: List[int] = []
        try:
            for _ in range(num_clusters):
                chain.append(self._allocate_cluster())
            for i in range(len(chain) - 1):
                self._update_fat_entry(chain[i], chain[i + 1])
            self._update_fat_entry(chain[-1], 0x0FFFFFFF)
            return chain
        except Exception:
            for c in chain:
                self._update_fat_entry(c, 0)
                self._free_clusters_count += 1
            self._update_fsinfo()
            raise

    def _free_cluster_chain(self, start_cluster: int) -> None:
        """Free an entire cluster chain in the FAT."""
        if start_cluster < 2:
            return
        curr = start_cluster
        visited = set()
        while 2 <= curr < 0x0FFFFFF8:
            if curr in visited:
                break
            visited.add(curr)
            nxt = self._get_fat_entry(curr)
            self._update_fat_entry(curr, 0)
            self._free_clusters_count += 1
            curr = nxt
        self._update_fsinfo()

    def _get_cluster_chain(self, start_cluster: int) -> List[int]:
        """Retrieve all cluster numbers in a chain starting at start_cluster."""
        if start_cluster < 2:
            return []
        chain = []
        curr = start_cluster
        visited = set()
        while 2 <= curr < 0x0FFFFFF8:
            if curr in visited:
                raise ValueError(f"Corrupted FAT chain: cycle detected at cluster {curr}")
            visited.add(curr)
            chain.append(curr)
            curr = self._get_fat_entry(curr)
        return chain

    def _write_cluster_data(self, cluster: int, data: bytes) -> None:
        """Write up to cluster_size bytes into the specified cluster."""
        off = self._cluster_to_byte_offset(cluster)
        write_len = min(len(data), self._cluster_size_bytes)
        self._image[off : off + write_len] = data[:write_len]
        if write_len < self._cluster_size_bytes:
            self._image[off + write_len : off + self._cluster_size_bytes] = b"\x00" * (
                self._cluster_size_bytes - write_len
            )

    def _fat_time_date(self, timestamp: Optional[int] = None) -> Tuple[int, int]:
        """Encode Unix epoch timestamp as FAT time and date uint16 values."""
        ts = self._epoch if timestamp is None else timestamp
        t = time.gmtime(ts)
        year = max(1980, min(2107, t.tm_year))
        month = max(1, min(12, t.tm_mon))
        day = max(1, min(31, t.tm_mday))
        hour = max(0, min(23, t.tm_hour))
        minute = max(0, min(59, t.tm_min))
        second = max(0, min(59, t.tm_sec))

        date_val = ((year - 1980) << 9) | (month << 5) | day
        time_val = (hour << 11) | (minute << 5) | (second // 2)
        return time_val, date_val

    def _lfn_checksum(self, short_name: bytes) -> int:
        """Compute unsigned 8-bit checksum for LFN entries from an 11-byte short name."""
        chk = 0
        for b in short_name[:11]:
            chk = (((chk & 1) << 7) + (chk >> 1) + b) & 0xFF
        return chk

    def _make_short_name(self, name: str, existing_names: Optional[Set[bytes]] = None) -> Tuple[bytes, bool]:
        """Generate 8.3 short name, returning (name_bytes_11, needs_lfn)."""
        if name == ".":
            return (b".          ", False)
        if name == "..":
            return (b"..         ", False)

        # Check strictly valid uppercase 8.3
        if "." in name:
            parts = name.split(".")
            if len(parts) == 2 and not name.startswith("."):
                b_str, e_str = parts
            else:
                b_str, e_str = None, None
        else:
            b_str, e_str = name, ""

        if b_str is not None and 0 < len(b_str) <= 8 and len(e_str) <= 3:
            if all(ord(c) in VALID_SHORT_CHARS for c in b_str) and all(ord(c) in VALID_SHORT_CHARS for c in e_str):
                short = b_str.encode("ascii").ljust(8, b" ") + e_str.encode("ascii").ljust(3, b" ")
                if existing_names is None or short not in existing_names:
                    return (short, False)

        clean_name = name.strip(". ")
        if "." in clean_name:
            raw_b, raw_e = clean_name.rsplit(".", 1)
        else:
            raw_b, raw_e = clean_name, ""

        def sanitize(s: str) -> str:
            out = []
            for c in s.upper():
                if ord(c) in VALID_SHORT_CHARS:
                    out.append(c)
                elif c not in " .,;+=":
                    out.append("_")
            return "".join(out)

        clean_b = sanitize(raw_b)
        clean_e = sanitize(raw_e)[:3]
        if not clean_b:
            clean_b = "FILE"

        if len(clean_b) <= 8 and len(raw_e) <= 3 and "." not in raw_b and " " not in name:
            candidate = clean_b.encode("ascii").ljust(8, b" ") + clean_e.encode("ascii").ljust(3, b" ")
            if existing_names is None or candidate not in existing_names:
                return (candidate, True)

        i = 1
        while True:
            tail = f"~{i}"
            prefix_len = max(1, 8 - len(tail))
            b_part = clean_b[:prefix_len]
            candidate = (b_part + tail).encode("ascii").ljust(8, b" ") + clean_e.encode("ascii").ljust(3, b" ")
            if existing_names is None or candidate not in existing_names:
                return (candidate, True)
            i += 1

    def _make_lfn_entries(self, long_name: str, short_name: bytes) -> List[bytes]:
        """Generate 32-byte LFN directory entries in reverse (on-disk) order."""
        chk = self._lfn_checksum(short_name)
        num_entries = (len(long_name) + 12) // 13
        entries: List[bytes] = []

        for k in range(num_entries, 0, -1):
            start = (k - 1) * 13
            chunk = long_name[start : start + 13]
            units = [ord(c) for c in chunk]
            if len(units) < 13:
                units.append(0x0000)
                while len(units) < 13:
                    units.append(0xFFFF)

            order = k | 0x40 if k == num_entries else k
            name1 = struct.pack("<5H", *units[0:5])
            name2 = struct.pack("<6H", *units[5:11])
            name3 = struct.pack("<2H", *units[11:13])

            entry = struct.pack(
                LFN_ENTRY_FORMAT,
                order,
                name1,
                ATTR_LONG_NAME,
                0x00,
                chk,
                name2,
                0x0000,
                name3,
            )
            entries.append(entry)
        return entries

    def _decode_lfn_chunk(self, data: bytes) -> str:
        """Decode up to 13 UTF-16LE characters from a 32-byte LFN entry."""
        chars_raw = data[1:11] + data[14:26] + data[28:32]
        out: List[int] = []
        for i in range(0, 26, 2):
            val = struct.unpack_from("<H", chars_raw, i)[0]
            if val == 0 or val == 0xFFFF:
                break
            out.append(val)
        return struct.pack(f"<{len(out)}H", *out).decode("utf-16le", errors="replace")

    def _scan_dir(self, dir_cluster: int) -> List[DirEntryInfo]:
        """Scan a directory cluster chain and return all active directory entries."""
        entries: List[DirEntryInfo] = []
        chain = self._get_cluster_chain(dir_cluster)
        slots_per_cluster = self._cluster_size_bytes // 32
        pending_lfn: List[Tuple[int, bytes, int, int]] = []

        for clus in chain:
            clus_off = self._cluster_to_byte_offset(clus)
            for slot in range(slots_per_cluster):
                off = clus_off + slot * 32
                entry_bytes = self._image[off : off + 32]
                first_byte = entry_bytes[0]

                if first_byte == 0x00:
                    # End of entries in this cluster
                    break
                if first_byte == 0xE5:
                    pending_lfn.clear()
                    continue

                attr = entry_bytes[11]
                if attr == ATTR_LONG_NAME:
                    pending_lfn.append((first_byte, bytes(entry_bytes), clus, off))
                    continue

                short_name = bytes(entry_bytes[0:11])
                name: Optional[str] = None
                lfn_slots: List[Tuple[int, int]] = []

                if pending_lfn:
                    chk = self._lfn_checksum(short_name)
                    sorted_lfn = sorted(pending_lfn, key=lambda x: x[0] & 0x1F)
                    valid = True
                    name_chunks: List[str] = []
                    for o, b, c, o_off in sorted_lfn:
                        if b[13] != chk:
                            valid = False
                            break
                        lfn_slots.append((c, o_off))
                        name_chunks.append(self._decode_lfn_chunk(b))
                    if valid:
                        name = "".join(name_chunks)
                    pending_lfn.clear()

                if name is None:
                    base = entry_bytes[0:8].decode("ascii", errors="replace").rstrip()
                    ext = entry_bytes[8:11].decode("ascii", errors="replace").rstrip()
                    name = f"{base}.{ext}" if ext else base

                hi = struct.unpack_from("<H", entry_bytes, 20)[0]
                lo = struct.unpack_from("<H", entry_bytes, 26)[0]
                size = struct.unpack_from("<I", entry_bytes, 28)[0]
                first_clus = (hi << 16) | lo

                entries.append(
                    DirEntryInfo(
                        name=name,
                        short_name=short_name,
                        attr=attr,
                        first_cluster=first_clus,
                        size=size,
                        entry_cluster=clus,
                        entry_offset=off,
                        lfn_entries=lfn_slots,
                    )
                )
        return entries

    def _list_short_names(self, dir_cluster: int) -> Set[bytes]:
        """List all 11-byte short names currently allocated in a directory."""
        names: Set[bytes] = set()
        chain = self._get_cluster_chain(dir_cluster)
        slots_per_cluster = self._cluster_size_bytes // 32
        for clus in chain:
            clus_off = self._cluster_to_byte_offset(clus)
            for slot in range(slots_per_cluster):
                off = clus_off + slot * 32
                b0 = self._image[off]
                if b0 == 0x00:
                    break
                if b0 == 0xE5:
                    continue
                attr = self._image[off + 11]
                if attr == ATTR_LONG_NAME:
                    continue
                names.add(bytes(self._image[off : off + 11]))
        return names

    def _find_entry_in_dir(self, dir_cluster: int, name: str) -> Optional[DirEntryInfo]:
        """Find a directory entry by name (case-insensitive) in the given directory."""
        entries = self._scan_dir(dir_cluster)
        target = name.lower()
        for e in entries:
            if e.attr == ATTR_VOLUME_ID:
                continue
            if e.name.lower() == target:
                return e
            base = e.short_name[0:8].decode("ascii", errors="replace").rstrip()
            ext = e.short_name[8:11].decode("ascii", errors="replace").rstrip()
            short_disp = f"{base}.{ext}" if ext else base
            if short_disp.lower() == target:
                return e
        return None

    def _add_directory_entry(
        self,
        dir_cluster: int,
        name: str,
        attr: int,
        first_cluster: int,
        size: int,
    ) -> None:
        """Add short and LFN entries to a directory."""
        existing_shorts = self._list_short_names(dir_cluster)
        short_name, needs_lfn = self._make_short_name(name, existing_shorts)

        if needs_lfn:
            lfn_entries = self._make_lfn_entries(name, short_name)
        else:
            lfn_entries = []

        ctime, cdate = self._fat_time_date()
        cluster_hi = (first_cluster >> 16) & 0xFFFF
        cluster_lo = first_cluster & 0xFFFF

        short_entry = struct.pack(
            DIR_ENTRY_FORMAT,
            short_name[:8],
            short_name[8:11],
            attr & 0xFF,
            0,
            0,
            ctime,
            cdate,
            cdate,
            cluster_hi,
            ctime,
            cdate,
            cluster_lo,
            size & 0xFFFFFFFF,
        )

        entries_to_write = lfn_entries + [short_entry]
        needed_slots = len(entries_to_write)

        chain = self._get_cluster_chain(dir_cluster)
        slots_per_cluster = self._cluster_size_bytes // 32

        placed = False
        for clus in chain:
            clus_off = self._cluster_to_byte_offset(clus)
            run_start = None
            run_len = 0
            for slot_idx in range(slots_per_cluster):
                off = clus_off + slot_idx * 32
                b0 = self._image[off]
                if b0 == 0x00:
                    if run_start is None:
                        run_start = slot_idx
                        run_len = slots_per_cluster - slot_idx
                    else:
                        run_len += slots_per_cluster - slot_idx
                    if run_len >= needed_slots:
                        write_start = run_start
                        for i, e in enumerate(entries_to_write):
                            tgt = clus_off + (write_start + i) * 32
                            self._image[tgt : tgt + 32] = e
                        placed = True
                        break
                    break
                elif b0 == 0xE5:
                    if run_start is None:
                        run_start = slot_idx
                        run_len = 1
                    else:
                        run_len += 1
                    if run_len >= needed_slots:
                        write_start = run_start
                        for i, e in enumerate(entries_to_write):
                            tgt = clus_off + (write_start + i) * 32
                            self._image[tgt : tgt + 32] = e
                        placed = True
                        break
                else:
                    run_start = None
                    run_len = 0
            if placed:
                break

        if not placed:
            # Allocate a new cluster to expand directory
            last_clus = chain[-1]
            new_clus = self._allocate_cluster()
            self._update_fat_entry(last_clus, new_clus)
            self._update_fat_entry(new_clus, 0x0FFFFFFF)
            clus_off = self._cluster_to_byte_offset(new_clus)
            for i, e in enumerate(entries_to_write):
                tgt = clus_off + i * 32
                self._image[tgt : tgt + 32] = e

    def _find_or_create_dir(self, path: str) -> int:
        """Traverse or create directory path and return its first cluster number."""
        norm = path.replace("\\", "/").strip()
        parts = [p for p in norm.split("/") if p and p != "."]

        curr_cluster = self.root_cluster
        for part in parts:
            entry = self._find_entry_in_dir(curr_cluster, part)
            if entry is not None:
                if not (entry.attr & ATTR_DIRECTORY):
                    raise NotADirectoryError(f"Path component '{part}' is a file, not a directory")
                curr_cluster = entry.first_cluster
            else:
                # Create directory cluster
                new_dir_cluster = self._allocate_cluster()
                ctime, cdate = self._fat_time_date()

                # '.' entry
                dot_entry = struct.pack(
                    DIR_ENTRY_FORMAT,
                    b".       ",
                    b"   ",
                    ATTR_DIRECTORY,
                    0,
                    0,
                    ctime,
                    cdate,
                    cdate,
                    (new_dir_cluster >> 16) & 0xFFFF,
                    ctime,
                    cdate,
                    new_dir_cluster & 0xFFFF,
                    0,
                )

                # '..' entry: parent root is represented as cluster 0 in FAT32
                dotdot_cluster = 0 if curr_cluster == self.root_cluster else curr_cluster
                dotdot_entry = struct.pack(
                    DIR_ENTRY_FORMAT,
                    b"..      ",
                    b"   ",
                    ATTR_DIRECTORY,
                    0,
                    0,
                    ctime,
                    cdate,
                    cdate,
                    (dotdot_cluster >> 16) & 0xFFFF,
                    ctime,
                    cdate,
                    dotdot_cluster & 0xFFFF,
                    0,
                )

                new_off = self._cluster_to_byte_offset(new_dir_cluster)
                self._image[new_off : new_off + 32] = dot_entry
                self._image[new_off + 32 : new_off + 64] = dotdot_entry

                # Add entry into parent
                self._add_directory_entry(curr_cluster, part, ATTR_DIRECTORY, new_dir_cluster, 0)
                curr_cluster = new_dir_cluster

        return curr_cluster

    def create_directory(self, path: str) -> None:
        """Create a directory (and any necessary parent directories)."""
        self._find_or_create_dir(path)

    def write_file(self, path: str, data: bytes) -> None:
        """Write a file at the specified path, overwriting if it exists."""
        norm = path.replace("\\", "/").strip()
        if not norm or norm == "/":
            raise ValueError("Cannot write file to empty or root path")

        parts = [p for p in norm.split("/") if p and p != "."]
        if not parts:
            raise ValueError(f"Invalid file path: {path}")

        parent_path = "/" + "/".join(parts[:-1]) if len(parts) > 1 else "/"
        filename = parts[-1]

        parent_cluster = self._find_or_create_dir(parent_path)
        existing = self._find_entry_in_dir(parent_cluster, filename)

        if existing is not None:
            if existing.attr & ATTR_DIRECTORY:
                raise IsADirectoryError(f"Cannot overwrite directory '{path}' with file")

            # Free old clusters
            if existing.first_cluster >= 2:
                self._free_cluster_chain(existing.first_cluster)

            first_cluster = 0
            if len(data) > 0:
                num_clus = (len(data) + self._cluster_size_bytes - 1) // self._cluster_size_bytes
                chain = self._allocate_cluster_chain(num_clus)
                first_cluster = chain[0]
                for i, clus in enumerate(chain):
                    chunk = data[i * self._cluster_size_bytes : (i + 1) * self._cluster_size_bytes]
                    self._write_cluster_data(clus, chunk)

            ctime, cdate = self._fat_time_date()
            entry_pos = existing.entry_offset
            struct.pack_into("<H", self._image, entry_pos + 20, (first_cluster >> 16) & 0xFFFF)
            struct.pack_into("<H", self._image, entry_pos + 22, ctime)
            struct.pack_into("<H", self._image, entry_pos + 24, cdate)
            struct.pack_into("<H", self._image, entry_pos + 26, first_cluster & 0xFFFF)
            struct.pack_into("<I", self._image, entry_pos + 28, len(data) & 0xFFFFFFFF)
        else:
            first_cluster = 0
            if len(data) > 0:
                num_clus = (len(data) + self._cluster_size_bytes - 1) // self._cluster_size_bytes
                chain = self._allocate_cluster_chain(num_clus)
                first_cluster = chain[0]
                for i, clus in enumerate(chain):
                    chunk = data[i * self._cluster_size_bytes : (i + 1) * self._cluster_size_bytes]
                    self._write_cluster_data(clus, chunk)

            self._add_directory_entry(parent_cluster, filename, ATTR_ARCHIVE, first_cluster, len(data))

    def read_file(self, path: str) -> bytes:
        """Read and return complete file content from the filesystem."""
        norm = path.replace("\\", "/").strip()
        parts = [p for p in norm.split("/") if p and p != "."]
        if not parts:
            raise ValueError(f"Invalid file path: {path}")

        parent_path = "/" + "/".join(parts[:-1]) if len(parts) > 1 else "/"
        filename = parts[-1]

        parent_cluster = self._find_or_create_dir(parent_path)
        entry = self._find_entry_in_dir(parent_cluster, filename)
        if entry is None:
            raise FileNotFoundError(f"File not found: {path}")
        if entry.attr & ATTR_DIRECTORY:
            raise IsADirectoryError(f"Target is a directory: {path}")

        if entry.size == 0 or entry.first_cluster < 2:
            return b""

        chain = self._get_cluster_chain(entry.first_cluster)
        chunks = []
        for clus in chain:
            off = self._cluster_to_byte_offset(clus)
            chunks.append(bytes(self._image[off : off + self._cluster_size_bytes]))
        return b"".join(chunks)[: entry.size]

    def exists(self, path: str) -> bool:
        """Check if a file or directory exists."""
        norm = path.replace("\\", "/").strip()
        parts = [p for p in norm.split("/") if p and p != "."]
        if not parts:
            return True

        parent_path = "/" + "/".join(parts[:-1]) if len(parts) > 1 else "/"
        filename = parts[-1]
        try:
            parent_cluster = self._find_or_create_dir(parent_path)
        except Exception:
            return False
        return self._find_entry_in_dir(parent_cluster, filename) is not None

    def list_dir(self, path: str = "/") -> List[str]:
        """List filenames and directory names in the specified directory."""
        norm = path.replace("\\", "/").strip()
        parts = [p for p in norm.split("/") if p and p != "."]
        curr_clus = self.root_cluster
        for part in parts:
            entry = self._find_entry_in_dir(curr_clus, part)
            if entry is None or not (entry.attr & ATTR_DIRECTORY):
                raise FileNotFoundError(f"Directory not found: {path}")
            curr_clus = entry.first_cluster

        entries = self._scan_dir(curr_clus)
        return [e.name for e in entries if e.attr != ATTR_VOLUME_ID and e.name not in (".", "..")]

    def populate_from_vfs(self, vfs: PosixVfs, vfs_prefix: str = "/") -> None:
        """
        Populate the FAT32 image from a PosixVfs filesystem tree.

        Walks all nodes under `vfs_prefix` in deterministic sorted order and writes
        regular files and directories into this FAT32 filesystem.
        """
        prefix = "/" + vfs_prefix.strip("/") if vfs_prefix.strip("/") else "/"
        prefix_len = len(prefix) if prefix != "/" else 1

        for path, node in vfs.walk_sorted():
            if not path.startswith(prefix):
                continue
            rel_path = path[prefix_len:] if prefix != "/" else path
            if not rel_path or rel_path == "/":
                continue
            dest_path = "/" + rel_path.lstrip("/")

            if node.node_type == VfsNodeType.DIRECTORY:
                self.create_directory(dest_path)
            elif node.node_type == VfsNodeType.REGULAR_FILE:
                self.write_file(dest_path, node.data)
            elif node.node_type == VfsNodeType.SYMLINK:
                target_node = vfs.get(node.link_target)
                if target_node and target_node.node_type == VfsNodeType.REGULAR_FILE:
                    self.write_file(dest_path, target_node.data)

    @classmethod
    def from_vfs(
        cls,
        vfs: PosixVfs,
        size_bytes: Optional[int] = None,
        volume_label: str = "TORITO_EFI",
        serial_number: int = 0,
        vfs_prefix: str = "/",
    ) -> "Fat32Image":
        """
        Create a new Fat32Image and populate it with files from a PosixVfs instance.
        """
        if size_bytes is None:
            total_data = sum(n.size for _, n in vfs.walk_sorted())
            needed = total_data + 8 * 1024 * 1024
            size_bytes = max(33554432, ((needed + 16777215) // 16777216) * 16777216)

        epoch = getattr(vfs, "_epoch", None)
        img = cls(
            size_bytes=size_bytes,
            volume_label=volume_label,
            serial_number=serial_number,
            epoch=epoch,
        )
        img.populate_from_vfs(vfs, vfs_prefix=vfs_prefix)
        return img

    def to_bytes(self) -> bytes:
        """Return the complete disk image as bytes."""
        return bytes(self._image)


def build_efi_esp(
    efi_binary: bytes,
    kernel: bytes = b"",
    initramfs: bytes = b"",
    size_mb: int = 64,
    volume_label: str = "TORITO_EFI",
    extra_files: Optional[Dict[str, bytes]] = None,
) -> bytes:
    """
    Build an EFI System Partition (efiboot.img) FAT32 disk image in memory.

    Parameters
    ----------
    efi_binary : bytes
        Raw bytes of the UEFI bootloader binary (e.g. BOOTX64.EFI).
    kernel : bytes, optional
        Raw bytes of the Linux kernel (/vmlinuz).
    initramfs : bytes, optional
        Raw bytes of the initial ramdisk (/initramfs.img).
    size_mb : int, optional
        Target image size in megabytes (default: 64 MB).
    volume_label : str, optional
        Volume label (default: "TORITO_EFI").
    extra_files : dict of str to bytes, optional
        Additional files to write into the ESP (e.g. bootloader configs).

    Returns
    -------
    bytes
        Complete FAT32 disk image suitable for writing to efiboot.img.
    """
    # Delegates to the one-shot builder, which picks FAT16/FAT32 by cluster
    # count exactly like UEFI firmware does (a small "FAT32" ESP is read as
    # FAT16 by firmware and fails to boot).
    from .fatfs import build_fat_image

    files: Dict[str, bytes] = {}
    if efi_binary:
        files["/EFI/BOOT/BOOTX64.EFI"] = efi_binary
    if kernel:
        files["/vmlinuz"] = kernel
    if initramfs:
        files["/initramfs.img"] = initramfs
    for fpath, fdata in (extra_files or {}).items():
        files[fpath] = fdata
    if not files:
        files["/EFI/BOOT/.keep"] = b""
    return build_fat_image(files, label=volume_label[:11], min_size=size_mb * 1024 * 1024 if size_mb else 0)
