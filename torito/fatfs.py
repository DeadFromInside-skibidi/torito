"""
torito.fatfs — One-shot FAT16/FAT32 Image Builder
=================================================
Builds a FAT filesystem image from a ``{path: bytes}`` mapping in a single
pass (``mkfs.vfat`` + ``mcopy`` replacement) for EFI System Partitions.

The FAT *type* is chosen the way every driver (Linux, Windows, EDK2 UEFI)
determines it — by cluster count: FAT16 for 4 085‥65 524 clusters, FAT32
above that.  (A "FAT32" volume with fewer than 65 525 clusters is read as
FAT16 by firmware and fails to boot — a classic ESP bug.)
"""

from __future__ import annotations

import math
import struct
import time
import zlib
from typing import Dict, List, Optional, Set, Tuple

SECTOR = 512
FAT16_MIN, FAT16_MAX = 4085, 65524
FAT32_MIN = 65525
_VALID_SHORT = set("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!#$%&'()-@^_`{}~")


def _fat_time(ts: int) -> Tuple[int, int]:
    t = time.gmtime(max(ts, 315532800))
    return ((t.tm_hour << 11) | (t.tm_min << 5) | (t.tm_sec // 2),
            ((min(t.tm_year, 2107) - 1980) << 9) | (t.tm_mon << 5) | t.tm_mday)


def _lfn_checksum(short: bytes) -> int:
    s = 0
    for b in short:
        s = (((s & 1) << 7) + (s >> 1) + b) & 0xFF
    return s


def _short_name(name: str, taken: Set[bytes]) -> Tuple[bytes, bool]:
    """Return (11-byte 8.3 name, needs_lfn)."""
    if "." in name and not name.startswith("."):
        base, ext = name.rsplit(".", 1)
    else:
        base, ext = name, ""
    if (
        0 < len(base) <= 8 and len(ext) <= 3 and name == name.upper()
        and all(c in _VALID_SHORT for c in base + ext)
    ):
        s = base.encode().ljust(8, b" ") + ext.encode().ljust(3, b" ")
        if s not in taken:
            return s, False

    def clean(x: str) -> str:
        return "".join(c if c in _VALID_SHORT else "_" for c in x.upper().replace(" ", "").replace(".", ""))

    b, e = clean(base) or "FILE", clean(ext)[:3]
    for i in range(1, 1000000):
        tail = f"~{i}"
        cand = (b[: 8 - len(tail)] + tail).encode().ljust(8, b" ") + e.encode().ljust(3, b" ")
        if cand not in taken:
            return cand, True
    raise ValueError("cannot generate short name")


def _lfn_entries(name: str, short: bytes) -> List[bytes]:
    chk = _lfn_checksum(short)
    units = list(name.encode("utf-16le"))
    chars = [units[i] | (units[i + 1] << 8) for i in range(0, len(units), 2)]
    n = (len(chars) + 12) // 13
    chars = chars + [0x0000] + [0xFFFF] * (n * 13 - len(chars) - 1) if len(chars) % 13 else chars
    out = []
    for k in range(n, 0, -1):
        seg = chars[(k - 1) * 13: k * 13]
        seq = k | (0x40 if k == n else 0)
        out.append(
            struct.pack("<B5HBBB6HH2H", seq, *seg[0:5], 0x0F, 0, chk, *seg[5:11], 0, *seg[11:13])
        )
    return out


def _dirent(short: bytes, attr: int, cluster: int, size: int, ts: int) -> bytes:
    t, d = _fat_time(ts)
    return struct.pack("<11sBBBHHHHHHHI", short, attr, 0, 0, t, d, d, (cluster >> 16) & 0xFFFF, t, d, cluster & 0xFFFF, size)


class _Dir:
    def __init__(self, path: str) -> None:
        self.path = path
        self.subdirs: Dict[str, "_Dir"] = {}
        self.files: Dict[str, bytes] = {}
        self.cluster = 0
        self.entries = b""


def build_fat_image(
    files: Dict[str, bytes],
    label: str = "EFIBOOT",
    min_size: int = 0,
    slack: float = 0.02,
    epoch: Optional[int] = None,
    serial: Optional[int] = None,
) -> bytes:
    """Create a FAT16/FAT32 image containing *files* (paths use ``/``)."""
    ts = int(epoch if epoch is not None else time.time())
    root = _Dir("/")
    for path, data in sorted(files.items()):
        parts = [p for p in path.replace("\\", "/").split("/") if p]
        d = root
        for comp in parts[:-1]:
            d = d.subdirs.setdefault(comp, _Dir(d.path.rstrip("/") + "/" + comp))
        d.files[parts[-1]] = bytes(data)

    def all_dirs(d: _Dir) -> List[_Dir]:
        out = [d]
        for s in d.subdirs.values():
            out.extend(all_dirs(s))
        return out

    dirs = all_dirs(root)

    def dir_entry_count(d: _Dir) -> int:
        n = 2 if d is not root else 1  # . and .. (or volume label in root)
        for name in list(d.subdirs) + list(d.files):
            n += 1 + (len(name) + 12) // 13
        return n

    total_payload = sum(len(v) for v in files.values())
    fat_bits = 16
    for spc in (1, 2, 4, 8, 16, 32, 64):
        cs = spc * SECTOR
        need = sum(math.ceil(len(v) / cs) for v in files.values())
        need += sum(max(1, math.ceil(dir_entry_count(d) * 32 / cs)) for d in dirs if d is not root)
        clusters = int(need * (1 + slack)) + 8
        clusters = max(clusters, FAT16_MIN + 16, math.ceil(min_size / cs))
        if clusters <= FAT16_MAX - 16:
            break
    else:
        fat_bits = 32
        spc = 8
        cs = spc * SECTOR
        need = sum(math.ceil(len(v) / cs) for v in files.values()) + len(dirs) * 4
        clusters = max(int(need * (1 + slack)) + 64, FAT32_MIN + 64, math.ceil(min_size / cs))

    if fat_bits == 16:
        reserved, root_entries = 1, 512
        root_secs = root_entries * 32 // SECTOR
        fat_secs = math.ceil((clusters + 2) * 2 / SECTOR)
    else:
        reserved, root_entries, root_secs = 32, 0, 0
        fat_secs = math.ceil((clusters + 2) * 4 / SECTOR)
    data_start = reserved + 2 * fat_secs + root_secs
    total_secs = data_start + clusters * spc
    img = bytearray(total_secs * SECTOR)
    fat = [0] * (clusters + 2)
    eoc = 0xFFFF if fat_bits == 16 else 0x0FFFFFFF
    fat[0] = 0xFFF8 if fat_bits == 16 else 0x0FFFFFF8
    fat[1] = eoc
    next_free = [2]

    def alloc(nbytes: int) -> int:
        n = max(1, math.ceil(nbytes / cs))
        first = next_free[0]
        if first + n > clusters + 2:
            raise OSError("FAT image too small")
        for c in range(first, first + n - 1):
            fat[c] = c + 1
        fat[first + n - 1] = eoc
        next_free[0] += n
        return first

    def cluster_off(c: int) -> int:
        return (data_start + (c - 2) * spc) * SECTOR

    # FAT32 root directory is a normal cluster chain.
    if fat_bits == 32:
        pass

    # Allocate directories first (sizes known up front), then files.
    for d in dirs:
        if d is root and fat_bits == 16:
            continue
        d.cluster = alloc(max(1, dir_entry_count(d)) * 32)

    file_clusters: Dict[Tuple[str, str], int] = {}
    for d in dirs:
        for name, data in d.files.items():
            if data:
                c = alloc(len(data))
                file_clusters[(d.path, name)] = c
                off = cluster_off(c)
                img[off: off + len(data)] = data

    vol = (label.upper().encode("ascii", "replace")[:11]).ljust(11, b" ")
    parent_of: Dict[str, _Dir] = {}
    for d in dirs:
        for s in d.subdirs.values():
            parent_of[s.path] = d

    for d in dirs:
        ents = bytearray()
        taken: Set[bytes] = set()
        if d is root:
            ents += _dirent(vol, 0x08, 0, 0, ts)
        else:
            parent = parent_of[d.path]
            pclus = 0 if parent is root else parent.cluster
            ents += _dirent(b".          ", 0x10, d.cluster, 0, ts)
            ents += _dirent(b"..         ", 0x10, pclus, 0, ts)
        for name, sub in sorted(d.subdirs.items()):
            short, lfn = _short_name(name, taken)
            taken.add(short)
            if lfn:
                for e in _lfn_entries(name, short):
                    ents += e
            ents += _dirent(short, 0x10, sub.cluster, 0, ts)
        for name, data in sorted(d.files.items()):
            short, lfn = _short_name(name, taken)
            taken.add(short)
            if lfn:
                for e in _lfn_entries(name, short):
                    ents += e
            ents += _dirent(short, 0x20, file_clusters.get((d.path, name), 0), len(data), ts)
        if d is root and fat_bits == 16:
            if len(ents) > root_entries * 32:
                raise OSError("too many entries in FAT16 root directory")
            off = (reserved + 2 * fat_secs) * SECTOR
        else:
            off = cluster_off(d.cluster)
        img[off: off + len(ents)] = ents

    # FAT tables
    if fat_bits == 16:
        fat_bytes = struct.pack(f"<{len(fat)}H", *fat)
    else:
        fat_bytes = struct.pack(f"<{len(fat)}I", *fat)
    for i in range(2):
        off = (reserved + i * fat_secs) * SECTOR
        img[off: off + len(fat_bytes)] = fat_bytes

    serial = serial if serial is not None else (zlib.crc32(vol + struct.pack("<Q", total_payload)) & 0xFFFFFFFF)
    tot16 = total_secs if total_secs < 0x10000 else 0
    tot32 = 0 if total_secs < 0x10000 else total_secs
    common = struct.pack(
        "<3s8sHBHBHHBHHHII",
        b"\xEB\x3C\x90" if fat_bits == 16 else b"\xEB\x58\x90", b"MSWIN4.1", SECTOR, spc, reserved, 2,
        root_entries, tot16 if fat_bits == 16 else 0, 0xF8, fat_secs if fat_bits == 16 else 0,
        32, 64, 0, tot32 if fat_bits == 16 else total_secs,
    )
    if fat_bits == 16:
        ext = struct.pack("<BBBI11s8s", 0x80, 0, 0x29, serial, vol, b"FAT16   ")
        bs = common + ext
    else:
        ext = struct.pack("<IHHIHH12sBBBI11s8s", fat_secs, 0, 0, 2, 1, 6, b"\x00" * 12, 0x80, 0, 0x29, serial, vol, b"FAT32   ")
        bs = common + ext
    img[0: len(bs)] = bs
    img[510:512] = b"\x55\xAA"
    if fat_bits == 32:
        fsinfo = bytearray(SECTOR)
        struct.pack_into("<I", fsinfo, 0, 0x41615252)
        struct.pack_into("<I", fsinfo, 484, 0x61417272)
        struct.pack_into("<I", fsinfo, 488, clusters - (next_free[0] - 2))
        struct.pack_into("<I", fsinfo, 492, next_free[0])
        struct.pack_into("<I", fsinfo, 508, 0xAA550000)
        img[SECTOR: 2 * SECTOR] = fsinfo
        img[6 * SECTOR: 6 * SECTOR + SECTOR] = img[0:SECTOR]
        img[7 * SECTOR: 8 * SECTOR] = fsinfo
    return bytes(img)
