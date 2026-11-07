"""
torito.iso9660 — Hybrid ISO9660 + El Torito Assembler
=====================================================
A pure-Python ``xorriso -as mkisofs`` for live media:

* ISO9660 (level 2 names) with **Rock Ridge** (SP/ER/PX/NM) so Linux sees
  real, case-preserved file names and POSIX modes;
* **El Torito** boot catalog with a BIOS no-emulation entry (ISOLINUX, load
  size 4, *boot-info-table* patched in) and an EFI section entry pointing at
  a FAT EFI System Partition image;
* an **isohybrid MBR** (syslinux ``isohdpfx`` boot code + partition table
  with an 0xEF ESP partition) so the same image boots when ``dd``'d to USB;
* streaming output: file payloads are copied from host files / bytes
  straight into the image, so multi-GiB images need no extra RAM.
"""

from __future__ import annotations

import io
import os
import re
import shutil
import struct
import time
from collections import deque
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import BinaryIO, Dict, List, Optional, Tuple, Union

from .vfs import PosixVfs, VfsNodeType

SECTOR_SIZE = 2048
LBA_SIZE = 512

ISO_STANDARD_ID = b"CD001"
ISO_VD_BOOT_RECORD = 0
ISO_VD_PRIMARY = 1
ISO_VD_SET_TERMINATOR = 255

EL_TORITO_SYS_ID = b"EL TORITO SPECIFICATION"
EL_TORITO_BOOTABLE = 0x88
EL_TORITO_NOT_BOOTABLE = 0x00
EL_TORITO_MEDIA_NO_EMULATION = 0x00
EL_TORITO_PLATFORM_X86 = 0x00
EL_TORITO_PLATFORM_EFI = 0xEF
EL_TORITO_HEADER_ID = 0x01
EL_TORITO_SECTION_HEADER_LAST = 0x91
EL_TORITO_KEY_BYTES = b"\x55\xAA"


class Iso9660Error(Exception):
    pass


class Iso9660PathError(Iso9660Error):
    pass


class Iso9660BuildError(Iso9660Error):
    pass


def _both32(v: int) -> bytes:
    return struct.pack("<I", v & 0xFFFFFFFF) + struct.pack(">I", v & 0xFFFFFFFF)


def _both16(v: int) -> bytes:
    return struct.pack("<H", v & 0xFFFF) + struct.pack(">H", v & 0xFFFF)


def _pad_str(text: str, n: int, fill: bytes = b" ") -> bytes:
    return text.encode("ascii", "replace")[:n].ljust(n, fill)


def _date17(ts: int) -> bytes:
    if ts <= 0:
        return b"0000000000000000\x00"
    g = time.gmtime(ts)
    return f"{g.tm_year:04d}{g.tm_mon:02d}{g.tm_mday:02d}{g.tm_hour:02d}{g.tm_min:02d}{g.tm_sec:02d}00".encode() + b"\x00"


def _date7(ts: int) -> bytes:
    g = time.gmtime(max(ts, 0))
    return struct.pack("BBBBBBb", max(0, min(255, g.tm_year - 1900)), g.tm_mon, g.tm_mday, g.tm_hour, g.tm_min, g.tm_sec, 0)


Source = Union[bytes, str]  # bytes payload or host file path


@dataclass
class _Entry:
    path: str
    is_dir: bool
    source: Optional[Source] = None
    size: int = 0
    mtime: int = 0
    mode: int = 0o644
    hidden: bool = False
    lba: int = 0
    iso_name: bytes = b""


class Iso9660Builder:
    """Collects files/directories and writes a bootable hybrid ISO."""

    def __init__(
        self,
        volume_id: str = "TORITO",
        system_id: str = "LINUX",
        publisher_id: str = "TORITO",
        application_id: str = "TORITO",
        rock_ridge: bool = True,
    ) -> None:
        self.volume_id = (volume_id or "TORITO").strip()[:32]
        self.system_id = (system_id or "LINUX").strip()[:32]
        self.publisher_id = (publisher_id or "TORITO").strip()[:128]
        self.application_id = (application_id or "TORITO").strip()[:128]
        self.rock_ridge = rock_ridge
        epoch_env = os.environ.get("SOURCE_DATE_EPOCH")
        self._creation_time = int(epoch_env) if epoch_env and epoch_env.isdigit() else int(time.time())
        self._entries: Dict[str, _Entry] = {"/": _Entry("/", True, mtime=self._creation_time, mode=0o755)}
        self._bios_path: Optional[str] = None
        self._bios_inline: bytes = b""
        self._bios_load_sectors = 4
        self._bios_boot_info_table = True
        self._efi_image: Optional[Source] = None
        self._efi_size = 0
        self._catalog_path: Optional[str] = None
        self._mbr_code: bytes = b""
        self.pad_to = 1024 * 1024
        self.layout: Dict[str, int] = {}

    # ------------------------------------------------------------------
    # Population
    # ------------------------------------------------------------------

    @staticmethod
    def _norm(path: str) -> str:
        p = "/" + "/".join(s for s in path.replace("\\", "/").split("/") if s and s != ".")
        return p

    def add_directory(self, iso_path: str, mtime: Optional[int] = None) -> None:
        p = self._norm(iso_path)
        parts = [s for s in p.split("/") if s]
        cur = ""
        for s in parts:
            cur += "/" + s
            if cur not in self._entries:
                self._entries[cur] = _Entry(cur, True, mtime=mtime or self._creation_time, mode=0o755)
            elif not self._entries[cur].is_dir:
                raise Iso9660PathError(f"{cur} is a file")

    def _add(self, iso_path: str, source: Source, size: int, mtime: Optional[int], mode: int) -> None:
        p = self._norm(iso_path)
        if p == "/":
            raise Iso9660PathError("Cannot add a file at root path '/'")
        self.add_directory(str(PurePosixPath(p).parent))
        self._entries[p] = _Entry(p, False, source=source, size=size, mtime=mtime or self._creation_time, mode=mode)

    def add_file(self, iso_path: str, data: bytes, mtime: Optional[int] = None, mode: int = 0o644) -> None:
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError(f"File data must be bytes or bytearray, got {type(data).__name__}")
        self._add(iso_path, bytes(data), len(data), mtime, mode)

    def add_host_file(self, iso_path: str, host_path: str, mtime: Optional[int] = None, mode: int = 0o644) -> None:
        self._add(iso_path, host_path, os.path.getsize(host_path), mtime, mode)

    def add_vfs(self, vfs: PosixVfs) -> None:
        for path, node in vfs.walk_sorted():
            if node.node_type == VfsNodeType.DIRECTORY:
                if path != "/":
                    self.add_directory(path, node.mtime)
            elif node.node_type == VfsNodeType.REGULAR_FILE:
                self.add_file(path, node.data, mtime=node.mtime, mode=node.mode)

    def set_bios_boot(self, iso_path: str, load_sectors: int = 4, boot_info_table: bool = True, catalog_path: Optional[str] = None) -> None:
        """Make the file at *iso_path* (e.g. isolinux.bin) the El Torito BIOS image."""
        self._bios_path = self._norm(iso_path)
        self._bios_load_sectors = load_sectors
        self._bios_boot_info_table = boot_info_table
        if catalog_path:
            self._catalog_path = self._norm(catalog_path)
            self.add_directory(str(PurePosixPath(self._catalog_path).parent))

    def set_efi_image(self, image: Source) -> None:
        self._efi_image = image
        self._efi_size = len(image) if isinstance(image, (bytes, bytearray)) else os.path.getsize(image)

    def set_isohybrid_mbr(self, code: bytes) -> None:
        if len(code) < 432:
            raise Iso9660BuildError("isohybrid MBR template must be at least 432 bytes")
        self._mbr_code = bytes(code[:432])

    def set_boot_images(self, bios_boot_image: bytes = b"", efi_boot_image: bytes = b"") -> None:
        """Legacy API: raw BIOS image (stored hidden, no boot-info-table) and EFI image."""
        self._bios_inline = bytes(bios_boot_image) if bios_boot_image else b""
        if efi_boot_image:
            self.set_efi_image(bytes(efi_boot_image))

    # ------------------------------------------------------------------
    # Naming
    # ------------------------------------------------------------------

    @staticmethod
    def _iso_name(name: str, is_dir: bool) -> str:
        up = name.upper()
        if is_dir:
            s = re.sub(r"[^A-Z0-9_]", "_", up)[:31] or "DIR"
            return s
        if "." in up and not up.startswith("."):
            base, ext = up.rsplit(".", 1)
        else:
            base, ext = up, ""
        base = re.sub(r"[^A-Z0-9_]", "_", base) or "FILE"
        ext = re.sub(r"[^A-Z0-9_]", "_", ext)[:8]
        base = base[: 30 - len(ext) - 1]
        return f"{base}.{ext}"

    def _iso_filename(self, name: str, is_dir: bool) -> bytes:
        """Kept for API compatibility."""
        if name == ".":
            return b"\x00"
        if name == "..":
            return b"\x01"
        n = self._iso_name(name, is_dir)
        return (n if is_dir else n + ";1").encode("ascii")

    # ------------------------------------------------------------------
    # Records
    # ------------------------------------------------------------------

    def _rr_fields(self, e: Optional[_Entry], name: Optional[str], is_dir: bool, root_dot: bool = False, ino: int = 0) -> bytes:
        if not self.rock_ridge:
            return b""
        out = b""
        if root_dot:
            out += b"SP" + bytes([7, 1, 0xBE, 0xEF, 0])
        mode = (0o040000 | (e.mode if e else 0o755)) if is_dir else (0o100000 | (e.mode if e else 0o644))
        nlink = 2 if is_dir else 1
        out += b"PX" + bytes([44, 1]) + _both32(mode) + _both32(nlink) + _both32(0) + _both32(0) + _both32(ino)
        if name is not None:
            nb = name.encode("utf-8")
            out += b"NM" + bytes([5 + len(nb), 1, 0]) + nb
        if root_dot:
            ident, desc, src = b"RRIP_1991A", b"ROCK RIDGE", b"TORITO"
            out += b"ER" + bytes([8 + len(ident) + len(desc) + len(src), 1, len(ident), len(desc), len(src), 1]) + ident + desc + src
        return out

    def _record(self, ident: bytes, lba: int, size: int, is_dir: bool, ts: int, su: bytes = b"") -> bytes:
        n = len(ident)
        pad = 1 if n % 2 == 0 else 0
        rec_len = 33 + n + pad + len(su)
        if rec_len % 2:
            su += b"\x00"
            rec_len += 1
        if rec_len > 255:
            raise Iso9660BuildError(f"directory record too long for {ident!r}")
        return (
            struct.pack("<BB", rec_len, 0) + _both32(lba) + _both32(size) + _date7(ts)
            + bytes([0x02 if is_dir else 0x00, 0, 0]) + _both16(1) + bytes([n]) + ident
            + (b"\x00" * pad) + su
        )

    @staticmethod
    def _pack_records(records: List[bytes]) -> bytes:
        sectors: List[bytearray] = [bytearray(SECTOR_SIZE)]
        off = 0
        for r in records:
            if off + len(r) > SECTOR_SIZE:
                sectors.append(bytearray(SECTOR_SIZE))
                off = 0
            sectors[-1][off: off + len(r)] = r
            off += len(r)
        return b"".join(sectors)

    # ------------------------------------------------------------------
    # Assembly
    # ------------------------------------------------------------------

    def _plan(self) -> Tuple[List[str], Dict[str, List[str]], int]:
        children: Dict[str, List[str]] = {p: [] for p, e in self._entries.items() if e.is_dir}
        for p in self._entries:
            if p != "/":
                children[str(PurePosixPath(p).parent)].append(p)
        # ISO names with per-directory collision handling.
        for d, kids in children.items():
            used: Dict[str, int] = {}
            for k in sorted(kids):
                e = self._entries[k]
                n = self._iso_name(PurePosixPath(k).name, e.is_dir)
                base = n
                i = 1
                while n in used:
                    tail = f"~{i}"
                    if e.is_dir:
                        n = base[: 31 - len(tail)] + tail
                    else:
                        b, x = base.rsplit(".", 1)
                        n = f"{b[: 30 - len(x) - 1 - len(tail)]}{tail}.{x}"
                    i += 1
                used[n] = 1
                e.iso_name = (n if e.is_dir else n + ";1").encode("ascii")
            kids.sort(key=lambda k: self._entries[k].iso_name)
        # BFS directory order (= path table order)
        order: List[str] = []
        q = deque(["/"])
        while q:
            d = q.popleft()
            order.append(d)
            for k in children[d]:
                if self._entries[k].is_dir:
                    q.append(k)
        return order, children, len(order)

    def _dir_extent(self, d: str, children: Dict[str, List[str]], lbas: Dict[str, int], sizes: Dict[str, int], inos: Dict[str, int]) -> bytes:
        e = self._entries[d]
        parent = str(PurePosixPath(d).parent) if d != "/" else "/"
        recs = [
            self._record(b"\x00", lbas[d], sizes[d], True, e.mtime, self._rr_fields(e, None, True, root_dot=(d == "/"), ino=inos[d])),
            self._record(b"\x01", lbas[parent], sizes[parent], True, self._entries[parent].mtime, self._rr_fields(self._entries[parent], None, True, ino=inos[parent])),
        ]
        for k in children[d]:
            c = self._entries[k]
            if c.is_dir:
                recs.append(self._record(c.iso_name, lbas[k], sizes[k], True, c.mtime, self._rr_fields(c, PurePosixPath(k).name, True, ino=inos[k])))
            else:
                recs.append(self._record(c.iso_name, c.lba, c.size, False, c.mtime, self._rr_fields(c, PurePosixPath(k).name, False, ino=inos[k])))
        return self._pack_records(recs)

    def write(self, out: BinaryIO) -> int:
        """Write the image to a seekable binary stream. Returns the size in bytes."""
        has_boot = bool(self._bios_path or self._bios_inline or self._efi_image is not None)
        if self._bios_path and self._bios_path not in self._entries:
            raise Iso9660BuildError(f"BIOS boot file {self._bios_path} is not in the image")

        # The boot catalog is exposed as a file when requested.
        if self._catalog_path:
            self._entries[self._catalog_path] = _Entry(self._catalog_path, False, source=b"\x00" * SECTOR_SIZE, size=SECTOR_SIZE, mtime=self._creation_time)

        order, children, _ = self._plan()
        inos = {p: i + 1 for i, p in enumerate(sorted(self._entries))}

        # Directory sizes (records depend only on names/sizes, not LBAs).
        sizes: Dict[str, int] = {}
        dummy_lbas = {p: 0 for p in self._entries}
        for d in order:
            for k in children[d]:
                self._entries[k].lba = 0
            sizes[d] = len(self._dir_extent(d, children, dummy_lbas, {p: 0 for p in order}, inos))

        # Path tables
        dir_num = {d: i + 1 for i, d in enumerate(order)}

        def path_table(lbas: Dict[str, int], big: bool) -> bytes:
            out_b = bytearray()
            for d in order:
                name = b"\x00" if d == "/" else self._entries[d].iso_name
                parent = dir_num[str(PurePosixPath(d).parent)] if d != "/" else 1
                fmt = ">BBIH" if big else "<BBIH"
                out_b += struct.pack(fmt, len(name), 0, lbas.get(d, 0), parent) + name
                if len(name) % 2:
                    out_b += b"\x00"
            return bytes(out_b)

        pt_size = len(path_table({}, False))
        pt_secs = max(1, -(-pt_size // SECTOR_SIZE))

        lba = 16
        pvd_lba = lba
        lba += 1
        brvd_lba = 0
        if has_boot:
            brvd_lba = lba
            lba += 1
        term_lba = lba
        lba += 1
        ptl_lba = lba
        lba += pt_secs
        ptm_lba = lba
        lba += pt_secs
        dir_lbas: Dict[str, int] = {}
        for d in order:
            dir_lbas[d] = lba
            lba += sizes[d] // SECTOR_SIZE
        catalog_lba = 0
        if has_boot:
            if self._catalog_path:
                catalog_lba = lba
                self._entries[self._catalog_path].lba = lba
            else:
                catalog_lba = lba
            lba += 1
        # File extents: BIOS image first, big files last (keeps boot bits early).
        files = [p for p, e in self._entries.items() if not e.is_dir and p != self._catalog_path]
        files.sort(key=lambda p: (0 if p == self._bios_path else 1, self._entries[p].size > (64 << 20), p))
        for p in files:
            e = self._entries[p]
            e.lba = lba if e.size else 0
            lba += -(-e.size // SECTOR_SIZE)
        bios_inline_lba = 0
        if self._bios_inline:
            bios_inline_lba = lba
            lba += -(-len(self._bios_inline) // SECTOR_SIZE)
        efi_lba = 0
        if self._efi_image is not None:
            efi_lba = lba
            lba += -(-self._efi_size // SECTOR_SIZE)
        # Trailing padding: 150 sectors (classic CD run-out), then round up.
        lba += 150
        total_bytes = lba * SECTOR_SIZE
        if self.pad_to:
            total_bytes = -(-total_bytes // self.pad_to) * self.pad_to
        total_sectors = total_bytes // SECTOR_SIZE

        self.layout = {"pvd": pvd_lba, "catalog": catalog_lba, "efi": efi_lba, "efi_size": self._efi_size,
                       "bios": self._entries[self._bios_path].lba if self._bios_path else bios_inline_lba,
                       "total_sectors": total_sectors}

        # ---------------- write ----------------
        out.seek(0)
        out.truncate(0)

        def put(at_lba: int, data: bytes) -> None:
            out.seek(at_lba * SECTOR_SIZE)
            out.write(data)

        # System area / MBR
        if self._mbr_code or self._efi_image is not None:
            put(0, self._build_mbr(total_bytes, efi_lba))

        root_rec = self._record(b"\x00", dir_lbas["/"], sizes["/"], True, self._creation_time)
        pvd = bytearray(SECTOR_SIZE)
        pvd[0] = ISO_VD_PRIMARY
        pvd[1:6] = ISO_STANDARD_ID
        pvd[6] = 1
        pvd[8:40] = _pad_str(self.system_id, 32)
        pvd[40:72] = _pad_str(self.volume_id, 32)
        pvd[80:88] = _both32(total_sectors)
        pvd[120:124] = _both16(1)
        pvd[124:128] = _both16(1)
        pvd[128:132] = _both16(SECTOR_SIZE)
        pvd[132:140] = _both32(pt_size)
        pvd[140:144] = struct.pack("<I", ptl_lba)
        pvd[148:152] = struct.pack(">I", ptm_lba)
        pvd[156:190] = root_rec
        pvd[190:318] = _pad_str(self.volume_id, 128)
        pvd[318:446] = _pad_str(self.publisher_id, 128)
        pvd[446:574] = _pad_str(self.publisher_id, 128)
        pvd[574:702] = _pad_str(self.application_id, 128)
        pvd[702:813] = b" " * 111
        pvd[813:830] = _date17(self._creation_time)
        pvd[830:847] = _date17(self._creation_time)
        pvd[847:864] = b"0000000000000000\x00"
        pvd[864:881] = _date17(self._creation_time)
        pvd[881] = 1
        put(pvd_lba, bytes(pvd))

        if has_boot:
            br = bytearray(SECTOR_SIZE)
            br[0] = ISO_VD_BOOT_RECORD
            br[1:6] = ISO_STANDARD_ID
            br[6] = 1
            br[7:39] = EL_TORITO_SYS_ID.ljust(32, b"\x00")
            br[71:75] = struct.pack("<I", catalog_lba)
            put(brvd_lba, bytes(br))
        term = bytearray(SECTOR_SIZE)
        term[0] = ISO_VD_SET_TERMINATOR
        term[1:6] = ISO_STANDARD_ID
        term[6] = 1
        put(term_lba, bytes(term))

        put(ptl_lba, path_table(dir_lbas, False))
        put(ptm_lba, path_table(dir_lbas, True))
        for d in order:
            put(dir_lbas[d], self._dir_extent(d, children, dir_lbas, sizes, inos))

        if has_boot:
            bios_lba = self._entries[self._bios_path].lba if self._bios_path else bios_inline_lba
            put(catalog_lba, self._build_catalog(bios_lba, efi_lba))

        for p in files:
            e = self._entries[p]
            if not e.size:
                continue
            if p == self._bios_path and self._bios_boot_info_table:
                data = self._read_source(e.source)
                data = self._patch_boot_info(data, pvd_lba, e.lba)
                put(e.lba, data)
            else:
                self._copy_source(out, e.lba * SECTOR_SIZE, e.source)
        if self._bios_inline:
            put(bios_inline_lba, self._bios_inline)
        if self._efi_image is not None:
            self._copy_source(out, efi_lba * SECTOR_SIZE, self._efi_image)

        out.seek(total_bytes - 1)
        out.write(b"\x00")
        out.truncate(total_bytes)
        out.flush()
        return total_bytes

    def build(self) -> bytes:
        buf = io.BytesIO()
        self.write(buf)
        return buf.getvalue()

    def write_to_file(self, path: str) -> int:
        tmp = path + ".part"
        with open(tmp, "w+b") as fh:
            size = self.write(fh)
        os.replace(tmp, path)
        return size

    # ------------------------------------------------------------------
    @staticmethod
    def _read_source(src: Optional[Source]) -> bytes:
        if src is None:
            return b""
        if isinstance(src, (bytes, bytearray)):
            return bytes(src)
        with open(src, "rb") as fh:
            return fh.read()

    @staticmethod
    def _copy_source(out: BinaryIO, offset: int, src: Optional[Source]) -> None:
        out.seek(offset)
        if src is None:
            return
        if isinstance(src, (bytes, bytearray)):
            out.write(src)
        else:
            with open(src, "rb") as fh:
                shutil.copyfileobj(fh, out, 8 << 20)

    @staticmethod
    def _patch_boot_info(data: bytes, pvd_lba: int, file_lba: int) -> bytes:
        """El Torito boot-info-table (mkisofs -boot-info-table)."""
        buf = bytearray(data)
        if len(buf) < 64:
            return bytes(buf)
        padded = bytes(buf) + b"\x00" * ((-len(buf)) % 4)
        csum = 0
        for (w,) in struct.iter_unpack("<I", padded[64:]):
            csum = (csum + w) & 0xFFFFFFFF
        struct.pack_into("<IIII", buf, 8, pvd_lba, file_lba, len(data), csum)
        buf[24:64] = b"\x00" * 40
        return bytes(buf)

    def _build_catalog(self, bios_lba: int, efi_lba: int) -> bytes:
        cat = bytearray(SECTOR_SIZE)
        val = bytearray(32)
        val[0] = EL_TORITO_HEADER_ID
        val[1] = EL_TORITO_PLATFORM_X86
        val[4:28] = self.application_id.encode("ascii", "replace")[:24].ljust(24, b"\x00")
        val[30:32] = EL_TORITO_KEY_BYTES
        csum = (-sum(struct.unpack("<16H", bytes(val)))) & 0xFFFF
        struct.pack_into("<H", val, 28, csum)
        cat[0:32] = val
        de = bytearray(32)
        if bios_lba:
            de[0] = EL_TORITO_BOOTABLE
            de[1] = EL_TORITO_MEDIA_NO_EMULATION
            count = self._bios_load_sectors if self._bios_path else max(1, -(-len(self._bios_inline) // 512))
            struct.pack_into("<HBBHI", de, 2, 0, 0, 0, min(count, 0xFFFF), bios_lba)
        cat[32:64] = de
        if efi_lba:
            sh = bytearray(32)
            sh[0] = EL_TORITO_SECTION_HEADER_LAST
            sh[1] = EL_TORITO_PLATFORM_EFI
            struct.pack_into("<H", sh, 2, 1)
            cat[64:96] = sh
            se = bytearray(32)
            se[0] = EL_TORITO_BOOTABLE
            se[1] = EL_TORITO_MEDIA_NO_EMULATION
            count = -(-self._efi_size // 512)
            # Values that do not fit mean "whole image" to UEFI (count < 2 → to end).
            struct.pack_into("<HBBHI", se, 2, 0, 0, 0, count if count <= 0xFFFF else 0, efi_lba)
            cat[96:128] = se
        return bytes(cat)

    @staticmethod
    def _chs(lba: int) -> bytes:
        heads, secs = 64, 32
        c = lba // (heads * secs)
        if c > 1023:
            return b"\xFE\xFF\xFF"
        h = (lba // secs) % heads
        s = lba % secs + 1
        return bytes([h, ((c >> 2) & 0xC0) | s, c & 0xFF])

    def _build_mbr(self, total_bytes: int, efi_lba: int) -> bytes:
        mbr = bytearray(LBA_SIZE)
        bios_lba = self._entries[self._bios_path].lba if self._bios_path else 0
        if self._mbr_code:
            mbr[0:432] = self._mbr_code
            struct.pack_into("<II", mbr, 432, bios_lba * 4, 0)
        struct.pack_into("<I", mbr, 440, sum(self.volume_id.encode()) * 2654435761 & 0xFFFFFFFF)
        total_512 = total_bytes // LBA_SIZE

        def entry(boot: int, ptype: int, start: int, count: int) -> bytes:
            return bytes([boot]) + self._chs(start) + bytes([ptype]) + self._chs(start + max(count, 1) - 1) + struct.pack("<II", start, count)

        if efi_lba:
            esp_start = efi_lba * 4
            esp_count = -(-self._efi_size // LBA_SIZE)
            # p1: boot partition ending where the ESP begins (type 0 like xorriso's
            # isohybrid layout, so firmware does not see overlapping partitions)
            mbr[446:462] = entry(0x80, 0x00, 0, esp_start)
            mbr[462:478] = entry(0x00, 0xEF, esp_start, esp_count)
        else:
            mbr[446:462] = entry(0x80, 0x17, 0, total_512)
        mbr[510:512] = b"\x55\xAA"
        return bytes(mbr)


# ---------------------------------------------------------------------------
# Convenience functions (API kept from Torito 1.x)
# ---------------------------------------------------------------------------


def build_hybrid_iso(
    files: Dict[str, bytes],
    bios_boot_image: bytes = b"",
    efi_boot_image: bytes = b"",
    volume_id: str = "TORITO",
    system_id: str = "LINUX",
    publisher_id: str = "",
    application_id: str = "",
) -> bytes:
    b = Iso9660Builder(volume_id=volume_id, system_id=system_id,
                       publisher_id=publisher_id or "TORITO", application_id=application_id or "TORITO")
    for path, data in files.items():
        b.add_file(path, data)
    if bios_boot_image or efi_boot_image:
        b.set_boot_images(bios_boot_image=bios_boot_image, efi_boot_image=efi_boot_image)
    return b.build()


def build_hybrid_iso_from_vfs(
    vfs: PosixVfs,
    bios_boot_image: bytes = b"",
    efi_boot_image: bytes = b"",
    volume_id: str = "TORITO",
    system_id: str = "LINUX",
    publisher_id: str = "",
    application_id: str = "",
) -> bytes:
    b = Iso9660Builder(volume_id=volume_id, system_id=system_id,
                       publisher_id=publisher_id or "TORITO", application_id=application_id or "TORITO")
    b.add_vfs(vfs)
    if bios_boot_image or efi_boot_image:
        b.set_boot_images(bios_boot_image=bios_boot_image, efi_boot_image=efi_boot_image)
    return b.build()
