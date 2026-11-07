"""
torito.inspect — ISO Image Inspector & Verifier
===============================================
Reads back a hybrid ISO and checks the things that decide whether it boots:
MBR/isohybrid partition table, ISO9660 volume descriptors and directory
tree (Rock Ridge aware), El Torito catalog (checksum, BIOS entry +
boot-info-table, EFI entry), the EFI System Partition's FAT type and boot
loader, the kernel/initramfs/SquashFS payloads and the SquashFS superblock.

``verify_iso(path)`` returns a list of problems (empty == looks bootable);
``inspect_iso(path)`` prints a human-readable report.
"""

from __future__ import annotations

import os
import struct
from typing import BinaryIO, Dict, List, Optional, Tuple

SECTOR_SIZE = 2048
_COMP = {1: "gzip", 2: "lzma", 3: "lzo", 4: "xz", 5: "lz4", 6: "zstd"}


def _read(fh: BinaryIO, off: int, n: int) -> bytes:
    fh.seek(off)
    return fh.read(n)


def _rr_name(su: bytes) -> Optional[str]:
    i = 0
    name = b""
    found = False
    while i + 4 <= len(su):
        sig, ln = su[i:i + 2], su[i + 2]
        if ln < 4:
            break
        if sig == b"NM":
            name += su[i + 5:i + ln]
            found = True
        i += ln
    return name.decode("utf-8", "replace") if found else None


def iso_tree(fh: BinaryIO) -> Dict[str, Tuple[int, int, bool]]:
    """Map path → (lba, size, is_dir) using Rock Ridge names when present."""
    pvd = _read(fh, 16 * SECTOR_SIZE, SECTOR_SIZE)
    root = pvd[156:190]
    out: Dict[str, Tuple[int, int, bool]] = {"/": (struct.unpack_from("<I", root, 2)[0], struct.unpack_from("<I", root, 10)[0], True)}
    stack = ["/"]
    seen = set()
    while stack:
        d = stack.pop()
        lba, size, _ = out[d]
        if lba in seen:
            continue
        seen.add(lba)
        data = _read(fh, lba * SECTOR_SIZE, size)
        off = 0
        while off < len(data):
            ln = data[off]
            if ln == 0:
                off = (off // SECTOR_SIZE + 1) * SECTOR_SIZE
                continue
            rec = data[off:off + ln]
            off += ln
            idlen = rec[32]
            ident = rec[33:33 + idlen]
            if ident in (b"\x00", b"\x01"):
                continue
            su_start = 33 + idlen + (1 if idlen % 2 == 0 else 0)
            name = _rr_name(rec[su_start:]) or ident.decode("ascii", "replace").split(";")[0].rstrip(".").lower()
            is_dir = bool(rec[25] & 0x02)
            p = (d.rstrip("/") + "/" + name)
            out[p] = (struct.unpack_from("<I", rec, 2)[0], struct.unpack_from("<I", rec, 10)[0], is_dir)
            if is_dir:
                stack.append(p)
    return out


def _fat_info(bpb: bytes) -> Dict[str, object]:
    spc = bpb[13]
    rsv = struct.unpack_from("<H", bpb, 14)[0]
    nfats = bpb[16]
    root_ent = struct.unpack_from("<H", bpb, 17)[0]
    tot = struct.unpack_from("<H", bpb, 19)[0] or struct.unpack_from("<I", bpb, 32)[0]
    fsz = struct.unpack_from("<H", bpb, 22)[0] or struct.unpack_from("<I", bpb, 36)[0]
    if spc == 0:
        return {"valid": False}
    clusters = (tot - rsv - nfats * fsz - (root_ent * 32 + 511) // 512) // spc
    kind = "FAT12" if clusters < 4085 else ("FAT16" if clusters < 65525 else "FAT32")
    label_field = bpb[54:62] if kind != "FAT32" else bpb[82:90]
    return {"valid": bpb[510:512] == b"\x55\xAA", "clusters": clusters, "type": kind,
            "declared": label_field.decode("ascii", "replace").strip(), "bytes": tot * 512,
            "spc": spc, "rsv": rsv, "nfats": nfats, "fsz": fsz, "root_ent": root_ent}


def _fat_has_file(img_reader, info: Dict[str, object], path: List[str]) -> bool:
    """Walk a FAT16/32 directory chain looking for a path (case-insensitive, LFN aware)."""
    spc, rsv, nf, fsz, rent = (int(info[k]) for k in ("spc", "rsv", "nfats", "fsz", "root_ent"))  # type: ignore[arg-type]
    fat_off = rsv * 512
    root_secs = (rent * 32 + 511) // 512
    data_start = (rsv + nf * fsz + root_secs) * 512
    cs = spc * 512
    is32 = info["type"] == "FAT32"

    def chain(c: int) -> bytes:
        out = b""
        for _ in range(100000):
            out += img_reader(data_start + (c - 2) * cs, cs)
            nxt = struct.unpack("<I", img_reader(fat_off + c * 4, 4))[0] & 0x0FFFFFFF if is32 else struct.unpack("<H", img_reader(fat_off + c * 2, 2))[0]
            if nxt >= (0x0FFFFFF8 if is32 else 0xFFF8) or nxt < 2:
                break
            c = nxt
        return out

    if is32:
        cur = chain(2)
    else:
        cur = img_reader((rsv + nf * fsz) * 512, rent * 32)
    for depth, comp in enumerate(path):
        lfn = ""
        hit = None
        for i in range(0, len(cur), 32):
            e = cur[i:i + 32]
            if not e or e[0] == 0:
                break
            if e[0] == 0xE5:
                lfn = ""
                continue
            if e[11] == 0x0F:
                part = (e[1:11] + e[14:26] + e[28:32]).decode("utf-16le", "replace").split("\x00")[0].rstrip("￿")
                lfn = part + lfn
                continue
            short = e[0:8].decode("ascii", "replace").strip() + ("." + e[8:11].decode("ascii", "replace").strip() if e[8:11].strip() else "")
            name = lfn or short
            lfn = ""
            if name.lower() == comp.lower() or short.lower() == comp.lower():
                hit = e
                break
        if hit is None:
            return False
        clus = (struct.unpack_from("<H", hit, 20)[0] << 16) | struct.unpack_from("<H", hit, 26)[0]
        if depth < len(path) - 1:
            if not hit[11] & 0x10:
                return False
            cur = chain(clus)
    return True


def _squashfs_problems(fh: BinaryIO, off: int, size: int) -> Tuple[List[str], Dict[str, object]]:
    sb = _read(fh, off, 96)
    probs: List[str] = []
    if len(sb) < 96 or sb[:4] != b"hsqs":
        return ["squashfs magic missing"], {}
    f = struct.unpack("<IIIIIHHHHHHQQQQQQQQ", sb)
    info = {"inodes": f[1], "block_size": f[3], "fragments": f[4], "compression": _COMP.get(f[5], f[5]),
            "version": f"{f[9]}.{f[10]}", "bytes_used": f[12], "ids": f[8]}
    bytes_used, id_t, xattr_t, inode_t, dir_t, frag_t = f[12], f[13], f[14], f[15], f[16], f[17]
    inv = 0xFFFFFFFFFFFFFFFF
    if (f[9], f[10]) != (4, 0):
        probs.append(f"squashfs version {f[9]}.{f[10]} (kernel needs 4.0)")
    if 1 << f[6] != f[3]:
        probs.append("squashfs block_log does not match block_size")
    if bytes_used > size:
        probs.append(f"squashfs bytes_used {bytes_used} exceeds file size {size}")
    if not (inode_t < dir_t <= (frag_t if frag_t != inv else id_t) and id_t < bytes_used):
        probs.append("squashfs table order violates kernel sanity checks")
    if xattr_t != inv and xattr_t >= bytes_used:
        probs.append("squashfs xattr table outside image")
    return probs, info


def verify_iso(iso_path: str) -> List[str]:
    problems: List[str] = []
    size = os.path.getsize(iso_path)
    with open(iso_path, "rb") as fh:
        if size % SECTOR_SIZE:
            problems.append("image size is not a multiple of 2048")
        pvd = _read(fh, 16 * SECTOR_SIZE, SECTOR_SIZE)
        if pvd[0] != 1 or pvd[1:6] != b"CD001":
            return problems + ["no ISO9660 primary volume descriptor"]
        label = pvd[40:72].decode("ascii", "replace").strip()
        tree = iso_tree(fh)

        # El Torito
        brvd = _read(fh, 17 * SECTOR_SIZE, SECTOR_SIZE)
        if brvd[1:6] != b"CD001" or brvd[0] != 0 or not brvd[7:30].startswith(b"EL TORITO SPECIFICATION"):
            problems.append("no El Torito boot record (image is not bootable)")
            return problems
        cat_lba = struct.unpack_from("<I", brvd, 71)[0]
        cat = _read(fh, cat_lba * SECTOR_SIZE, SECTOR_SIZE)
        if cat[0] != 1 or cat[30:32] != b"\x55\xAA" or sum(struct.unpack("<16H", cat[:32])) & 0xFFFF:
            problems.append("El Torito validation entry invalid (checksum/key)")
        bios_ok = cat[32] == 0x88
        if bios_ok:
            count, rba = struct.unpack_from("<HI", cat, 38)
            boot = _read(fh, rba * SECTOR_SIZE, 64)
            files_at = {v[0]: (k, v[1]) for k, v in tree.items() if not v[2]}
            if rba not in files_at:
                problems.append("BIOS boot image is not a file in the ISO tree (ISOLINUX cannot find itself)")
            else:
                path, flen = files_at[rba]
                bi_pvd, bi_file, bi_len, _ = struct.unpack_from("<IIII", boot, 8)
                if path.endswith("isolinux.bin") and (bi_pvd != 16 or bi_file != rba or bi_len != flen):
                    problems.append("isolinux.bin boot-info-table not patched")
            if count == 0:
                problems.append("BIOS boot entry load count is 0")
        # EFI
        efi = None
        off = 64
        while off + 64 <= SECTOR_SIZE and cat[off] in (0x90, 0x91):
            n = struct.unpack_from("<H", cat, off + 2)[0]
            plat = cat[off + 1]
            for j in range(n):
                e = cat[off + 32 * (j + 1): off + 32 * (j + 2)]
                if plat == 0xEF and e[0] == 0x88:
                    efi = struct.unpack_from("<HI", e, 6)
            last = cat[off] == 0x91
            off += 32 * (n + 1)
            if last:
                break
        if not bios_ok and efi is None:
            problems.append("El Torito catalog has no bootable entry")
        if efi is not None:
            count, rba = efi
            bpb = _read(fh, rba * SECTOR_SIZE, 512)
            fi = _fat_info(bpb)
            if not fi.get("valid"):
                problems.append("EFI image has no valid FAT boot sector")
            else:
                if str(fi["declared"]) != str(fi["type"]):
                    problems.append(f"ESP declares {fi['declared']} but has {fi['clusters']} clusters ({fi['type']}) — firmware will misread it")
                reader = lambda o, n, base=rba * SECTOR_SIZE: _read(fh, base + o, n)  # noqa: E731
                if not _fat_has_file(reader, fi, ["EFI", "BOOT", "BOOTX64.EFI"]):
                    problems.append("ESP lacks /EFI/BOOT/BOOTX64.EFI")
        # MBR / isohybrid
        mbr = _read(fh, 0, 512)
        if mbr[510:512] == b"\x55\xAA":
            parts = []
            for i in range(4):
                e = mbr[446 + 16 * i: 462 + 16 * i]
                t = e[4]
                s, c = struct.unpack_from("<II", e, 8)
                if t:
                    parts.append((s, c, t))
            for i, a in enumerate(parts):
                for b in parts[i + 1:]:
                    if a[0] < b[0] + b[1] and b[0] < a[0] + a[1]:
                        problems.append("MBR partitions overlap (UEFI firmware rejects the table when booting from USB)")
        # payloads
        sfs = [k for k in tree if k.endswith(".sfs") or k.endswith(".squashfs")]
        if not sfs:
            problems.append("no squashfs root filesystem on the image")
        for k in sfs:
            lba, ln, _ = tree[k]
            p, _info = _squashfs_problems(fh, lba * SECTOR_SIZE, ln)
            problems += [f"{k}: {x}" for x in p]
        for k, (lba, ln, isdir) in tree.items():
            if not isdir and k.endswith("vmlinuz"):
                hdr = _read(fh, lba * SECTOR_SIZE + 0x202, 4)
                if hdr != b"HdrS":
                    problems.append(f"{k} is not a Linux kernel image")
        cfg = tree.get("/boot/syslinux/syslinux.cfg")
        if cfg and label:
            text = _read(fh, cfg[0] * SECTOR_SIZE, cfg[1]).decode("utf-8", "replace")
            if "torito.label=" in text and f"torito.label={label}" not in text:
                problems.append("boot menu label does not match the volume label")
    return problems


def inspect_iso(iso_path: str) -> None:
    if not os.path.isfile(iso_path):
        raise FileNotFoundError(f"ISO file not found: {iso_path}")
    size = os.path.getsize(iso_path)
    print("=" * 72)
    print(f"TORITO ISO INSPECTOR: {os.path.basename(iso_path)}")
    print("=" * 72)
    print(f"Size: {size:,} bytes ({size / 1048576:.1f} MiB), {size // SECTOR_SIZE:,} sectors")
    with open(iso_path, "rb") as fh:
        mbr = _read(fh, 0, 512)
        print("\n[MBR]")
        sig = "55AA" if mbr[510:512] == b"\x55\xAA" else "none"
        code = "isohybrid" if any(mbr[:432]) else "none"
        print(f"  signature: {sig}; boot code: {code}")
        for i in range(4):
            e = mbr[446 + 16 * i: 462 + 16 * i]
            s, c = struct.unpack_from("<II", e, 8)
            if e[4] or c:
                print(f"  p{i + 1}: active={'yes' if e[0] == 0x80 else 'no'} type=0x{e[4]:02X} start={s} sectors={c}")
        pvd = _read(fh, 16 * SECTOR_SIZE, SECTOR_SIZE)
        if pvd[1:6] != b"CD001":
            print("\nNo ISO9660 volume.")
            return
        print("\n[ISO9660]")
        print(f"  volume id:   {pvd[40:72].decode('ascii', 'replace').strip()}")
        print(f"  application: {pvd[574:702].decode('ascii', 'replace').strip()}")
        print(f"  volume size: {struct.unpack_from('<I', pvd, 80)[0]:,} sectors")
        tree = iso_tree(fh)
        print("\n[Files]")
        for k in sorted(tree):
            lba, ln, isdir = tree[k]
            if not isdir:
                print(f"  {k:<44} {ln:>14,} B  @LBA {lba}")
        brvd = _read(fh, 17 * SECTOR_SIZE, SECTOR_SIZE)
        if brvd[0] == 0 and brvd[1:6] == b"CD001":
            cat_lba = struct.unpack_from("<I", brvd, 71)[0]
            cat = _read(fh, cat_lba * SECTOR_SIZE, SECTOR_SIZE)
            print(f"\n[El Torito] catalog @LBA {cat_lba}")
            count, rba = struct.unpack_from("<HI", cat, 38)
            print(f"  BIOS entry: {'bootable' if cat[32] == 0x88 else 'not bootable'}, load {count}×512 B @LBA {rba}")
            if cat[64] in (0x90, 0x91):
                c2, r2 = struct.unpack_from("<HI", cat, 96 + 6)
                print(f"  EFI  entry: platform 0x{cat[65]:02X}, {'bootable' if cat[96] == 0x88 else 'not bootable'}, count {c2} @LBA {r2}")
                fi = _fat_info(_read(fh, r2 * SECTOR_SIZE, 512))
                if fi.get("valid"):
                    print(f"  ESP: {fi['type']} ({fi['clusters']} clusters, declared {fi['declared']}), {int(fi['bytes']) / 1048576:.1f} MiB")
        for k in sorted(tree):
            if k.endswith(".sfs") or k.endswith(".squashfs"):
                lba, ln, _ = tree[k]
                probs, info = _squashfs_problems(fh, lba * SECTOR_SIZE, ln)
                print(f"\n[SquashFS {k}]")
                for kk, vv in info.items():
                    print(f"  {kk}: {vv}")
    problems = verify_iso(iso_path)
    print("\n[Verification]")
    if problems:
        for p in problems:
            print(f"  ✗ {p}")
    else:
        print("  ✓ structure looks bootable (BIOS + UEFI)")
    print("=" * 72)
