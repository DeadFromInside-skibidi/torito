"""
torito.inspect — ISO Image Structure Inspector
=================================================
Examines and validates the internal binary architecture of any bootable
Linux ISO image: Protective MBR, Primary/Backup GPT, ISO9660 Volume
Descriptors (PVD/BRVD), El Torito Boot Catalog (BIOS & UEFI), embedded
SquashFS 4.0 filesystems, and FAT32 EFI System Partitions.
"""

from __future__ import annotations

import os
import struct
import zlib
from dataclasses import dataclass
from typing import Dict, List, Optional


SECTOR_SIZE = 2048
MBR_SIZE = 512
GPT_HEADER_SIZE = 92
EFI_SYSTEM_PARTITION_GUID = "C12A7328-F81F-11D2-BA4B-00A0C93EC93B"


def _format_uuid(raw16: bytes) -> str:
    """Format a 16-byte mixed-endian GUID into standard canonical string."""
    d1, d2, d3 = struct.unpack("<IHH", raw16[:8])
    d4 = raw16[8:10].hex().upper()
    d5 = raw16[10:16].hex().upper()
    return f"{d1:08X}-{d2:04X}-{d3:04X}-{d4}-{d5}"


def inspect_iso(iso_path: str) -> None:
    """
    Examine and print a diagnostic report of the ISO image structure.
    """
    if not os.path.isfile(iso_path):
        raise FileNotFoundError(f"ISO file not found: {iso_path}")

    file_size = os.path.getsize(iso_path)
    total_sectors = file_size // SECTOR_SIZE

    print("=" * 70)
    print(f"TORITO ISO IMAGE INSPECTOR: {os.path.basename(iso_path)}")
    print("=" * 70)
    print(f"File Path:       {os.path.abspath(iso_path)}")
    print(f"File Size:       {file_size:,} bytes ({file_size / (1024 * 1024):.2f} MB)")
    print(f"Total Sectors:   {total_sectors:,} (2048 bytes/sector)")
    print(f"Sector Alignment:{'Valid (2048-byte aligned)' if file_size % SECTOR_SIZE == 0 else 'INVALID'}")
    print()

    with open(iso_path, "rb") as fh:
        # ──────────────────────────────────────────────────────────
        # 1. Master Boot Record (MBR) at LBA 0 (Offset 0)
        # ──────────────────────────────────────────────────────────
        fh.seek(0)
        mbr_data = fh.read(512)
        mbr_sig = struct.unpack("<H", mbr_data[510:512])[0]
        has_mbr = (mbr_sig == 0xAA55)

        print("[1] Master Boot Record (LBA 0)")
        print(f"    MBR Signature:   0x{mbr_sig:04X} {'(Valid 0xAA55)' if has_mbr else '(Invalid)'}")

        protective_gpt = False
        for i in range(4):
            part_off = 446 + (i * 16)
            part_entry = mbr_data[part_off : part_off + 16]
            status, c1, c2, c3, p_type, c4, c5, c6, lba_start, lba_size = struct.unpack(
                "<BBBBBBBBII", part_entry
            )
            if p_type != 0:
                print(f"    Partition {i + 1}:     Type=0x{p_type:02X}, Start LBA={lba_start}, Sectors={lba_size}")
                if p_type == 0xEE:
                    protective_gpt = True
                    print("                     └─ Type 0xEE: GPT Protective Partition (isohybrid)")

        print()

        # ──────────────────────────────────────────────────────────
        # 2. GUID Partition Table (GPT) Header at LBA 1 (Offset 512)
        # ──────────────────────────────────────────────────────────
        fh.seek(512)
        gpt_data = fh.read(512)
        sig = gpt_data[:8]
        has_gpt = (sig == b"EFI PART")

        print("[2] GUID Partition Table (Primary GPT, LBA 1)")
        print(f"    GPT Signature:   {sig.decode('ascii', errors='replace')} {'(Valid)' if has_gpt else '(None)'}")

        if has_gpt:
            rev, hdr_size, crc, _, my_lba, alt_lba, first_lba, last_lba = struct.unpack(
                "<IIIIQQQQ", gpt_data[8:56]
            )
            disk_guid = _format_uuid(gpt_data[56:72])
            part_lba, num_parts, part_size, part_crc = struct.unpack("<QIII", gpt_data[72:92])

            print(f"    Disk GUID:       {disk_guid}")
            print(f"    My LBA:          {my_lba}")
            print(f"    Alternate LBA:   {alt_lba}")
            print(f"    Usable Range:    LBA {first_lba} to LBA {last_lba}")
            print(f"    Partition Array: LBA {part_lba} ({num_parts} entries, {part_size} bytes each)")

            # Read partition entries
            fh.seek(part_lba * 512)
            part_bytes = fh.read(num_parts * part_size)
            for p_idx in range(num_parts):
                p_off = p_idx * part_size
                p_raw = part_bytes[p_off : p_off + part_size]
                type_guid_raw = p_raw[:16]
                if type_guid_raw == b"\x00" * 16:
                    continue
                type_guid = _format_uuid(type_guid_raw)
                part_guid = _format_uuid(p_raw[16:32])
                s_lba, e_lba, attrs = struct.unpack("<QQQ", p_raw[32:56])
                p_name = p_raw[56:128].decode("utf-16le", errors="replace").strip("\x00")

                is_esp = (type_guid == EFI_SYSTEM_PARTITION_GUID)
                print(f"    Entry {p_idx + 1}:         Name=\"{p_name}\" {'[EFI System Partition]' if is_esp else ''}")
                print(f"                     Type GUID:  {type_guid}")
                print(f"                     Start-End:  LBA {s_lba} - {e_lba} (Size: {(e_lba - s_lba + 1) * 512:,} bytes)")
        print()

        # ──────────────────────────────────────────────────────────
        # 3. ISO9660 Primary Volume Descriptor (PVD) at Sector 16
        # ──────────────────────────────────────────────────────────
        pvd_offset = 16 * SECTOR_SIZE
        if file_size > pvd_offset + SECTOR_SIZE:
            fh.seek(pvd_offset)
            pvd_raw = fh.read(SECTOR_SIZE)
            if pvd_raw[1:6] == b"CD001" and pvd_raw[0] == 1:
                vol_id = pvd_raw[40:72].decode("ascii", errors="replace").strip()
                sys_id = pvd_raw[8:40].decode("ascii", errors="replace").strip()
                pub_id = pvd_raw[318:446].decode("ascii", errors="replace").strip()
                app_id = pvd_raw[574:702].decode("ascii", errors="replace").strip()
                vol_space = struct.unpack("<I", pvd_raw[80:84])[0]
                created = pvd_raw[813:830].decode("ascii", errors="replace").strip()

                print("[3] ISO9660 Primary Volume Descriptor (Sector 16)")
                print(f"    System ID:       {sys_id}")
                print(f"    Volume ID:       {vol_id}")
                print(f"    Publisher:       {pub_id}")
                print(f"    Application:     {app_id}")
                print(f"    Volume Space:    {vol_space:,} sectors")
                print(f"    Creation Date:   {created}")
            else:
                print("[3] ISO9660 Primary Volume Descriptor: Not found or invalid")
        print()

        # ──────────────────────────────────────────────────────────
        # 4. El Torito Boot Record Volume Descriptor (Sector 17)
        # ──────────────────────────────────────────────────────────
        brvd_offset = 17 * SECTOR_SIZE
        boot_catalog_sector = 0
        if file_size > brvd_offset + SECTOR_SIZE:
            fh.seek(brvd_offset)
            brvd_raw = fh.read(SECTOR_SIZE)
            if brvd_raw[1:6] == b"CD001" and brvd_raw[0] == 0:
                boot_sys_id = brvd_raw[7:39].decode("ascii", errors="replace").strip()
                boot_catalog_sector = struct.unpack("<I", brvd_raw[71:75])[0]

                print("[4] El Torito Boot Record Volume Descriptor (Sector 17)")
                print(f"    Boot System ID:  {boot_sys_id}")
                print(f"    Boot Catalog:    Sector {boot_catalog_sector} (Offset {boot_catalog_sector * SECTOR_SIZE:,} bytes)")
        print()

        # ──────────────────────────────────────────────────────────
        # 5. El Torito Boot Catalog
        # ──────────────────────────────────────────────────────────
        if boot_catalog_sector > 0 and file_size > boot_catalog_sector * SECTOR_SIZE:
            fh.seek(boot_catalog_sector * SECTOR_SIZE)
            cat_raw = fh.read(SECTOR_SIZE)

            # Validation Entry (32 bytes)
            val_id, platform_id, _, manuf, chksum, key1, key2 = struct.unpack(
                "<BBH24sHBB", cat_raw[:32]
            )
            has_val = (val_id == 1 and key1 == 0x55 and key2 == 0xAA)
            print("[5] El Torito Boot Catalog")
            print(f"    Validation Entry: {'Valid (Key 0x55AA)' if has_val else 'Invalid'}")
            print(f"    Platform ID:     0x{platform_id:02X} ({'80x86' if platform_id == 0 else 'Other'})")

            # Initial / Default Entry (BIOS Boot Entry)
            init_boot, init_media, init_seg, init_sys, _, init_sectors, init_rba = struct.unpack(
                "<BBHBBHI", cat_raw[32:48]
            )
            is_bootable = (init_boot == 0x88)
            print(f"    BIOS Boot Entry: {'Bootable (0x88)' if is_bootable else 'Non-bootable (0x00)'}")
            if init_rba > 0:
                print(f"      Load RBA:      Sector {init_rba} (Offset {init_rba * SECTOR_SIZE:,} bytes)")
                print(f"      Sector Count:  {init_sectors}")

            # Scan for EFI Section Entry
            offset = 64
            while offset + 32 <= len(cat_raw):
                entry_raw = cat_raw[offset : offset + 32]
                hdr_ind = entry_raw[0]
                if hdr_ind in (0x90, 0x91):
                    p_id = entry_raw[1]
                    is_efi = (p_id == 0xEF)
                    print(f"    Section Header:  Platform=0x{p_id:02X} {'[EFI]' if is_efi else ''}")
                    offset += 32
                    if offset + 32 <= len(cat_raw):
                        sec_raw = cat_raw[offset : offset + 32]
                        s_boot, s_media, s_seg, _, _, s_secs, s_rba = struct.unpack(
                            "<BBHBBHI", sec_raw[:16]
                        )
                        print(f"    UEFI Boot Entry: {'Bootable (0x88)' if s_boot == 0x88 else 'Disabled'}")
                        print(f"      Load RBA:      Sector {s_rba} (Offset {s_rba * SECTOR_SIZE:,} bytes)")
                        print(f"      Sector Count:  {s_secs} (Size: {s_secs * 512:,} bytes)")

                        # Probe EFI FAT image at s_rba
                        if s_rba > 0 and file_size > s_rba * SECTOR_SIZE + 512:
                            fh.seek(s_rba * SECTOR_SIZE)
                            fat_bpb = fh.read(512)
                            fat_sig = struct.unpack("<H", fat_bpb[510:512])[0]
                            fat_type = fat_bpb[82:90].decode("ascii", errors="replace").strip()
                            fat_label = fat_bpb[71:82].decode("ascii", errors="replace").strip()
                            print(f"      FAT Volume:    Signature=0x{fat_sig:04X}, Type=\"{fat_type}\", Label=\"{fat_label}\"")
                    break
                offset += 32
        print()

        # ──────────────────────────────────────────────────────────
        # 6. Embedded SquashFS Probe
        # ──────────────────────────────────────────────────────────
        # Probe first 16 MB for SquashFS magic 'hsqs'
        print("[6] Embedded SquashFS Filesystem Probe")
        fh.seek(0)
        found_sqsh = False
        probe_limit = min(file_size, 32 * 1024 * 1024)
        step = 4096
        for probe_off in range(0, probe_limit, step):
            fh.seek(probe_off)
            chk_magic = fh.read(4)
            if chk_magic == b"hsqs":
                fh.seek(probe_off)
                sb_data = fh.read(96)
                if len(sb_data) == 96:
                    (
                        sq_magic, sq_inodes, sq_mtime, sq_bsize, sq_frags,
                        sq_comp, sq_blog, sq_flags, sq_ids, sq_vmaj, sq_vmin,
                        sq_root_ref, sq_bytes, sq_id_tab, sq_xattr, sq_in_tab,
                        sq_dir_tab, sq_frag_tab, sq_exp_tab
                    ) = struct.unpack("<5I 6H 8q", sb_data)

                    comp_names = {1: "gzip", 2: "lzma", 3: "lzo", 4: "xz", 5: "lz4", 6: "zstd"}
                    print(f"    SquashFS 4.0:    Found at Offset {probe_off:,} bytes (Sector {probe_off // SECTOR_SIZE})")
                    print(f"    Version:         {sq_vmaj}.{sq_vmin}")
                    print(f"    Compression:     {comp_names.get(sq_comp, f'Unknown ({sq_comp})')}")
                    print(f"    Block Size:      {sq_bsize:,} bytes (2^{sq_blog})")
                    print(f"    Inodes:          {sq_inodes:,}")
                    print(f"    Fragments:       {sq_frags:,}")
                    print(f"    Unique IDs:      {sq_ids}")
                    print(f"    Filesystem Size: {sq_bytes:,} bytes")
                    found_sqsh = True
                    break

        if not found_sqsh:
            print("    SquashFS 4.0:    Not detected in initial 32 MB range")

    print()
    print("=" * 70)
    print("INSPECTION COMPLETE")
    print("=" * 70)
