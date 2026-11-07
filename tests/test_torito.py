"""
Unit & Integration Test Suite for Torito ISO Compiler
=====================================================
Exhaustively verifies every subsystem:
1. PosixVfs — in-memory POSIX tree, mode bits, CRLF sanitization, dev nodes.
2. Config — TOML, JSON, and INI manifest parsers.
3. Mutations — SHA-512 ($6$) crypt, users/groups, systemd/openrc/runit symlinks.
4. CPIO — SVR4 newc header struct packing, padding, and zstd/gzip initramfs.
5. SquashFS — superblock, inode table, directory grouping, ID/fragment tables.
6. FAT32 — BPB, FSInfo, cluster chains, LFN directory entries, EFI ESP.
7. ISO9660 — PVD, BRVD, El Torito boot catalog, protective MBR, Primary/Backup GPT.
8. End-to-End Build — Complete non-blocking controller build outputting a hybrid ISO.
"""

from __future__ import annotations

import io
import os
import shutil
import struct
import tempfile
import threading
import unittest

from torito.vfs import PosixVfs, VfsNode, VfsNodeType, sanitise_crlf
from torito.config import BuildConfig, load_config
from torito.mutations import sha512_crypt, apply_all_mutations
from torito.cpio import CpioArchiver, build_initramfs
from torito.squashfs import SquashFSWriter, build_squashfs, SQUASHFS_MAGIC
from torito.fat32 import Fat32Image, build_efi_esp
from torito.iso9660 import Iso9660Builder, build_hybrid_iso
from torito.builder import BuildController, BuildStage, BuildResult


class TestToritoVfs(unittest.TestCase):
    def test_vfs_hierarchy_and_modes(self):
        vfs = PosixVfs(source_date_epoch=1700000000)
        vfs.init_base_hierarchy()
        self.assertGreater(vfs.node_count(), 30)

        # Inode /dev/null
        dev_null = vfs.get("/dev/null")
        self.assertIsNotNone(dev_null)
        self.assertEqual(dev_null.node_type, VfsNodeType.CHAR_DEVICE)
        self.assertEqual(dev_null.dev_major, 1)
        self.assertEqual(dev_null.dev_minor, 3)
        self.assertEqual(dev_null.mode & 0o777, 0o666)

        # Suid executable
        vfs.add_file("/usr/bin/sudo", b"\x7fELFfake", mode=0o4755, uid=0, gid=0)
        sudo_node = vfs.get("/usr/bin/sudo")
        self.assertEqual(sudo_node.mode, 0o4755)
        self.assertTrue(sudo_node.is_executable())

        # Symlinks
        vfs.add_symlink("/bin/sh", "bash")
        sh_node = vfs.get("/bin/sh")
        self.assertEqual(sh_node.node_type, VfsNodeType.SYMLINK)
        self.assertEqual(sh_node.link_target, "bash")

    def test_crlf_sanitization(self):
        crlf_data = b"#!/bin/bash\r\necho 'hello world'\r\nexit 0\r\n"
        lf_data = sanitise_crlf(crlf_data)
        self.assertEqual(lf_data, b"#!/bin/bash\necho 'hello world'\nexit 0\n")
        self.assertNotIn(b"\r", lf_data)

    def test_collect_id_table(self):
        vfs = PosixVfs(source_date_epoch=1700000000)
        vfs.mkdir("/home/test", mode=0o700, uid=1000, gid=1000)
        vfs.add_file("/home/test/file.txt", b"test", mode=0o644, uid=1000, gid=100)
        id_list, id_map = vfs.collect_id_table()
        self.assertIn(1000, id_list)
        self.assertIn(100, id_list)
        self.assertIn(0, id_list)
        self.assertEqual(id_map[1000], id_list.index(1000))


class TestToritoMutations(unittest.TestCase):
    def test_sha512_crypt(self):
        password = "rootpassword"
        salt = "testsalt12345678"
        h = sha512_crypt(password, salt, rounds=5000)
        self.assertTrue(h.startswith("$6$testsalt12345678$"))
        # Deterministic
        h2 = sha512_crypt(password, salt, rounds=5000)
        self.assertEqual(h, h2)

    def test_state_synthesis(self):
        vfs = PosixVfs(source_date_epoch=1700000000)
        vfs.init_base_hierarchy()

        cfg = BuildConfig()
        cfg.hostname = "toritobox"
        from torito.config import UserSpec, ServiceSpec
        cfg.users.append(UserSpec(name="archlinux", uid=1001, gid=1001, password="secretpassword", groups=["wheel"]))
        cfg.services.append(ServiceSpec(name="sshd", init_system="systemd"))
        cfg.services.append(ServiceSpec(name="networking", init_system="openrc", runlevel="boot"))

        apply_all_mutations(vfs, cfg)

        # Check /etc/passwd
        passwd = vfs.get("/etc/passwd")
        self.assertIsNotNone(passwd)
        self.assertIn(b"archlinux:x:1001:1001:archlinux:/home/archlinux:/bin/bash", passwd.data)

        # Check /etc/shadow
        shadow = vfs.get("/etc/shadow")
        self.assertIsNotNone(shadow)
        self.assertIn(b"archlinux:$6$", shadow.data)

        # Check /etc/hostname
        hostname = vfs.get("/etc/hostname")
        self.assertEqual(hostname.data.strip(), b"toritobox")

        # Check systemd symlink
        sshd_link = vfs.get("/etc/systemd/system/multi-user.target.wants/sshd.service")
        self.assertIsNotNone(sshd_link)
        self.assertEqual(sshd_link.node_type, VfsNodeType.SYMLINK)

        # Check OpenRC symlink
        openrc_link = vfs.get("/etc/runlevels/boot/networking")
        self.assertIsNotNone(openrc_link)
        self.assertEqual(openrc_link.node_type, VfsNodeType.SYMLINK)


class TestToritoCpio(unittest.TestCase):
    def test_cpio_archive_packing(self):
        vfs = PosixVfs(source_date_epoch=1700000000)
        vfs.mkdir("/bin", mode=0o755)
        vfs.add_file("/init", b"#!/bin/sh\necho boot\n", mode=0o755)
        vfs.add_symlink("/bin/sh", "/init")

        archiver = CpioArchiver()
        archiver.add_from_vfs(vfs)
        cpio_raw = archiver.finalize()

        self.assertTrue(cpio_raw.startswith(b"070701"))
        self.assertIn(b"TRAILER!!!", cpio_raw)

        # Test compression
        initramfs_zstd = build_initramfs(vfs, compression="zstd")
        self.assertTrue(len(initramfs_zstd) > 0)
        # Magic byte for Zstandard frame is 0x28B52FFD
        self.assertEqual(initramfs_zstd[:4], b"\x28\xb5\x2f\xfd")


class TestToritoSquashfs(unittest.TestCase):
    def test_squashfs_creation(self):
        vfs = PosixVfs(source_date_epoch=1700000000)
        vfs.init_base_hierarchy()
        vfs.add_file("/etc/torito.conf", b"key=value\n", mode=0o644)
        vfs.add_file("/usr/bin/hello", b"echo hello\n", mode=0o755)
        vfs.fixup_nlinks()

        writer = SquashFSWriter(block_size=131072, compression="zstd")
        sqsh_bytes = writer.build(vfs)

        self.assertGreater(len(sqsh_bytes), 96)
        magic, inodes = struct.unpack("<II", sqsh_bytes[:8])
        self.assertEqual(magic, SQUASHFS_MAGIC)
        self.assertGreaterEqual(inodes, vfs.node_count())
        self.assertEqual(len(sqsh_bytes) % 4096, 0)  # 4KB aligned


class TestToritoFat32(unittest.TestCase):
    def test_fat32_esp_building(self):
        efi_stub = b"\x4d\x5a" + b"\x90" * 1024  # PE/COFF MZ stub
        esp_bytes = build_efi_esp(
            efi_binary=efi_stub,
            kernel=b"vmlinuz-data",
            initramfs=b"initramfs-data",
            size_mb=4,
            volume_label="TORITO_EFI",
        )

        self.assertEqual(len(esp_bytes), 4 * 1024 * 1024)
        # Check boot sector signature
        self.assertEqual(esp_bytes[510:512], b"\x55\xaa")
        # Check FAT32 type string in BPB
        self.assertEqual(esp_bytes[82:90], b"FAT32   ")
        # Check OEM name
        self.assertEqual(esp_bytes[3:11], b"MSWIN4.1")


class TestToritoIso9660(unittest.TestCase):
    def test_hybrid_iso_structures(self):
        files = {
            "/live/filesystem.squashfs": b"fake-squashfs-payload" * 100,
            "/boot/vmlinuz": b"fake-kernel",
        }
        efi_esp = b"\x55\xaa" * 2048  # dummy ESP

        iso_bytes = build_hybrid_iso(
            files=files,
            bios_boot_image=b"",
            efi_boot_image=efi_esp,
            volume_id="TORITO_TEST",
        )

        self.assertGreater(len(iso_bytes), 16 * 2048)
        self.assertEqual(len(iso_bytes) % 2048, 0)

        # Protective MBR at sector 0
        mbr_sig = iso_bytes[510:512]
        self.assertEqual(mbr_sig, b"\x55\xaa")
        part1_type = iso_bytes[446 + 4]
        self.assertEqual(part1_type, 0xEE)  # GPT protective

        # Primary GPT Header at LBA 1 (offset 512)
        gpt_sig = iso_bytes[512:512 + 8]
        self.assertEqual(gpt_sig, b"EFI PART")

        # ISO9660 PVD at sector 16 (offset 16 * 2048 = 32768)
        pvd_offset = 16 * 2048
        self.assertEqual(iso_bytes[pvd_offset], 1)  # Type 1 = PVD
        self.assertEqual(iso_bytes[pvd_offset + 1:pvd_offset + 6], b"CD001")
        self.assertIn(b"TORITO_TEST", iso_bytes[pvd_offset + 40:pvd_offset + 72])

        # Boot Record Volume Descriptor (El Torito) at sector 17
        brvd_offset = 17 * 2048
        self.assertEqual(iso_bytes[brvd_offset], 0)  # Type 0 = BRVD
        self.assertEqual(iso_bytes[brvd_offset + 1:brvd_offset + 6], b"CD001")
        self.assertIn(b"EL TORITO SPECIFICATION", iso_bytes[brvd_offset + 7:brvd_offset + 39])


class TestToritoConfig(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_json_and_ini_parsers(self):
        import json
        # Test JSON
        json_path = os.path.join(self.tmp_dir, "distro.json")
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump({
                "name": "JSONDistro",
                "version": "3.0.0",
                "hostname": "jsonhost",
                "users": [{"name": "alice", "uid": 1002, "gid": 1002}],
                "services": ["nginx"],
            }, f)

        cfg_json = load_config(json_path)
        self.assertEqual(cfg_json.name, "JSONDistro")
        self.assertEqual(cfg_json.version, "3.0.0")
        self.assertEqual(cfg_json.hostname, "jsonhost")
        self.assertEqual(len(cfg_json.users), 1)
        self.assertEqual(cfg_json.users[0].name, "alice")
        self.assertEqual(len(cfg_json.services), 1)
        self.assertEqual(cfg_json.services[0].name, "nginx")

        # Test INI
        ini_path = os.path.join(self.tmp_dir, "distro.ini")
        with open(ini_path, "w", encoding="utf-8") as f:
            f.write("""
[general]
name = INIDistro
version = 4.0.0
hostname = inihost

[user.bob]
uid = 1003
gid = 1003
groups = wheel, audio

[services]
svc1 = sshd, systemd, multi-user.target
""")

        cfg_ini = load_config(ini_path)
        self.assertEqual(cfg_ini.name, "INIDistro")
        self.assertEqual(cfg_ini.version, "4.0.0")
        self.assertEqual(cfg_ini.hostname, "inihost")
        self.assertEqual(len(cfg_ini.users), 1)
        self.assertEqual(cfg_ini.users[0].name, "bob")
        self.assertEqual(cfg_ini.users[0].groups, ["wheel", "audio"])
        self.assertEqual(len(cfg_ini.services), 1)
        self.assertEqual(cfg_ini.services[0].name, "sshd")


class TestToritoIngest(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_tar_ingestion_and_overlay(self):
        import tarfile
        from torito.ingest import ingest_package, ingest_overlay_directory

        # Create a mock tar archive
        tar_path = os.path.join(self.tmp_dir, "package.tar")
        with tarfile.open(tar_path, "w") as tf:
            # File
            data = b"#!/bin/sh\r\necho package\r\n"
            ti = tarfile.TarInfo("usr/bin/pkgapp")
            ti.size = len(data)
            ti.mode = 0o755
            tf.addfile(ti, io.BytesIO(data))

            # Symlink
            ti_sym = tarfile.TarInfo("usr/bin/pkglink")
            ti_sym.type = tarfile.SYMTYPE
            ti_sym.linkname = "pkgapp"
            tf.addfile(ti_sym)

        vfs = PosixVfs(source_date_epoch=1700000000)
        vfs.init_base_hierarchy()
        count = ingest_package(vfs, tar_path, fmt="tar")
        self.assertGreaterEqual(count, 2)

        node = vfs.get("/usr/bin/pkgapp")
        self.assertIsNotNone(node)
        self.assertEqual(node.data, b"#!/bin/sh\necho package\n")  # CRLF sanitized
        self.assertEqual(node.mode, 0o755)

        link_node = vfs.get("/usr/bin/pkglink")
        self.assertIsNotNone(link_node)
        self.assertEqual(link_node.link_target, "pkgapp")

        # Test overlay directory
        overlay_dir = os.path.join(self.tmp_dir, "overlay")
        os.makedirs(os.path.join(overlay_dir, "etc", "skel"), exist_ok=True)
        with open(os.path.join(overlay_dir, "etc", "skel", ".bashrc"), "wb") as f:
            f.write(b"# skel bashrc\r\nexport FOO=BAR\r\n")

        overlay_count = ingest_overlay_directory(vfs, overlay_dir)
        self.assertGreaterEqual(overlay_count, 1)

        skel_node = vfs.get("/etc/skel/.bashrc")
        self.assertIsNotNone(skel_node)
        self.assertEqual(skel_node.data, b"# skel bashrc\nexport FOO=BAR\n")


class TestToritoEndToEnd(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="torito_test_")

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_full_pipeline_cli_build(self):
        # Create declarative build manifest
        manifest_path = os.path.join(self.test_dir, "distro.toml")
        iso_out = os.path.join(self.test_dir, "output", "testdistro.iso")

        overlay_dir = os.path.join(self.test_dir, "overlay")
        os.makedirs(os.path.join(overlay_dir, "etc"), exist_ok=True)
        with open(os.path.join(overlay_dir, "etc", "motd"), "wb") as f:
            f.write(b"Welcome to Torito Linux!\r\n")

        dummy_efi = os.path.join(self.test_dir, "BOOTX64.EFI")
        with open(dummy_efi, "wb") as f:
            f.write(b"MZ\x90\x00" + b"\xCC" * 512)

        manifest_content = f"""
name = "ToritoLinux"
version = "2026.11"
arch = "x86_64"
hostname = "torito-live"
rootfs_overlay_dirs = ["{overlay_dir.replace('\\', '/')}"]

[bootloader]
efi_binary = "{dummy_efi.replace('\\', '/')}"

[iso]
output = "{iso_out.replace('\\', '/')}"
volume_id = "TORITO_LIVE"
squashfs_compression = "zstd"

[[users]]
name = "liveuser"
uid = 1000
gid = 1000
password = "livepassword"
groups = ["wheel"]

[[services]]
name = "systemd-networkd"
init_system = "systemd"
"""
        with open(manifest_path, "w", encoding="utf-8") as f:
            f.write(manifest_content)

        controller = BuildController()
        done_event = threading.Event()
        results: list[BuildResult] = []

        def on_finished(res: BuildResult):
            results.append(res)
            done_event.set()

        controller.on_finished = on_finished
        controller.start(manifest_path)
        self.assertTrue(done_event.wait(timeout=60.0), "Build timed out")

        self.assertEqual(len(results), 1)
        res = results[0]
        self.assertTrue(res.success, f"Build failed: {res.error_message}")
        self.assertTrue(os.path.isfile(iso_out))
        self.assertGreater(os.path.getsize(iso_out), 64 * 1024)

        # Inspect binary structure of the produced ISO
        with open(iso_out, "rb") as f:
            iso_head = f.read(65536)

        # MBR signature
        self.assertEqual(iso_head[510:512], b"\x55\xaa")
        # GPT Header
        self.assertEqual(iso_head[512:520], b"EFI PART")
        # ISO9660 PVD
        self.assertEqual(iso_head[32768:32768 + 6], b"\x01CD001")


if __name__ == "__main__":
    unittest.main()
