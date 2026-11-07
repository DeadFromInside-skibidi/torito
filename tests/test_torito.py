"""
Torito test suite (offline — no network access needed)
=====================================================
Covers every subsystem and finishes with a full end-to-end build of a
bootable hybrid ISO from synthetic pacman packages, verified by
``torito.inspect.verify_iso``.

Run:  python -m unittest discover -s tests -v
"""

from __future__ import annotations

import gzip
import io
import json
import os
import shutil
import struct
import tarfile
import tempfile
import unittest

import zstandard

from torito.boot import base_cmdline, generate_syslinux_cfg, generate_systemd_boot_entries
from torito.builder import BuildController, BuildResult
from torito.config import BuildConfig, ServiceSpec, UserSpec, load_config
from torito.cpio import CpioArchiver, build_initramfs, parse_cpio, decompress_initramfs
from torito.fatfs import build_fat_image
from torito.ingest import PackageRecord, ingest_package, ingest_overlay_directory, write_pacman_local_db
from torito.inspect import iso_tree, verify_iso
from torito.iso9660 import Iso9660Builder
from torito.kmod import KernelInfo, elf_section, find_kernels, index_modules, parse_modinfo, resolve_modules
from torito.mutations import Accounts, apply_all_mutations, enable_systemd_unit, sha512_crypt
from torito.repo import PackageDatabase, RepoSpec, parse_sync_db, satisfies, vercmp
from torito.squashfs import SQUASHFS_MAGIC, SquashFSWriter
from torito.vfs import BlobStore, PosixVfs, VfsNodeType, sanitise_crlf


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def make_elf_with_modinfo(modinfo: bytes) -> bytes:
    """Minimal ELF64 relocatable with a .modinfo and .shstrtab section."""
    shstr = b"\x00.modinfo\x00.shstrtab\x00"
    body = modinfo + shstr
    shoff = 64 + len(body)
    shoff += (-shoff) % 8
    hdr = bytearray(64)
    hdr[0:4] = b"\x7fELF"
    hdr[4], hdr[5], hdr[6] = 2, 1, 1
    struct.pack_into("<HHIQQQIHHHHHH", hdr, 16, 1, 62, 1, 0, 0, shoff, 0, 64, 0, 0, 64, 3, 2)
    sections = bytearray(64)  # null section
    sections += struct.pack("<IIQQQQIIQQ", 1, 1, 0, 0, 64, len(modinfo), 0, 0, 1, 0)
    sections += struct.pack("<IIQQQQIIQQ", 10, 3, 0, 0, 64 + len(modinfo), len(shstr), 0, 0, 1, 0)
    out = bytes(hdr) + body
    out += b"\x00" * (shoff - len(out))
    return out + bytes(sections)


def make_pkg(path: str, name: str, version: str, files: dict, extra_info: str = "") -> None:
    """Write a .pkg.tar.zst with a .PKGINFO and the given {path: bytes|('link', target)}."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.PAX_FORMAT) as tf:
        info = f"pkgname = {name}\npkgver = {version}\npkgdesc = test\narch = x86_64\nsize = 1\n{extra_info}".encode()
        ti = tarfile.TarInfo(".PKGINFO")
        ti.size = len(info)
        tf.addfile(ti, io.BytesIO(info))
        dirs = set()
        for p in files:
            parts = p.split("/")[:-1]
            for i in range(1, len(parts) + 1):
                dirs.add("/".join(parts[:i]))
        for d in sorted(dirs):
            ti = tarfile.TarInfo(d)
            ti.type = tarfile.DIRTYPE
            ti.mode = 0o755
            tf.addfile(ti)
        for p, content in files.items():
            ti = tarfile.TarInfo(p)
            if isinstance(content, tuple) and content[0] == "link":
                ti.type = tarfile.SYMTYPE
                ti.linkname = content[1]
                tf.addfile(ti)
            else:
                ti.size = len(content)
                ti.mode = 0o755 if content[:4] == b"\x7fELF" or p.endswith(".sh") else 0o644
                ti.uname, ti.gname = "root", "root"
                tf.addfile(ti, io.BytesIO(content))
    with open(path, "wb") as fh:
        fh.write(zstandard.ZstdCompressor().compress(buf.getvalue()))


def fake_kernel() -> bytes:
    k = bytearray(4096)
    k[0x202:0x206] = b"HdrS"
    return bytes(k)


# ---------------------------------------------------------------------------
# VFS
# ---------------------------------------------------------------------------


class TestVfs(unittest.TestCase):
    def test_hierarchy_usrmerge_and_symlink_resolution(self):
        vfs = PosixVfs(source_date_epoch=1700000000)
        vfs.init_base_hierarchy()
        self.assertEqual(vfs.get("/bin").node_type, VfsNodeType.SYMLINK)
        vfs.add_file("/lib/libfoo.so", b"x")  # goes through /lib -> usr/lib
        self.assertIsNotNone(vfs.get("/usr/lib/libfoo.so"))
        self.assertIsNone(vfs.get("/lib/libfoo.so"))
        vfs.mkdir("/bin")  # a package shipping /bin as a dir keeps the symlink
        self.assertEqual(vfs.get("/bin").node_type, VfsNodeType.SYMLINK)
        dev_null = vfs.get("/dev/null")
        self.assertEqual((dev_null.dev_major, dev_null.dev_minor), (1, 3))

    def test_modes_listing_and_remove(self):
        vfs = PosixVfs(source_date_epoch=1700000000)
        vfs.add_file("/usr/bin/sudo", b"\x7fELF", mode=0o4755)
        self.assertEqual(vfs.get("/usr/bin/sudo").mode, 0o4755)
        vfs.add_file("/a/b/c.txt", b"1")
        vfs.add_file("/a/b/d.txt", b"2")
        self.assertEqual(vfs.list_dir("/a/b"), ["c.txt", "d.txt"])
        vfs.remove("/a")
        self.assertFalse(vfs.exists("/a/b/c.txt"))
        self.assertEqual(vfs.list_dir("/"), ["usr"])

    def test_blob_store(self):
        d = tempfile.mkdtemp()
        try:
            store = BlobStore(os.path.join(d, "p.pack"))
            vfs = PosixVfs(source_date_epoch=1, blob_store=store)
            big = os.urandom(100000)
            vfs.add_file("/big", big)
            self.assertIsNotNone(vfs.get("/big").blob)
            self.assertEqual(vfs.get("/big").data, big)
            vfs.add_hardlink("/big2", "/big")
            self.assertEqual(vfs.get("/big2").blob, vfs.get("/big").blob)
            store.delete()
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_crlf(self):
        self.assertEqual(sanitise_crlf(b"a\r\nb\r\n"), b"a\nb\n")


# ---------------------------------------------------------------------------
# Repository client
# ---------------------------------------------------------------------------


def _desc(**kw) -> bytes:
    out = ""
    for k, v in kw.items():
        vals = v if isinstance(v, list) else [v]
        out += f"%{k.upper()}%\n" + "\n".join(vals) + "\n\n"
    return out.encode()


def make_sync_db(path: str, entries: list) -> None:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        for e in entries:
            data = _desc(**e)
            ti = tarfile.TarInfo(f"{e['name']}-{e['version']}/desc")
            ti.size = len(data)
            tf.addfile(ti, io.BytesIO(data))
    with open(path, "wb") as fh:
        fh.write(gzip.compress(buf.getvalue()))


class TestRepo(unittest.TestCase):
    def test_vercmp(self):
        self.assertEqual(vercmp("1.0", "1.0"), 0)
        self.assertEqual(vercmp("1.0a", "1.0"), -1)
        self.assertEqual(vercmp("1:1.0", "2.0"), 1)
        self.assertEqual(vercmp("1.0-1", "1.0-2"), -1)
        self.assertEqual(vercmp("1.0rc1", "1.0"), -1)
        self.assertTrue(satisfies("39-2", ">=", "38"))
        self.assertFalse(satisfies("38-1", "<", "38"))

    def test_parse_and_resolve(self):
        d = tempfile.mkdtemp()
        try:
            os.makedirs(os.path.join(d, "sync"))
            make_sync_db(os.path.join(d, "sync", "core.db"), [
                {"name": "bash", "version": "5-1", "filename": "bash-5-1.pkg.tar.zst", "depends": ["glibc>=2"], "provides": ["sh"]},
                {"name": "glibc", "version": "2.40-1", "filename": "glibc-2.40-1.pkg.tar.zst"},
                {"name": "app", "version": "1-1", "filename": "app-1-1.pkg.tar.zst", "depends": ["sh", "libfoo.so=1-64"]},
                {"name": "foo", "version": "1-1", "filename": "foo-1-1.pkg.tar.zst", "provides": ["libfoo.so=1-64"]},
                {"name": "zfoo", "version": "1-1", "filename": "zfoo-1-1.pkg.tar.zst", "provides": ["libfoo.so=1-64"]},
            ])
            db = PackageDatabase([RepoSpec("core", ["http://invalid"])], cache_dir=d, db_max_age=10 ** 9)
            db.refresh()
            order = [p.name for p in db.resolve(["app"])]
            self.assertEqual(order[-1], "app")
            self.assertLess(order.index("glibc"), order.index("bash"))
            self.assertIn("foo", order)
            self.assertNotIn("zfoo", order)
        finally:
            shutil.rmtree(d, ignore_errors=True)


# ---------------------------------------------------------------------------
# Config & state synthesis
# ---------------------------------------------------------------------------


class TestConfig(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_toml_packages_and_defaults(self):
        p = os.path.join(self.tmp, "d.toml")
        with open(p, "w", encoding="utf-8") as f:
            f.write('name="X"\npackages=["base","linux","local/thing.pkg.tar.zst"]\n[iso]\nvolume_id="my-live disk"\n')
        cfg = load_config(p)
        self.assertEqual(cfg.package_names, ["base", "linux"])
        self.assertEqual(len(cfg.packages), 1)
        self.assertEqual([r.name for r in cfg.repositories], ["core", "extra"])
        self.assertEqual(cfg.iso.volume_id, "MY_LIVE_DISK")

    def test_json_and_ini(self):
        jp = os.path.join(self.tmp, "d.json")
        with open(jp, "w", encoding="utf-8") as f:
            json.dump({"name": "J", "users": [{"name": "alice", "uid": 1002}], "services": ["nginx"]}, f)
        cfg = load_config(jp)
        self.assertEqual(cfg.users[0].name, "alice")
        self.assertEqual(cfg.services[0].name, "nginx")
        ip = os.path.join(self.tmp, "d.ini")
        with open(ip, "w", encoding="utf-8") as f:
            f.write("[general]\nname = I\n[user.bob]\nuid = 1003\ngroups = wheel, audio\n[services]\nsvc1 = sshd, systemd, multi-user.target\n")
        cfg = load_config(ip)
        self.assertEqual(cfg.users[0].groups, ["wheel", "audio"])
        self.assertEqual(cfg.services[0].target, "multi-user.target")


class TestMutations(unittest.TestCase):
    def test_sha512_crypt_known_vector(self):
        # Test vector from Drepper's SHA-crypt specification.
        self.assertEqual(
            sha512_crypt("Hello world!", "saltstring"),
            "$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJuesI68u4OTLiBFdcbYEdFCoEOfaS35inz1",
        )

    def test_sysusers_users_services(self):
        vfs = PosixVfs(source_date_epoch=1700000000)
        vfs.init_base_hierarchy()
        vfs.add_file("/usr/lib/sysusers.d/test.conf", b'g video 985\nu polkitd 102 "PolicyKit daemon"\nu greeter - "Greeter" /var/lib/greeter\n')
        vfs.add_file("/usr/lib/systemd/system/sshd.service", b"[Unit]\n[Service]\nExecStart=/x\n[Install]\nWantedBy=multi-user.target\n")
        vfs.add_file("/usr/lib/systemd/system/greetd.service", b"[Service]\nExecStart=/g\n[Install]\nAlias=display-manager.service\n")
        vfs.add_file("/usr/lib/systemd/system/getty@.service", b"[Service]\n[Install]\nWantedBy=getty.target\nDefaultInstance=tty1\n")
        vfs.add_file("/usr/lib/systemd/system/graphical.target", b"[Unit]\n")
        vfs.add_file("/var/lib/greeter/x", b"", uname="greeter", gname="greeter")
        cfg = BuildConfig(hostname="box", default_target="graphical.target")
        cfg.users.append(UserSpec(name="live", uid=1000, password="pw", groups=["wheel", "video"]))
        cfg.users.append(UserSpec(name="root", password="rootpw"))
        cfg.services += [ServiceSpec(name="sshd"), ServiceSpec(name="greetd"), ServiceSpec(name="getty@tty2")]
        acc = apply_all_mutations(vfs, cfg)
        passwd = vfs.read_file("/etc/passwd").decode()
        self.assertIn("polkitd:x:102:102:PolicyKit daemon:/:/usr/bin/nologin", passwd)
        self.assertIn("live:x:1000:1000::/home/live:/bin/bash", passwd)
        self.assertIn("live", vfs.read_file("/etc/group").decode().split("video:x:985:")[1].split("\n")[0])
        self.assertTrue(vfs.read_file("/etc/shadow").decode().split("root:")[1].startswith("$6$"))
        self.assertEqual(vfs.get("/var/lib/greeter/x").uid, acc.uids()["greeter"])
        self.assertEqual(vfs.get("/etc/systemd/system/multi-user.target.wants/sshd.service").link_target, "/usr/lib/systemd/system/sshd.service")
        self.assertIsNotNone(vfs.get("/etc/systemd/system/display-manager.service"))
        self.assertEqual(vfs.get("/etc/systemd/system/getty.target.wants/getty@tty2.service").link_target, "/usr/lib/systemd/system/getty@.service")
        self.assertEqual(vfs.get("/etc/systemd/system/default.target").link_target, "/usr/lib/systemd/system/graphical.target")
        self.assertEqual(vfs.get("/home/live").uid, 1000)


# ---------------------------------------------------------------------------
# Archives & filesystems
# ---------------------------------------------------------------------------


class TestCpio(unittest.TestCase):
    def test_roundtrip(self):
        vfs = PosixVfs(source_date_epoch=1700000000)
        vfs.add_file("/init", b"#!/bin/sh\n", mode=0o755)
        vfs.add_symlink("/bin/sh", "busybox")
        vfs.add_char_device("/dev/console", 5, 1, mode=0o600)
        archiver = CpioArchiver()
        archiver.add_from_vfs(vfs)
        raw = archiver.finalize()
        self.assertTrue(raw.startswith(b"070701"))
        names = [e.name for e in parse_cpio(raw)]
        self.assertIn("init", names)
        z = build_initramfs(vfs, compression="zstd")
        self.assertEqual(z[:4], b"\x28\xb5\x2f\xfd")
        self.assertEqual(decompress_initramfs(z)[:6], b"070701")


class TestSquashfs(unittest.TestCase):
    def test_superblock_and_tables(self):
        vfs = PosixVfs(source_date_epoch=1700000000)
        vfs.init_base_hierarchy()
        for i in range(3000):  # listing > 64 KiB → extended directory inode
            vfs.add_file(f"/many/a-rather-long-file-name-{i:05d}.conf", b"x" * (i % 50))
        vfs.add_file("/big", os.urandom(300000) + bytes(262144))
        vfs.get("/big").xattrs = {"security.capability": b"\x01\x00\x00\x02" + bytes(16)}
        img = SquashFSWriter(block_size=131072, compression="zstd", level=3).build(vfs)
        f = struct.unpack("<IIIIIHHHHHHQQQQQQQQ", img[:96])
        self.assertEqual(f[0], SQUASHFS_MAGIC)
        self.assertEqual((f[9], f[10]), (4, 0))
        self.assertEqual(f[1], vfs.node_count())
        bytes_used, id_t, xattr_t, inode_t, dir_t, frag_t = f[12], f[13], f[14], f[15], f[16], f[17]
        self.assertTrue(inode_t < dir_t <= frag_t < id_t < bytes_used)
        self.assertLess(xattr_t, bytes_used)
        self.assertEqual(len(img) % 4096, 0)
        for comp in ("gzip", "xz"):
            self.assertEqual(SquashFSWriter(compression=comp).build(vfs)[:4], b"hsqs")


class TestFat(unittest.TestCase):
    def test_fat16_by_cluster_count(self):
        files = {"/EFI/BOOT/BOOTX64.EFI": b"MZ" + bytes(1000), "/loader/entries/01-a-long-name.conf": b"title x\n", "/boot/k": os.urandom(5 << 20)}
        img = build_fat_image(files, label="EFIBOOT", epoch=1700000000)
        self.assertEqual(img[510:512], b"\x55\xaa")
        self.assertEqual(img[54:62], b"FAT16   ")
        spc, rsv, nf, rent = img[13], struct.unpack_from("<H", img, 14)[0], img[16], struct.unpack_from("<H", img, 17)[0]
        tot = struct.unpack_from("<H", img, 19)[0] or struct.unpack_from("<I", img, 32)[0]
        fsz = struct.unpack_from("<H", img, 22)[0]
        clusters = (tot - rsv - nf * fsz - rent * 32 // 512) // spc
        self.assertTrue(4085 <= clusters < 65525)


class TestIso(unittest.TestCase):
    def test_boot_structures_and_rock_ridge(self):
        b = Iso9660Builder(volume_id="T_LIVE")
        isolinux = bytes(64) + os.urandom(4000)
        b.add_file("/boot/syslinux/isolinux.bin", isolinux)
        b.add_file("/boot/x86_64/vmlinuz", fake_kernel())
        b.add_file("/live/x86_64/rootfs.sfs", SquashFSWriter().build(PosixVfs(source_date_epoch=1)))
        b.add_file("/boot/Intel-UCode.img", b"u")
        b.set_bios_boot("/boot/syslinux/isolinux.bin", catalog_path="/boot/syslinux/boot.cat")
        b.set_isohybrid_mbr(b"\x33\xc0" + bytes(430))
        b.set_efi_image(build_fat_image({"/EFI/BOOT/BOOTX64.EFI": b"MZ" + bytes(100)}))
        img = b.build()
        d = tempfile.mkdtemp()
        try:
            p = os.path.join(d, "t.iso")
            with open(p, "wb") as fh:
                fh.write(img)
            self.assertEqual(verify_iso(p), [])
            with open(p, "rb") as fh:
                tree = iso_tree(fh)
            self.assertIn("/boot/Intel-UCode.img", tree)  # Rock Ridge keeps the real name
            lba = tree["/boot/syslinux/isolinux.bin"][0]
            pvd, flba, flen = struct.unpack_from("<III", img, lba * 2048 + 8)
            self.assertEqual((pvd, flba, flen), (16, lba, len(isolinux)))
            self.assertEqual(struct.unpack_from("<I", img, 432)[0], lba * 4)  # isohybrid boot LBA
        finally:
            shutil.rmtree(d, ignore_errors=True)


class TestKmodAndIngest(unittest.TestCase):
    def test_modinfo_and_closure(self):
        elf = make_elf_with_modinfo(b"license=GPL\x00depends=bar\x00alias=pci:v*\x00")
        self.assertEqual(parse_modinfo(elf_section(elf, ".modinfo"))["depends"], ["bar"])
        vfs = PosixVfs(source_date_epoch=1)
        root = "/usr/lib/modules/6.1.0-t"
        vfs.add_file(f"{root}/vmlinuz", fake_kernel())
        vfs.add_file(f"{root}/kernel/fs/foo.ko.zst", zstandard.ZstdCompressor().compress(elf))
        vfs.add_file(f"{root}/kernel/fs/bar.ko", make_elf_with_modinfo(b"depends=\x00"))
        vfs.add_file(f"{root}/modules.builtin", b"kernel/fs/baz.ko\n")
        k = find_kernels(vfs)[0]
        index_modules(vfs, k)
        order = [m.name for m in resolve_modules(vfs, k, ["foo", "baz"])]
        self.assertEqual(order, ["bar", "foo"])

    def test_pacman_ingest_and_local_db(self):
        d = tempfile.mkdtemp()
        try:
            p = os.path.join(d, "hello-1.0-1-x86_64.pkg.tar.zst")
            make_pkg(p, "hello", "1.0-1", {"usr/bin/hello": b"\x7fELF\r\n", "usr/bin/hi": ("link", "hello")}, "depend = glibc\nbackup = etc/hello.conf\n")
            vfs = PosixVfs(source_date_epoch=1)
            rec = PackageRecord(name="")
            ingest_package(vfs, p, record=rec)
            self.assertEqual(vfs.get("/usr/bin/hello").data, b"\x7fELF\r\n")  # payloads never rewritten
            self.assertEqual(vfs.get("/usr/bin/hi").link_target, "hello")
            write_pacman_local_db(vfs, [rec], install_date=1)
            desc = vfs.read_file("/var/lib/pacman/local/hello-1.0-1/desc").decode()
            self.assertIn("%NAME%\nhello", desc)
            self.assertIn("%DEPENDS%\nglibc", desc)
            ov = os.path.join(d, "ov", "etc")
            os.makedirs(ov)
            with open(os.path.join(ov, "motd"), "wb") as fh:
                fh.write(b"hi\r\n")
            ingest_overlay_directory(vfs, os.path.join(d, "ov"))
            self.assertEqual(vfs.read_file("/etc/motd"), b"hi\n")  # host overlays are LF-normalised
        finally:
            shutil.rmtree(d, ignore_errors=True)


# ---------------------------------------------------------------------------
# End to end: synthetic packages → bootable ISO
# ---------------------------------------------------------------------------


class TestEndToEnd(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="torito_e2e_")

    def tearDown(self):
        shutil.rmtree(self.d, ignore_errors=True)

    def test_full_build(self):
        pk = os.path.join(self.d, "pkgs")
        os.makedirs(pk)
        kv = "6.9.0-test"
        mod = make_elf_with_modinfo(b"depends=\x00")
        make_pkg(os.path.join(pk, "filesystem.pkg.tar.zst"), "filesystem", "1-1", {
            "etc/passwd": b"root:x:0:0::/root:/bin/bash\n", "etc/group": b"root:x:0:root\nwheel:x:998:\n",
            "etc/shadow": b"root:*::::::::\n", "etc/gshadow": b"root:::root\n", "etc/skel/.bashrc": b"# rc\n",
        })
        make_pkg(os.path.join(pk, "linux.pkg.tar.zst"), "linux", f"{kv}-1", {
            f"usr/lib/modules/{kv}/vmlinuz": fake_kernel(), f"usr/lib/modules/{kv}/pkgbase": b"linux\n",
            f"usr/lib/modules/{kv}/kernel/fs/squashfs/squashfs.ko.zst": zstandard.ZstdCompressor().compress(mod),
            f"usr/lib/modules/{kv}/kernel/fs/overlayfs/overlay.ko": mod,
        })
        make_pkg(os.path.join(pk, "busybox.pkg.tar.zst"), "busybox", "1-1", {"usr/bin/busybox": b"\x7fELF" + bytes(2000)})
        make_pkg(os.path.join(pk, "syslinux.pkg.tar.zst"), "syslinux", "6-1", {
            **{f"usr/lib/syslinux/bios/{n}": b"\x00" * 64 + n.encode() for n in ["isolinux.bin", "ldlinux.c32", "menu.c32", "libutil.c32", "libcom32.c32", "reboot.c32", "poweroff.c32"]},
            "usr/lib/syslinux/bios/isohdpfx.bin": b"\x33\xed" + bytes(430),
        })
        make_pkg(os.path.join(pk, "systemd.pkg.tar.zst"), "systemd", "1-1", {
            "usr/lib/systemd/boot/efi/systemd-bootx64.efi": b"MZ" + bytes(4000),
            "usr/lib/systemd/system/sshd.service": b"[Install]\nWantedBy=multi-user.target\n",
            "usr/lib/systemd/system/multi-user.target": b"[Unit]\n",
        })
        ov = os.path.join(self.d, "overlay", "etc")
        os.makedirs(ov)
        with open(os.path.join(ov, "motd"), "wb") as fh:
            fh.write(b"Welcome\r\n")
        out = os.path.join(self.d, "out", "e2e.iso")
        manifest = os.path.join(self.d, "distro.toml")
        pkgs = ", ".join(f'"{os.path.join(pk, n).replace(os.sep, "/")}"' for n in sorted(os.listdir(pk)))
        with open(manifest, "w", encoding="utf-8") as fh:
            fh.write(f"""
name = "E2E"
version = "1"
default_target = "multi-user.target"
packages = [{pkgs}]
rootfs_overlay_dirs = ["{os.path.join(self.d, 'overlay').replace(os.sep, '/')}"]
cache_dir = "{os.path.join(self.d, 'cache').replace(os.sep, '/')}"
work_dir = "{os.path.join(self.d, 'work').replace(os.sep, '/')}"
[[users]]
name = "live"
password = "live"
groups = ["wheel"]
[[services]]
name = "sshd"
[iso]
output = "{out.replace(os.sep, '/')}"
volume_id = "E2E_LIVE"
squashfs_level = 1
""")
        res: BuildResult = BuildController().run_sync(manifest)
        self.assertTrue(res.success, res.error_message)
        self.assertEqual(verify_iso(out), [])
        with open(out, "rb") as fh:
            tree = iso_tree(fh)
            for want in ("/boot/x86_64/vmlinuz", "/boot/x86_64/initramfs.img", "/live/x86_64/rootfs.sfs", "/boot/syslinux/syslinux.cfg"):
                self.assertIn(want, tree)
            lba, ln, _ = tree["/boot/syslinux/syslinux.cfg"]
            fh.seek(lba * 2048)
            self.assertIn("torito.label=E2E_LIVE", fh.read(ln).decode())


class TestBootConfig(unittest.TestCase):
    def test_cmdline_and_entries(self):
        cfg = BuildConfig()
        cfg.iso.volume_id = "ABC"
        cfg.kernel.cmdline = "quiet systemd.journald.forward_to_console=1"
        cmd = base_cmdline(cfg)
        self.assertIn("torito.label=ABC", cmd)
        self.assertIn("console=ttyS0,115200", cmd)  # substring "console=" in other args must not suppress it
        sl = generate_syslinux_cfg(cfg, ["/boot/x86_64/initramfs.img"])
        self.assertTrue(sl.startswith("SERIAL 0 115200"))
        entries = generate_systemd_boot_entries(cfg)
        self.assertIn("/loader/loader.conf", entries)


if __name__ == "__main__":
    unittest.main()
