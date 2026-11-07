"""
torito.builder — Build Orchestrator
===================================
Drives the whole pipeline::

    manifest → resolve & download packages → VFS → overlays → state synthesis
             → initramfs → SquashFS → EFI System Partition → hybrid ISO

and reports progress through thread-safe callbacks (used by both the CLI
and the Tk GUI).
"""

from __future__ import annotations

import hashlib
import os
import shutil
import threading
import time
import traceback
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Callable, Dict, List, Optional, Tuple


class BuildStage(IntEnum):
    IDLE = 0
    LOADING_CONFIG = 1
    RESOLVING_PACKAGES = 2
    INIT_VFS = 3
    INGESTING_PACKAGES = 4
    INGESTING_OVERLAYS = 5
    SYNTHESISING_STATE = 6
    BUILDING_INITRAMFS = 7
    BUILDING_SQUASHFS = 8
    BUILDING_ESP = 9
    ASSEMBLING_ISO = 10
    FINALISING = 11
    DONE = 12
    ERROR = 99


STAGE_LABELS = {
    BuildStage.IDLE: "Idle",
    BuildStage.LOADING_CONFIG: "Loading build manifest…",
    BuildStage.RESOLVING_PACKAGES: "Resolving & downloading packages…",
    BuildStage.INIT_VFS: "Initialising POSIX VFS…",
    BuildStage.INGESTING_PACKAGES: "Installing packages into the VFS…",
    BuildStage.INGESTING_OVERLAYS: "Applying rootfs overlays…",
    BuildStage.SYNTHESISING_STATE: "Synthesising system state (users, services, hooks)…",
    BuildStage.BUILDING_INITRAMFS: "Building live initramfs…",
    BuildStage.BUILDING_SQUASHFS: "Building root filesystem (SquashFS)…",
    BuildStage.BUILDING_ESP: "Building EFI System Partition…",
    BuildStage.ASSEMBLING_ISO: "Assembling hybrid ISO9660 image…",
    BuildStage.FINALISING: "Finalising and verifying…",
    BuildStage.DONE: "Build complete ✓",
    BuildStage.ERROR: "Build failed ✗",
}

TOTAL_STAGES = 11


class BuildError(RuntimeError):
    pass


@dataclass
class BuildResult:
    success: bool = False
    output_path: str = ""
    output_size: int = 0
    elapsed_seconds: float = 0.0
    error_message: str = ""
    node_count: int = 0
    package_count: int = 0
    sha256: str = ""
    warnings: List[str] = field(default_factory=list)


class BuildController:
    """Runs a build on a background thread with progress/log callbacks."""

    def __init__(self) -> None:
        self._thread: Optional[threading.Thread] = None
        self._cancel_event = threading.Event()
        self._lock = threading.Lock()
        self._stage = BuildStage.IDLE
        self.keep_work = False
        self.on_stage_changed: Optional[Callable[[BuildStage, str], None]] = None
        self.on_progress: Optional[Callable[[float], None]] = None
        self.on_log: Optional[Callable[[str], None]] = None
        self.on_finished: Optional[Callable[[BuildResult], None]] = None

    @property
    def stage(self) -> BuildStage:
        with self._lock:
            return self._stage

    @property
    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def cancel(self) -> None:
        self._cancel_event.set()

    def _check_cancelled(self) -> None:
        if self._cancel_event.is_set():
            raise InterruptedError("Build cancelled by user")

    def _set_stage(self, stage: BuildStage) -> None:
        with self._lock:
            self._stage = stage
        label = STAGE_LABELS.get(stage, str(stage))
        if self.on_stage_changed:
            self.on_stage_changed(stage, label)
        if self.on_log:
            self.on_log(f"[stage] {label}")
        if stage.value <= TOTAL_STAGES and self.on_progress:
            self.on_progress(max(0, stage.value - 1) / TOTAL_STAGES)

    def _sub_progress(self, frac: float) -> None:
        if self.on_progress:
            st = self.stage
            if st.value <= TOTAL_STAGES:
                self.on_progress((st.value - 1 + max(0.0, min(1.0, frac))) / TOTAL_STAGES)

    def _log(self, message: str) -> None:
        if self.on_log:
            self.on_log(message)

    def start(self, manifest_path: str) -> None:
        if self.is_running:
            raise RuntimeError("A build is already in progress")
        self._cancel_event.clear()
        self._thread = threading.Thread(target=self._run, args=(manifest_path,), name="torito-build", daemon=True)
        self._thread.start()

    def run_sync(self, manifest_path: str) -> BuildResult:
        holder: List[BuildResult] = []
        prev = self.on_finished
        self.on_finished = lambda r: holder.append(r)
        try:
            self._run(manifest_path)
        finally:
            self.on_finished = prev
        return holder[0]

    # ------------------------------------------------------------------
    def _run(self, manifest_path: str) -> None:
        result = BuildResult()
        t0 = time.monotonic()
        try:
            self._pipeline(manifest_path, result)
            result.success = True
        except InterruptedError:
            result.error_message = "Build cancelled by user"
            self._log("⚠ Build cancelled")
        except Exception as exc:  # noqa: BLE001 — report everything to the UI
            result.error_message = f"{type(exc).__name__}: {exc}"
            self._log(f"✗ ERROR: {result.error_message}")
            self._log(traceback.format_exc())
        finally:
            result.elapsed_seconds = time.monotonic() - t0
            self._set_stage(BuildStage.DONE if result.success else BuildStage.ERROR)
            if result.success and self.on_progress:
                self.on_progress(1.0)
            self._log(f"  Elapsed: {result.elapsed_seconds:.1f}s")
            if self.on_finished:
                self.on_finished(result)

    # ------------------------------------------------------------------
    def _pipeline(self, manifest_path: str, result: BuildResult) -> None:
        from .boot import (
            INITRD_ISO_PATH, KERNEL_ISO_PATH, SQUASHFS_ISO_PATH, SYSLINUX_DIR, SYSLINUX_MODULES,
            generate_syslinux_cfg, generate_systemd_boot_entries,
        )
        from .config import load_config
        from .fatfs import build_fat_image
        from .ingest import PackageRecord, ingest_overlay_directory, ingest_package, write_pacman_local_db
        from .initramfs import build_live_initramfs
        from .iso9660 import Iso9660Builder
        from .kmod import KernelInfo, find_kernels
        from .mutations import apply_all_mutations, emulate_install_scripts, install_deferred_hooks, remove_paths
        from .repo import PackageDatabase, RepoSpec
        from .squashfs import SquashFSWriter
        from .vfs import BlobStore, PosixVfs, VfsNodeType

        log = self._log

        # 1 ── manifest ────────────────────────────────────────────────
        self._set_stage(BuildStage.LOADING_CONFIG)
        config = load_config(manifest_path)
        log(f"  Project: {config.name} {config.version} ({config.arch})")
        log(f"  Output:  {config.iso.output_path}")
        epoch = config.source_date_epoch if config.source_date_epoch is not None else int(time.time())
        os.makedirs(config.work_dir, exist_ok=True)
        os.makedirs(config.cache_dir, exist_ok=True)
        want_kernel = config.bootloader.bios != "none" or config.bootloader.uefi != "none"

        # 2 ── packages ────────────────────────────────────────────────
        self._set_stage(BuildStage.RESOLVING_PACKAGES)
        resolved = []
        pkg_paths: Dict[str, str] = {}
        tool_paths: Dict[str, str] = {}
        db: Optional[PackageDatabase] = None
        if config.package_names:
            db = PackageDatabase(
                [RepoSpec(r.name, r.servers) for r in config.repositories],
                arch=config.arch, cache_dir=config.cache_dir, log=log,
            )
            db.refresh()
            resolved = db.resolve(config.package_names, preferences=config.package_preferences, ignore=config.ignore_packages)
            total_c = sum(p.csize for p in resolved)
            total_i = sum(p.isize for p in resolved)
            log(f"  {len(resolved)} packages ({total_c / 1048576:.0f} MiB download, {total_i / 1048576:.0f} MiB installed)")
            last = [0.0]

            def dl_progress(i: int, n: int, p) -> None:
                self._sub_progress(i / max(1, n))
                now = time.monotonic()
                if now - last[0] > 5 or i == n:
                    last[0] = now
                    log(f"    downloaded {i}/{n}")
                self._check_cancelled()

            pkg_paths = db.download(resolved, progress=dl_progress)
            # Build-only tools (not installed into the image)
            names = {p.name for p in resolved}
            tools = []
            if want_kernel and "busybox" not in names:
                tools.append("busybox")
            if config.bootloader.bios == "syslinux" and not config.bootloader.bios_binary_path and "syslinux" not in names:
                tools.append("syslinux")
            if config.bootloader.uefi == "systemd-boot" and not config.bootloader.efi_binary_path and "systemd" not in names:
                tools.append("systemd")
            tool_pkgs = [db.by_name[t] for t in tools if t in db.by_name]
            if tool_pkgs:
                log(f"  build tools: {', '.join(p.name for p in tool_pkgs)}")
                tool_paths = db.download(tool_pkgs)
        else:
            log("  no repository packages requested")
        self._check_cancelled()

        # 3 ── VFS ─────────────────────────────────────────────────────
        self._set_stage(BuildStage.INIT_VFS)
        store = BlobStore(os.path.join(config.work_dir, "blobs.pack"))
        vfs = PosixVfs(source_date_epoch=epoch, blob_store=store)
        vfs.init_base_hierarchy(usrmerge=True, device_nodes=True)
        log(f"  base hierarchy: {vfs.node_count()} nodes")

        try:
            # 4 ── install packages ────────────────────────────────────────
            self._set_stage(BuildStage.INGESTING_PACKAGES)
            records: List[PackageRecord] = []
            explicit = set(config.package_names)
            t_ing = time.monotonic()
            for i, p in enumerate(resolved):
                self._check_cancelled()
                rec = PackageRecord(name=p.name, reason_explicit=p.name in explicit)
                ingest_package(vfs, pkg_paths[p.name], fmt="pacman", record=rec)
                records.append(rec)
                self._sub_progress((i + 1) / max(1, len(resolved) + len(config.packages)))
                if (i + 1) % 50 == 0 or i + 1 == len(resolved):
                    log(f"    installed {i + 1}/{len(resolved)} ({vfs.node_count()} nodes, {store.size / 1048576:.0f} MiB)")
            for spec in config.packages:
                self._check_cancelled()
                if not os.path.isfile(spec.path):
                    raise BuildError(f"package file not found: {spec.path}")
                rec = PackageRecord(name=os.path.basename(spec.path))
                n = ingest_package(vfs, spec.path, fmt=spec.format, record=rec)
                if rec.pkginfo:
                    records.append(rec)
                log(f"  local package {os.path.basename(spec.path)}: {n} nodes")
            if records:
                write_pacman_local_db(vfs, records, install_date=epoch)
            log(f"  packages installed in {time.monotonic() - t_ing:.1f}s")

            # 5 ── overlays ───────────────────────────────────────────────
            self._set_stage(BuildStage.INGESTING_OVERLAYS)
            for d in config.rootfs_overlay_dirs:
                self._check_cancelled()
                if not os.path.isdir(d):
                    raise BuildError(f"overlay directory not found: {d}")
                n = ingest_overlay_directory(vfs, d)
                log(f"  overlay {d}: {n} nodes")

            # 6 ── state synthesis ────────────────────────────────────────
            self._set_stage(BuildStage.SYNTHESISING_STATE)
            if config.remove_paths:
                remove_paths(vfs, config.remove_paths, log)
            emulate_install_scripts(vfs, [r.name for r in records], {r.name: r.install_script for r in records}, log)
            install_deferred_hooks(vfs, log)
            apply_all_mutations(vfs, config, log)
            vfs.fixup_nlinks()
            log(f"  VFS: {vfs.node_count()} nodes, {vfs.total_file_bytes() / 1048576:.0f} MiB of file data")
            result.node_count = vfs.node_count()
            result.package_count = len(records)

            # 7 ── kernel & initramfs ─────────────────────────────────────
            self._set_stage(BuildStage.BUILDING_INITRAMFS)
            kernel: Optional[KernelInfo] = None
            kernel_bytes = b""
            initramfs_bytes = b""
            ucode: List[Tuple[str, bytes]] = []
            if want_kernel:
                kernels = find_kernels(vfs)
                if config.kernel.package:
                    kernels = [k for k in kernels if k.pkgbase == config.kernel.package] or kernels
                if config.kernel.vmlinuz_path:
                    with open(config.kernel.vmlinuz_path, "rb") as fh:
                        kernel_bytes = fh.read()
                    kernel = kernels[0] if kernels else None
                    if kernel is None:
                        raise BuildError("an explicit vmlinuz needs matching kernel modules in the image")
                elif kernels:
                    kernel = kernels[0]
                    kernel_bytes = vfs.lookup(kernel.vmlinuz_path).data  # type: ignore[union-attr]
                else:
                    raise BuildError("no kernel found: add a kernel package (e.g. 'linux') to `packages`")
                log(f"  kernel {kernel.version} ({len(kernel_bytes) / 1048576:.1f} MiB)")

                busybox = None
                bb_node = vfs.lookup("/usr/bin/busybox")
                if bb_node is not None and bb_node.node_type == VfsNodeType.REGULAR_FILE:
                    busybox = bb_node.data
                elif "busybox" in tool_paths:
                    tvfs = PosixVfs(source_date_epoch=epoch)
                    ingest_package(tvfs, tool_paths["busybox"], fmt="pacman")
                    busybox = tvfs.read_file("/usr/bin/busybox")
                if not busybox:
                    raise BuildError("busybox is required for the live initramfs (add it to packages)")
                if b"ld-linux" in busybox[:4096] or b"/lib64/ld" in busybox[:8192]:
                    raise BuildError("busybox must be statically linked")
                initramfs_bytes = build_live_initramfs(
                    vfs, kernel, busybox, label=config.iso.volume_id, squashfs_path=SQUASHFS_ISO_PATH,
                    overlay_size=config.live.overlay_size, copytoram=config.live.copytoram,
                    extra_modules=config.kernel.initramfs_modules, compression=config.kernel.initramfs_compression,
                    epoch=epoch, log=log,
                )
                log(f"  initramfs: {len(initramfs_bytes) / 1048576:.1f} MiB")
                if config.kernel.microcode:
                    for name in ("intel-ucode.img", "amd-ucode.img"):
                        data = vfs.read_file(f"/boot/{name}")
                        if data:
                            ucode.append((name.split("-")[0], data))
                    if ucode:
                        log("  microcode: " + ", ".join(n for n, _ in ucode))
            self._check_cancelled()

            # 8 ── squashfs ────────────────────────────────────────────────
            self._set_stage(BuildStage.BUILDING_SQUASHFS)
            sfs_path = os.path.join(config.work_dir, "rootfs.sfs")
            writer = SquashFSWriter(
                block_size=config.iso.squashfs_block_size, compression=config.iso.squashfs_compression,
                level=config.iso.squashfs_level, log=log, progress=self._sub_progress,
            )
            sfs_size = writer.build_to_file(vfs, sfs_path)
            log(f"  rootfs.sfs: {sfs_size / 1048576:.1f} MiB")
            self._check_cancelled()

            # 9 ── EFI System Partition ────────────────────────────────────
            self._set_stage(BuildStage.BUILDING_ESP)
            initrd_paths = [f"/boot/ucode/{n}.img" for n, _ in ucode] + [INITRD_ISO_PATH]
            esp_bytes = b""
            if want_kernel and config.bootloader.uefi != "none":
                efi_bin = b""
                if config.bootloader.efi_binary_path:
                    with open(config.bootloader.efi_binary_path, "rb") as fh:
                        efi_bin = fh.read()
                else:
                    efi_bin = vfs.read_file("/usr/lib/systemd/boot/efi/systemd-bootx64.efi") or b""
                    if not efi_bin and "systemd" in tool_paths:
                        tvfs = PosixVfs(source_date_epoch=epoch)
                        ingest_package(tvfs, tool_paths["systemd"], fmt="pacman")
                        efi_bin = tvfs.read_file("/usr/lib/systemd/boot/efi/systemd-bootx64.efi") or b""
                if efi_bin[:2] != b"MZ":
                    raise BuildError("no valid UEFI boot loader (systemd-bootx64.efi) available")
                esp_files: Dict[str, bytes] = {
                    "/EFI/BOOT/BOOTX64.EFI": efi_bin,
                    KERNEL_ISO_PATH: kernel_bytes,
                    INITRD_ISO_PATH: initramfs_bytes,
                }
                for n, data in ucode:
                    esp_files[f"/boot/ucode/{n}.img"] = data
                for p, text in generate_systemd_boot_entries(config, initrd_paths).items():
                    esp_files[p] = text.encode()
                esp_bytes = build_fat_image(esp_files, label="EFIBOOT", epoch=epoch)
                log(f"  ESP: {len(esp_bytes) / 1048576:.1f} MiB (systemd-boot)")
            self._check_cancelled()

            # 10 ── ISO ────────────────────────────────────────────────────
            self._set_stage(BuildStage.ASSEMBLING_ISO)
            iso = Iso9660Builder(
                volume_id=config.iso.volume_id, system_id=config.iso.system_id,
                publisher_id=config.iso.publisher_id, application_id=config.iso.application_id,
            )
            iso._creation_time = epoch
            iso.add_host_file(SQUASHFS_ISO_PATH, sfs_path)
            if want_kernel:
                iso.add_file(KERNEL_ISO_PATH, kernel_bytes)
                iso.add_file(INITRD_ISO_PATH, initramfs_bytes)
                for n, data in ucode:
                    iso.add_file(f"/boot/ucode/{n}.img", data)
            if want_kernel and config.bootloader.bios == "syslinux":
                if config.bootloader.bios_binary_path:
                    with open(config.bootloader.bios_binary_path, "rb") as fh:
                        iso.add_file(f"{SYSLINUX_DIR}/isolinux.bin", fh.read())
                    sl = None
                else:
                    sl = vfs if vfs.lookup("/usr/lib/syslinux/bios/isolinux.bin") else None
                    if sl is None and "syslinux" in tool_paths:
                        sl = PosixVfs(source_date_epoch=epoch)
                        ingest_package(sl, tool_paths["syslinux"], fmt="pacman")
                    if sl is None:
                        raise BuildError("syslinux is required for BIOS boot (add it to packages or set bootloader.bios = 'none')")
                    for f in ["isolinux.bin"] + SYSLINUX_MODULES:
                        data = sl.read_file(f"/usr/lib/syslinux/bios/{f}")
                        if data is None:
                            raise BuildError(f"syslinux file missing: {f}")
                        iso.add_file(f"{SYSLINUX_DIR}/{f}", data)
                    iso.set_isohybrid_mbr(sl.read_file("/usr/lib/syslinux/bios/isohdpfx.bin") or b"")
                iso.add_file(f"{SYSLINUX_DIR}/syslinux.cfg", generate_syslinux_cfg(config, initrd_paths).encode())
                iso.set_bios_boot(f"{SYSLINUX_DIR}/isolinux.bin", catalog_path=f"{SYSLINUX_DIR}/boot.cat")
            if esp_bytes:
                iso.set_efi_image(esp_bytes)
                # Also expose the boot files on ISO9660 for firmware that browses it.
                iso.add_file("/EFI/BOOT/BOOTX64.EFI", esp_files["/EFI/BOOT/BOOTX64.EFI"])
            out_path = config.iso.output_path
            os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
            size = iso.write_to_file(out_path)
            log(f"  ISO: {size / 1048576:.1f} MiB → {out_path}")
            log(f"  layout: {iso.layout}")

            # 11 ── finalise ───────────────────────────────────────────────
            self._set_stage(BuildStage.FINALISING)
            h = hashlib.sha256()
            with open(out_path, "rb") as fh:
                for chunk in iter(lambda: fh.read(8 << 20), b""):
                    h.update(chunk)
            result.sha256 = h.hexdigest()
            with open(out_path + ".sha256", "w", encoding="utf-8") as fh:
                fh.write(f"{result.sha256}  {os.path.basename(out_path)}\n")
            from .inspect import verify_iso

            problems = verify_iso(out_path)
            for p in problems:
                log(f"  ⚠ verify: {p}")
            result.warnings.extend(problems)
            log(f"  SHA-256: {result.sha256}")
            result.output_path = out_path
            result.output_size = size
            if not self.keep_work:
                try:
                    os.remove(sfs_path)
                except OSError:
                    pass
        finally:
            store.delete()
