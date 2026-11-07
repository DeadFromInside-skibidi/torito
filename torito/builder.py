"""
torito.builder — Threaded Build Orchestrator
================================================
Drives the ISO compilation pipeline stage by stage, reporting progress
and streaming stdout/stderr telemetry to the GUI via thread-safe callbacks.
"""

from __future__ import annotations

import os
import threading
import time
import traceback
from dataclasses import dataclass, field
from enum import IntEnum, auto
from typing import Callable, List, Optional


class BuildStage(IntEnum):
    """Sequential stages of the ISO build pipeline."""

    IDLE = 0
    LOADING_CONFIG = 1
    INIT_VFS = 2
    INGESTING_PACKAGES = 3
    INGESTING_OVERLAYS = 4
    SYNTHESISING_STATE = 5
    BUILDING_INITRAMFS = 6
    BUILDING_SQUASHFS = 7
    BUILDING_ESP = 8
    ASSEMBLING_ISO = 9
    FINALISING = 10
    DONE = 11
    ERROR = 99


STAGE_LABELS = {
    BuildStage.IDLE: "Idle",
    BuildStage.LOADING_CONFIG: "Loading build manifest…",
    BuildStage.INIT_VFS: "Initialising POSIX VFS…",
    BuildStage.INGESTING_PACKAGES: "Ingesting packages…",
    BuildStage.INGESTING_OVERLAYS: "Ingesting rootfs overlays…",
    BuildStage.SYNTHESISING_STATE: "Synthesising system state…",
    BuildStage.BUILDING_INITRAMFS: "Packing initramfs (CPIO + Zstd)…",
    BuildStage.BUILDING_SQUASHFS: "Building filesystem.squashfs…",
    BuildStage.BUILDING_ESP: "Building EFI System Partition…",
    BuildStage.ASSEMBLING_ISO: "Assembling hybrid ISO9660 image…",
    BuildStage.FINALISING: "Finalising and verifying…",
    BuildStage.DONE: "Build complete ✓",
    BuildStage.ERROR: "Build failed ✗",
}

# Number of stages for progress bar (excluding IDLE, DONE, ERROR)
TOTAL_STAGES = 10


@dataclass
class BuildResult:
    """Outcome of a completed (or failed) build."""

    success: bool = False
    output_path: str = ""
    output_size: int = 0
    elapsed_seconds: float = 0.0
    error_message: str = ""
    node_count: int = 0


class BuildController:
    """
    Manages the ISO build pipeline in a background thread with
    thread-safe progress and telemetry callbacks for the GUI.
    """

    def __init__(self) -> None:
        self._thread: Optional[threading.Thread] = None
        self._cancel_event = threading.Event()
        self._lock = threading.Lock()
        self._stage = BuildStage.IDLE
        self._stage_progress: float = 0.0  # 0.0 – 1.0 within current stage

        # Callbacks (set by the GUI)
        self.on_stage_changed: Optional[Callable[[BuildStage, str], None]] = None
        self.on_progress: Optional[Callable[[float], None]] = None  # 0.0 – 1.0 overall
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
        """Signal the build thread to stop at the next cancellation check."""
        self._cancel_event.set()

    def _check_cancelled(self) -> None:
        if self._cancel_event.is_set():
            raise InterruptedError("Build cancelled by user")

    def _set_stage(self, stage: BuildStage) -> None:
        with self._lock:
            self._stage = stage
            self._stage_progress = 0.0
        label = STAGE_LABELS.get(stage, str(stage))
        if self.on_stage_changed:
            self.on_stage_changed(stage, label)
        if self.on_log:
            self.on_log(f"[stage] {label}")
        # Update overall progress
        if stage.value <= TOTAL_STAGES:
            overall = stage.value / TOTAL_STAGES
            if self.on_progress:
                self.on_progress(overall)

    def _log(self, message: str) -> None:
        if self.on_log:
            self.on_log(message)

    def start(self, manifest_path: str) -> None:
        """Launch the build pipeline in a background thread."""
        if self.is_running:
            raise RuntimeError("A build is already in progress")

        self._cancel_event.clear()
        self._thread = threading.Thread(
            target=self._run,
            args=(manifest_path,),
            name="torito-build",
            daemon=True,
        )
        self._thread.start()

    def _run(self, manifest_path: str) -> None:
        """The actual build pipeline — runs on the background thread."""
        result = BuildResult()
        t0 = time.monotonic()

        try:
            # ── Stage 1: Load config ──
            self._set_stage(BuildStage.LOADING_CONFIG)
            self._check_cancelled()
            from .config import load_config

            config = load_config(manifest_path)
            self._log(f"  Project: {config.name} v{config.version} ({config.arch})")
            self._log(f"  Output:  {config.iso.output_path}")

            # ── Stage 2: Initialise VFS ──
            self._set_stage(BuildStage.INIT_VFS)
            self._check_cancelled()
            from .vfs import PosixVfs

            vfs = PosixVfs(source_date_epoch=config.source_date_epoch)
            vfs.init_base_hierarchy()
            self._log(f"  Base hierarchy: {vfs.node_count()} nodes")

            # ── Stage 3: Ingest packages ──
            self._set_stage(BuildStage.INGESTING_PACKAGES)
            self._check_cancelled()
            from .ingest import ingest_package

            for i, pkg in enumerate(config.packages):
                self._check_cancelled()
                self._log(f"  [{i + 1}/{len(config.packages)}] {os.path.basename(pkg.path)}")
                if os.path.isfile(pkg.path):
                    count = ingest_package(
                        vfs, pkg.path, fmt=pkg.format,
                        progress=lambda p: None,
                    )
                    self._log(f"    → {count} nodes")
                else:
                    self._log(f"    ⚠ File not found: {pkg.path}")

            # ── Stage 4: Ingest overlays ──
            self._set_stage(BuildStage.INGESTING_OVERLAYS)
            self._check_cancelled()
            from .ingest import ingest_overlay_directory

            for overlay_dir in config.rootfs_overlay_dirs:
                self._check_cancelled()
                if os.path.isdir(overlay_dir):
                    self._log(f"  Overlay: {overlay_dir}")
                    count = ingest_overlay_directory(vfs, overlay_dir)
                    self._log(f"    → {count} nodes")
                else:
                    self._log(f"  ⚠ Overlay dir not found: {overlay_dir}")

            # ── Stage 5: State synthesis ──
            self._set_stage(BuildStage.SYNTHESISING_STATE)
            self._check_cancelled()
            from .mutations import apply_all_mutations

            apply_all_mutations(vfs, config)
            self._log(f"  Users: {len(config.users)}, Services: {len(config.services)}")
            self._log(f"  VFS total: {vfs.node_count()} nodes")

            # Fixup nlinks before serialisation
            vfs.fixup_nlinks()

            # ── Stage 6: Build initramfs ──
            self._set_stage(BuildStage.BUILDING_INITRAMFS)
            self._check_cancelled()
            initramfs_bytes = b""

            # Check if we have a kernel and need an initramfs
            kernel_bytes = b""
            if config.kernel.vmlinuz_path and os.path.isfile(config.kernel.vmlinuz_path):
                with open(config.kernel.vmlinuz_path, "rb") as kf:
                    kernel_bytes = kf.read()
                self._log(f"  Kernel: {len(kernel_bytes):,} bytes")

                # Build initramfs from VFS subset
                from .cpio import build_initramfs
                from .vfs import PosixVfs as _PVfs

                initramfs_vfs = _PVfs(source_date_epoch=config.source_date_epoch)
                initramfs_vfs.init_base_hierarchy()

                # Add init script
                init_script = (
                    b"#!/bin/sh\n"
                    b"mount -t proc proc /proc\n"
                    b"mount -t sysfs sysfs /sys\n"
                    b"mount -t devtmpfs devtmpfs /dev\n"
                    b"exec /sbin/init\n"
                )
                initramfs_vfs.add_file("/init", init_script, mode=0o755)

                # Add any extra initramfs files
                for ef in config.kernel.initramfs_extra_files:
                    if os.path.isfile(ef):
                        initramfs_vfs.ingest_host_file(ef, "/" + os.path.basename(ef))

                for ed in config.kernel.initramfs_extra_dirs:
                    if os.path.isdir(ed):
                        initramfs_vfs.ingest_host_directory(ed, "/")

                initramfs_vfs.fixup_nlinks()
                initramfs_bytes = build_initramfs(initramfs_vfs, compression="zstd")
                self._log(f"  Initramfs: {len(initramfs_bytes):,} bytes (zstd)")
            else:
                self._log("  No kernel specified; skipping initramfs")

            # Store kernel and initramfs in the main VFS
            if kernel_bytes:
                vfs.add_file("/boot/vmlinuz", kernel_bytes, mode=0o644)
            if initramfs_bytes:
                vfs.add_file("/boot/initramfs.img", initramfs_bytes, mode=0o644)

            # ── Stage 7: Build SquashFS ──
            self._set_stage(BuildStage.BUILDING_SQUASHFS)
            self._check_cancelled()
            from .squashfs import build_squashfs

            squashfs_bytes = build_squashfs(
                vfs,
                block_size=config.iso.squashfs_block_size,
                compression=config.iso.squashfs_compression,
            )
            self._log(f"  SquashFS: {len(squashfs_bytes):,} bytes")

            # ── Stage 8: Build EFI ESP ──
            self._set_stage(BuildStage.BUILDING_ESP)
            self._check_cancelled()
            from .boot import (
                generate_grub_cfg,
                generate_limine_cfg,
                generate_isolinux_cfg,
                generate_startup_nsh,
                generate_systemd_boot_entries,
            )

            grub_cfg_text = generate_grub_cfg(config)
            limine_cfg_text = generate_limine_cfg(config)
            isolinux_cfg_text = generate_isolinux_cfg(config)
            startup_nsh_text = generate_startup_nsh(config)

            esp_extra_files = {
                "/EFI/BOOT/grub.cfg": grub_cfg_text.encode("utf-8"),
                "/startup.nsh": startup_nsh_text.encode("utf-8"),
            }
            for e_path, e_text in generate_systemd_boot_entries(config).items():
                esp_extra_files[e_path] = e_text.encode("utf-8")

            efi_binary = b""
            efi_esp_bytes = b""

            if config.bootloader.efi_binary_path and os.path.isfile(config.bootloader.efi_binary_path):
                with open(config.bootloader.efi_binary_path, "rb") as ef:
                    efi_binary = ef.read()
                self._log(f"  EFI binary: {len(efi_binary):,} bytes")

                from .fat32 import build_efi_esp

                efi_esp_bytes = build_efi_esp(
                    efi_binary=efi_binary,
                    kernel=kernel_bytes,
                    initramfs=initramfs_bytes,
                    extra_files=esp_extra_files,
                )
                self._log(f"  ESP image: {len(efi_esp_bytes):,} bytes")
            else:
                self._log("  No EFI binary specified; creating minimal ESP with fallback boot scripts")
                from .fat32 import build_efi_esp

                efi_esp_bytes = build_efi_esp(
                    efi_binary=b"",
                    kernel=kernel_bytes,
                    initramfs=initramfs_bytes,
                    size_mb=4,
                    extra_files=esp_extra_files,
                )

            # ── Stage 9: Assemble ISO ──
            self._set_stage(BuildStage.ASSEMBLING_ISO)
            self._check_cancelled()
            from .iso9660 import build_hybrid_iso

            bios_boot_image = b""
            if config.bootloader.bios_binary_path and os.path.isfile(config.bootloader.bios_binary_path):
                with open(config.bootloader.bios_binary_path, "rb") as bf:
                    bios_boot_image = bf.read()
                self._log(f"  BIOS boot image: {len(bios_boot_image):,} bytes")

            iso_files = {
                "/live/filesystem.squashfs": squashfs_bytes,
                "/boot/grub/grub.cfg": grub_cfg_text.encode("utf-8"),
                "/limine.cfg": limine_cfg_text.encode("utf-8"),
                "/boot/isolinux/isolinux.cfg": isolinux_cfg_text.encode("utf-8"),
                "/startup.nsh": startup_nsh_text.encode("utf-8"),
            }
            if kernel_bytes:
                iso_files["/boot/vmlinuz"] = kernel_bytes
            if initramfs_bytes:
                iso_files["/boot/initramfs.img"] = initramfs_bytes

            iso_bytes = build_hybrid_iso(
                files=iso_files,
                bios_boot_image=bios_boot_image,
                efi_boot_image=efi_esp_bytes,
                volume_id=config.iso.volume_id,
                system_id=config.iso.system_id,
                publisher_id=config.iso.publisher_id,
                application_id=config.iso.application_id,
            )
            self._log(f"  ISO image: {len(iso_bytes):,} bytes")

            # ── Stage 10: Finalise ──
            self._set_stage(BuildStage.FINALISING)
            self._check_cancelled()

            output_dir = os.path.dirname(config.iso.output_path)
            if output_dir and not os.path.isdir(output_dir):
                os.makedirs(output_dir, exist_ok=True)

            with open(config.iso.output_path, "wb") as out:
                out.write(iso_bytes)

            import hashlib

            sha256 = hashlib.sha256(iso_bytes).hexdigest()
            self._log(f"  SHA-256: {sha256}")
            self._log(f"  Written: {config.iso.output_path}")

            result.success = True
            result.output_path = config.iso.output_path
            result.output_size = len(iso_bytes)
            result.node_count = vfs.node_count()

        except InterruptedError:
            result.success = False
            result.error_message = "Build cancelled by user"
            self._log("⚠ Build cancelled")

        except Exception as exc:
            result.success = False
            result.error_message = f"{type(exc).__name__}: {exc}"
            self._log(f"✗ ERROR: {result.error_message}")
            self._log(traceback.format_exc())

        finally:
            result.elapsed_seconds = time.monotonic() - t0
            self._set_stage(BuildStage.DONE if result.success else BuildStage.ERROR)
            self._log(f"  Elapsed: {result.elapsed_seconds:.2f}s")
            if self.on_finished:
                self.on_finished(result)

