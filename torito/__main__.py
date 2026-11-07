"""
torito.__main__ — CLI & GUI entry point
==========================================
Provides both a GUI launcher and a headless CLI mode for automated builds.
"""

from __future__ import annotations

import argparse
import os
import struct
import sys
import time


def _scaffold_project(target_dir: str) -> int:
    """Scaffold a ready-to-compile distribution project skeleton."""
    abs_dir = os.path.abspath(target_dir)
    os.makedirs(os.path.join(abs_dir, "overlays", "rootfs", "etc"), exist_ok=True)
    os.makedirs(os.path.join(abs_dir, "boot"), exist_ok=True)
    os.makedirs(os.path.join(abs_dir, "packages"), exist_ok=True)
    os.makedirs(os.path.join(abs_dir, "output"), exist_ok=True)

    # 1. Overlay files
    motd_path = os.path.join(abs_dir, "overlays", "rootfs", "etc", "motd")
    with open(motd_path, "wb") as f:
        f.write(b"Welcome to Torito Linux! Booted directly on userspace hardware.\n")

    # 2. Mock EFI stub and kernel
    efi_path = os.path.join(abs_dir, "boot", "BOOTX64.EFI")
    with open(efi_path, "wb") as f:
        # Minimal PE/COFF header stub
        f.write(b"MZ\x90\x00" + b"\x00" * 58 + struct.pack("<I", 0x80) + b"\x00" * 64 + b"PE\x00\x00\x64\x86" + b"\xCC" * 1024)

    kernel_path = os.path.join(abs_dir, "boot", "vmlinuz-linux")
    with open(kernel_path, "wb") as f:
        f.write(b"\x1f\x8b\x08\x00fake-vmlinuz-linux-kernel-binary-stream" + b"\x00" * 2048)

    # 3. Declarative manifest
    manifest_path = os.path.join(abs_dir, "distro.toml")
    distro_name = os.path.basename(abs_dir).capitalize()
    manifest_content = f"""# Torito Build Manifest for {distro_name}
name        = "{distro_name}"
version     = "1.0.0"
arch        = "x86_64"
hostname    = "{distro_name.lower()}"
locale      = "en_US.UTF-8"
timezone    = "UTC"

rootfs_overlay_dirs = [
    "overlays/rootfs",
]

[kernel]
vmlinuz = "boot/vmlinuz-linux"
cmdline = "root=live:CDLABEL={distro_name.upper()} rd.live.image quiet splash"

[bootloader]
efi_binary = "boot/BOOTX64.EFI"

[[users]]
name     = "user"
uid      = 1000
gid      = 1000
password = "live"
groups   = ["wheel", "audio", "video"]

[[services]]
name        = "systemd-networkd"
init_system = "systemd"

[iso]
output               = "output/{distro_name.lower()}-x86_64.iso"
volume_id            = "{distro_name.upper()}"
squashfs_compression = "zstd"
"""
    with open(manifest_path, "w", encoding="utf-8") as f:
        f.write(manifest_content)

    print(f"✓ Created new Torito distribution project at: {abs_dir}")
    print(f"  Manifest:   {manifest_path}")
    print(f"  Compile:    python -m torito {os.path.relpath(manifest_path)}")
    print(f"  GUI:        python -m torito --gui")
    return 0


def _cli_build(manifest_path: str, verbose: bool = False) -> int:
    """Run a headless build from the command line."""
    from .builder import BuildController, BuildResult, BuildStage

    controller = BuildController()
    result_holder: list = []
    done_event = __import__("threading").Event()

    def on_log(msg: str) -> None:
        if verbose:
            print(msg, flush=True)

    def on_stage(stage: BuildStage, label: str) -> None:
        print(f"[{stage.value:2d}/{10}] {label}", flush=True)

    def on_finished(result: BuildResult) -> None:
        result_holder.append(result)
        done_event.set()

    controller.on_log = on_log
    controller.on_stage_changed = on_stage
    controller.on_finished = on_finished

    controller.start(manifest_path)
    done_event.wait()

    result = result_holder[0]
    if result.success:
        size_mb = result.output_size / (1024 * 1024)
        print(f"\n✓ Build succeeded in {result.elapsed_seconds:.2f}s")
        print(f"  Output: {result.output_path} ({size_mb:.1f} MB)")
        print(f"  Nodes:  {result.node_count:,}")
        return 0
    else:
        print(f"\n✗ Build failed: {result.error_message}", file=sys.stderr)
        return 1


def main() -> None:
    """Parse arguments and dispatch to GUI or CLI mode."""
    parser = argparse.ArgumentParser(
        prog="torito",
        description="Torito — Rootless Linux ISO Compiler",
        epilog="Run without arguments to launch the GUI.",
    )
    parser.add_argument(
        "manifest",
        nargs="?",
        help="Path to a build manifest (.toml / .json / .ini)",
    )
    parser.add_argument(
        "--init",
        metavar="DIR",
        help="Scaffold a new distribution project skeleton",
    )
    parser.add_argument(
        "--gui",
        action="store_true",
        default=False,
        help="Force GUI mode even when a manifest is provided",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        default=False,
        help="Enable verbose output in CLI mode",
    )
    parser.add_argument(
        "--version",
        action="version",
        version="Torito 1.0.0",
    )

    args = parser.parse_args()

    if args.init:
        sys.exit(_scaffold_project(args.init))
    elif args.manifest and not args.gui:
        # Headless CLI mode
        if not os.path.isfile(args.manifest):
            print(f"Error: manifest file not found: {args.manifest}", file=sys.stderr)
            sys.exit(1)
        sys.exit(_cli_build(args.manifest, verbose=args.verbose))
    else:
        # GUI mode
        from .gui import main as gui_main
        gui_main()


if __name__ == "__main__":
    main()

