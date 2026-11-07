"""
torito.__main__ — CLI & GUI entry point
=======================================

    python -m torito distro.toml          build headlessly
    python -m torito distro.toml -v       … with full telemetry
    python -m torito --inspect out.iso    report on an ISO
    python -m torito --verify out.iso     exit 1 if the ISO looks unbootable
    python -m torito --init mydistro      scaffold a project
    python -m torito                      GUI
"""

from __future__ import annotations

import argparse
import os
import sys
import threading

from . import __version__


def _utf8_console() -> None:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
        except (AttributeError, ValueError):
            pass


SCAFFOLD_MANIFEST = """# Torito build manifest for {name}
# Build:  python -m torito distro.toml -v
name        = "{name}"
version     = "1.0.0"
arch        = "x86_64"
hostname    = "{slug}"
locale      = "en_US.UTF-8"
timezone    = "UTC"
keymap      = "us"
default_target = "multi-user.target"

# Packages come from the Arch Linux repositories (core + extra) unless
# [[repositories]] says otherwise. Dependencies are resolved automatically.
packages = [
    "base", "linux", "linux-firmware",
    "networkmanager", "sudo", "nano", "vim",
]

# Files copied over the root filesystem (Windows line endings are fixed).
rootfs_overlay_dirs = ["overlays/rootfs"]

file_permissions = {{ "/etc/sudoers.d/10-wheel" = "0:0:440" }}

[[users]]
name     = "live"
password = "live"
groups   = ["wheel", "audio", "video", "network", "storage", "input"]

[[users]]
name     = "root"
password = "root"

[[services]]
name = "NetworkManager"

[iso]
output    = "output/{slug}-x86_64.iso"
volume_id = "{label}"
"""


def _scaffold_project(target_dir: str) -> int:
    abs_dir = os.path.abspath(target_dir)
    name = os.path.basename(abs_dir.rstrip("\\/")).capitalize() or "Mydistro"
    slug = name.lower()
    os.makedirs(os.path.join(abs_dir, "overlays", "rootfs", "etc", "sudoers.d"), exist_ok=True)
    os.makedirs(os.path.join(abs_dir, "output"), exist_ok=True)
    with open(os.path.join(abs_dir, "overlays", "rootfs", "etc", "motd"), "w", encoding="utf-8", newline="\n") as f:
        f.write(f"Welcome to {name}! Built with Torito.\n")
    with open(os.path.join(abs_dir, "overlays", "rootfs", "etc", "sudoers.d", "10-wheel"), "w", encoding="utf-8", newline="\n") as f:
        f.write("%wheel ALL=(ALL:ALL) ALL\n")
    manifest = os.path.join(abs_dir, "distro.toml")
    with open(manifest, "w", encoding="utf-8", newline="\n") as f:
        f.write(SCAFFOLD_MANIFEST.format(name=name, slug=slug, label=(slug.upper() + "_LIVE")[:32]))
    print(f"✓ Created Torito project at {abs_dir}")
    print(f"  Build: python -m torito {manifest} -v")
    return 0


def _cli_build(manifest_path: str, verbose: bool = False, keep_work: bool = False) -> int:
    from .builder import TOTAL_STAGES, BuildController, BuildResult, BuildStage

    controller = BuildController()
    controller.keep_work = keep_work
    holder: list = []
    done = threading.Event()

    def on_log(msg: str) -> None:
        if verbose or msg.startswith(("✗", "⚠", "  ⚠")):
            print(msg, flush=True)

    def on_stage(stage: BuildStage, label: str) -> None:
        if 0 < stage.value <= TOTAL_STAGES:
            print(f"[{stage.value:2d}/{TOTAL_STAGES}] {label}", flush=True)

    def on_finished(result: BuildResult) -> None:
        holder.append(result)
        done.set()

    controller.on_log = on_log
    controller.on_stage_changed = on_stage
    controller.on_finished = on_finished
    controller.start(manifest_path)
    done.wait()
    result: BuildResult = holder[0]
    if result.success:
        print(f"\n✓ Build succeeded in {result.elapsed_seconds:.1f}s")
        print(f"  Output:   {result.output_path} ({result.output_size / 1048576:.1f} MiB)")
        print(f"  SHA-256:  {result.sha256}")
        print(f"  Packages: {result.package_count}, nodes: {result.node_count:,}")
        for w in result.warnings:
            print(f"  ⚠ {w}")
        return 0
    print(f"\n✗ Build failed: {result.error_message}", file=sys.stderr)
    return 1


def main() -> None:
    _utf8_console()
    parser = argparse.ArgumentParser(prog="torito", description="Torito — rootless Linux ISO compiler",
                                     epilog="Run without arguments to launch the GUI.")
    parser.add_argument("manifest", nargs="?", help="build manifest (.toml / .json / .ini)")
    parser.add_argument("--init", metavar="DIR", help="scaffold a new distribution project")
    parser.add_argument("--inspect", metavar="ISO", help="print the boot structures of an ISO")
    parser.add_argument("--verify", metavar="ISO", help="verify an ISO; exit status 1 on problems")
    parser.add_argument("--gui", action="store_true", help="force GUI mode")
    parser.add_argument("--keep-work", action="store_true", help="keep the intermediate rootfs.sfs in work_dir")
    parser.add_argument("-v", "--verbose", action="store_true", help="verbose build telemetry")
    parser.add_argument("--version", action="version", version=f"Torito {__version__}")
    args = parser.parse_args()

    if args.inspect:
        from .inspect import inspect_iso

        inspect_iso(args.inspect)
        sys.exit(0)
    if args.verify:
        from .inspect import verify_iso

        problems = verify_iso(args.verify)
        for p in problems:
            print(f"✗ {p}")
        if not problems:
            print("✓ no problems found")
        sys.exit(1 if problems else 0)
    if args.init:
        sys.exit(_scaffold_project(args.init))
    if args.manifest and not args.gui:
        if not os.path.isfile(args.manifest):
            print(f"Error: manifest file not found: {args.manifest}", file=sys.stderr)
            sys.exit(1)
        sys.exit(_cli_build(args.manifest, verbose=args.verbose, keep_work=args.keep_work))
    from .gui import main as gui_main

    gui_main()


if __name__ == "__main__":
    main()
