"""
torito.__main__ — CLI & GUI entry point
=======================================

    python -m torito distro.toml          build headlessly
    python -m torito distro.toml -v       … with full telemetry
    python -m torito --inspect out.iso    report on an ISO
    python -m torito --verify out.iso     exit 1 if the ISO looks unbootable
    python -m torito --init mydistro      scaffold a project (--template desktop|server)
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


def _scaffold_project(target_dir: str, template: str) -> int:
    from .templates import TEMPLATES, scaffold_project

    try:
        manifest = scaffold_project(target_dir, template)
    except (ValueError, FileExistsError) as exc:
        print(f"✗ {exc}", file=sys.stderr)
        return 1
    print(f"✓ Created a '{template}' Torito project in {os.path.dirname(manifest)}")
    print(f"  {TEMPLATES[template].summary}")
    print(f"  Edit:  {manifest}")
    print(f"  Build: python -m torito \"{manifest}\"")
    return 0


def _list_templates() -> int:
    from .templates import DEFAULT_TEMPLATE, TEMPLATES

    for t in TEMPLATES.values():
        mark = " (default)" if t.name == DEFAULT_TEMPLATE else ""
        print(f"  {t.name:<9} {t.summary}{mark}")
    return 0


def _cli_build(manifest_path: str, verbose: bool = False, keep_work: bool = False) -> int:
    from .builder import TOTAL_STAGES, BuildController, BuildResult, BuildStage

    controller = BuildController()
    controller.keep_work = keep_work
    holder: list = []
    done = threading.Event()

    def on_log(msg: str) -> None:
        if verbose or msg.startswith(("✗", "⚠", "  ⚠", "  •")):
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
    parser.add_argument("--init", metavar="DIR", help="create a new distribution project in DIR")
    parser.add_argument("--template", default="console",
                        help="project template for --init: console (default), desktop, server")
    parser.add_argument("--list-templates", action="store_true", help="show the available project templates")
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
    if args.list_templates:
        sys.exit(_list_templates())
    if args.init:
        sys.exit(_scaffold_project(args.init, args.template))
    if args.manifest and not args.gui:
        if not os.path.isfile(args.manifest):
            print(f"Error: manifest file not found: {args.manifest}", file=sys.stderr)
            sys.exit(1)
        sys.exit(_cli_build(args.manifest, verbose=args.verbose, keep_work=args.keep_work))
    from .gui import main as gui_main

    gui_main()


if __name__ == "__main__":
    main()
