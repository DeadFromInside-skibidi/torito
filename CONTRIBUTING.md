# Contributing to Torito

Thanks for helping. Torito's goal is simple: someone on Windows writes a
short manifest and gets an ISO that boots. Every change should keep that
working, or make it work for more people.

## Getting set up

```powershell
git clone https://github.com/DeadFromInside-skibidi/torito
cd torito
python -m venv .venv
.venv\Scripts\activate
pip install -e .
python -m unittest discover -s tests -v
```

The unit tests are offline and take a few seconds. The last one builds a
complete ISO from synthetic packages and runs the verifier on it.

## Testing a real build

```powershell
torito --init scratch
torito scratch\distro.toml -v
torito --verify scratch\output\scratch-x86_64.iso
```

Then boot the result. Any hypervisor works; on Linux (or in CI),
`bash tools/boot-test.sh scratch/output/scratch-x86_64.iso bios` and
`… uefi` boot it in QEMU and pass once a login prompt appears on the serial
console.

If your change touches anything under *boot* — the initramfs, kernel module
selection, boot loaders, the ISO/FAT/SquashFS writers, or the accounts and
services code — please boot-test it under **both BIOS and UEFI** and say so
in the pull request.

## Code map

| Module | Job |
|---|---|
| `config.py` | Manifest parsing, defaults, unknown-key warnings |
| `templates.py` | `--init` project templates |
| `repo.py` | pacman sync DBs, dependency resolution, downloads |
| `ingest.py` | Streaming packages and overlays into the VFS, pacman local DB |
| `vfs.py` | In-memory POSIX filesystem (owners, modes, links, xattrs) |
| `mutations.py` | Accounts, `systemctl enable`, networking, deferred hooks |
| `kmod.py` / `initramfs.py` / `cpio.py` | Kernel modules and the live initramfs |
| `squashfs.py` / `fatfs.py` / `iso9660.py` | Image writers |
| `boot.py` | Boot menus and kernel command line |
| `inspect.py` | `--inspect` / `--verify` |
| `builder.py` | Pipeline orchestration (shared by CLI and GUI) |
| `gui.py` | Tk GUI |

## Guidelines

- **Pure Python, no new runtime dependencies** unless there is no other way.
  Every dependency is one more thing that can fail to install on someone's
  Windows machine.
- **Errors should tell the user what to do**, not just what went wrong.
- **Add a test** for bug fixes and new manifest options. Small synthetic
  packages (see `make_pkg` in the tests) are usually enough.
- Keep manifests and generated files **ASCII/UTF-8 with LF line endings**.
- Document new manifest options in `example.toml` and, if users will need
  them, in the README.

## Reporting bugs

Please include the manifest (with passwords removed), the output of
`torito distro.toml -v`, and for boot problems the hypervisor or PC model,
BIOS or UEFI, and a photo or serial log of where it stops. Booting with
`torito.debug` (press Tab or e in the boot menu) makes the initramfs log
every step.
