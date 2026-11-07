"""
torito.initramfs — Live-Boot Initramfs Generator
================================================
Builds a small, self-contained initramfs (``mkinitcpio``/``dracut``
replacement) that:

1. loads the storage/CD/USB/hypervisor drivers needed to see the medium
   (dependency closure computed by :mod:`torito.kmod`, modules shipped
   decompressed so busybox ``insmod`` can load them),
2. finds the live medium by its ISO9660 volume label,
3. loop-mounts the SquashFS root (optionally copied to RAM first),
4. stacks a tmpfs upper layer with overlayfs, and
5. ``switch_root``\\ s into the real init (systemd).

The userland is a statically linked busybox taken from the package set.
"""

from __future__ import annotations

from typing import Callable, Dict, List, Optional

from .cpio import build_initramfs
from .kmod import KernelInfo, LIVE_MODULES, index_modules, module_raw, resolve_modules
from .vfs import PosixVfs

BUSYBOX_APPLETS = [
    "sh", "ash", "mount", "umount", "mkdir", "rmdir", "sleep", "cat", "echo", "insmod",
    "losetup", "switch_root", "blkid", "findfs", "cp", "ls", "dmesg", "setsid",
    "cttyhack", "grep", "sed", "cut", "tr", "head", "tail", "test", "[", "rm", "mknod",
    "ln", "dd", "basename", "dirname", "mv", "stat", "readlink", "uname", "free", "df",
    "lsmod", "modprobe", "poweroff", "reboot", "vi", "less", "ps", "kill", "chroot",
    "find", "xargs", "wc", "sync", "true", "false", "printf",
]

LIVE_INIT = r"""#!/bin/sh
# Torito live initramfs — find the medium, mount squashfs + overlay, switch_root.
export PATH=/bin
mount -t devtmpfs -o mode=0755,nosuid devtmpfs /dev
mount -t proc -o nosuid,nodev,noexec proc /proc
mount -t sysfs -o nosuid,nodev,noexec sysfs /sys
mount -t tmpfs -o nosuid,nodev,mode=0755 run /run

. /etc/torito.conf

msg()  { echo "<6>torito: $*" > /dev/kmsg 2>/dev/null; }
warn() { echo "<3>torito: $*" > /dev/kmsg 2>/dev/null || echo "torito: $*"; }
rescue() {
    warn "$*"
    echo
    echo "torito: $*"
    echo "torito: dropping to a rescue shell; type 'exit' to retry the boot."
    setsid cttyhack sh || sh
}

INIT=""
BREAK=""
for arg in $(cat /proc/cmdline); do
    case "$arg" in
        torito.label=*)        LABEL="${arg#torito.label=}" ;;
        torito.squashfs=*)     SQUASHFS="${arg#torito.squashfs=}" ;;
        torito.copytoram|torito.copytoram=1|torito.copytoram=y|torito.copytoram=yes) COPYTORAM=1 ;;
        torito.copytoram=0|torito.copytoram=n|torito.copytoram=no) COPYTORAM=0 ;;
        torito.overlay_size=*) OVERLAY_SIZE="${arg#torito.overlay_size=}" ;;
        torito.break)          BREAK=1 ;;
        torito.debug)          set -x ;;
        init=*)                INIT="${arg#init=}" ;;
    esac
done

msg "loading drivers for $(uname -r)"
while read -r m; do
    [ -n "$m" ] && insmod "/lib/modules/$KVER/$m" 2>/dev/null
done < /lib/modules/torito-load.list

label_of() {
    # ISO9660 primary volume descriptor: volume id at byte 32808, 32 chars
    dd if="$1" bs=1 skip=32808 count=32 2>/dev/null | tr -d ' \000'
}

find_medium() {
    d=$(findfs "LABEL=$LABEL" 2>/dev/null)
    if [ -n "$d" ] && [ -b "$d" ]; then echo "$d"; return 0; fi
    for d in /dev/sr* /dev/sd* /dev/vd* /dev/xvd* /dev/nvme*n* /dev/mmcblk* /dev/hd*; do
        [ -b "$d" ] || continue
        if [ "$(label_of "$d")" = "$LABEL" ]; then echo "$d"; return 0; fi
    done
    return 1
}

DEV=""
i=0
while [ $i -lt 150 ]; do
    DEV=$(find_medium) && break
    [ $i -eq 15 ] && echo "torito: waiting for the live medium labelled $LABEL ..."
    sleep 0.2 2>/dev/null || sleep 1
    i=$((i + 1))
done
while [ -z "$DEV" ]; do
    rescue "no device with label '$LABEL' found"
    DEV=$(find_medium)
done
msg "live medium: $DEV"

mkdir -p /run/torito/medium /run/torito/sfs /run/torito/cow /run/torito/ram /new_root
until mount -t iso9660 -o ro "$DEV" /run/torito/medium 2>/dev/null || mount -o ro "$DEV" /run/torito/medium; do
    rescue "cannot mount $DEV"
done

IMG="/run/torito/medium$SQUASHFS"
while [ ! -f "$IMG" ]; do
    rescue "squashfs image $SQUASHFS missing on the medium"
done

if [ "$COPYTORAM" = "1" ]; then
    echo "torito: copying the system image to RAM ..."
    mount -t tmpfs -o mode=0755,size=100% ram /run/torito/ram
    if cp "$IMG" /run/torito/ram/rootfs.sfs; then
        IMG=/run/torito/ram/rootfs.sfs
        umount /run/torito/medium 2>/dev/null
    else
        warn "copytoram failed, running from the medium"
        umount /run/torito/ram
    fi
fi

until mount -t squashfs -o ro,loop "$IMG" /run/torito/sfs; do
    rescue "cannot mount the squashfs image"
done

mount -t tmpfs -o mode=0755,size="$OVERLAY_SIZE" cow /run/torito/cow
mkdir -p /run/torito/cow/upper /run/torito/cow/work
until mount -t overlay -o lowerdir=/run/torito/sfs,upperdir=/run/torito/cow/upper,workdir=/run/torito/cow/work overlay /new_root; do
    rescue "cannot mount the overlay root"
done

[ -n "$BREAK" ] && rescue "break requested (torito.break); root is at /new_root"

if [ -z "$INIT" ]; then
    for c in /sbin/init /usr/lib/systemd/systemd /usr/bin/init /bin/sh; do
        if [ -e "/new_root$c" ] || [ -L "/new_root$c" ]; then INIT=$c; break; fi
    done
fi
msg "switching root, exec $INIT"

mount --move /run /new_root/run
mount --move /sys /new_root/sys
mount --move /proc /new_root/proc
mount --move /dev /new_root/dev
exec switch_root /new_root "$INIT"
"""


def build_live_initramfs(
    rootfs: PosixVfs,
    kernel: KernelInfo,
    busybox: bytes,
    label: str,
    squashfs_path: str,
    overlay_size: str = "75%",
    copytoram: bool = False,
    extra_modules: Optional[List[str]] = None,
    extra_files: Optional[Dict[str, bytes]] = None,
    compression: str = "zstd",
    epoch: Optional[int] = None,
    log: Callable[[str], None] = lambda m: None,
) -> bytes:
    """Return a compressed newc CPIO initramfs for live booting."""
    if not kernel.modules:
        index_modules(rootfs, kernel)
    mods = resolve_modules(rootfs, kernel, list(LIVE_MODULES) + list(extra_modules or []), log=log)

    ivfs = PosixVfs(source_date_epoch=epoch)
    for d in ("/bin", "/dev", "/etc", "/proc", "/sys", "/run", "/tmp", "/new_root", "/lib/modules"):
        ivfs.mkdir(d)
    ivfs.add_symlink("/sbin", "bin")
    ivfs.add_symlink("/usr/bin", "../bin")
    ivfs.add_char_device("/dev/console", 5, 1, mode=0o600)
    ivfs.add_char_device("/dev/null", 1, 3, mode=0o666)
    ivfs.add_char_device("/dev/kmsg", 1, 11, mode=0o644)
    ivfs.add_file("/bin/busybox", busybox, mode=0o755)
    for applet in BUSYBOX_APPLETS:
        ivfs.add_symlink(f"/bin/{applet}", "busybox")
    ivfs.add_file("/init", LIVE_INIT.encode(), mode=0o755)
    conf = (
        f'LABEL="{label}"\n'
        f'SQUASHFS="{squashfs_path}"\n'
        f'OVERLAY_SIZE="{overlay_size}"\n'
        f'COPYTORAM="{1 if copytoram else 0}"\n'
        f'KVER="{kernel.version}"\n'
    )
    ivfs.add_file("/etc/torito.conf", conf.encode())

    load_list: List[str] = []
    total = 0
    for m in mods:
        raw = module_raw(rootfs, m)
        ivfs.add_file(f"/lib/modules/{kernel.version}/{m.rel}", raw, mode=0o644)
        load_list.append(m.rel)
        total += len(raw)
    ivfs.add_file("/lib/modules/torito-load.list", ("\n".join(load_list) + "\n").encode())
    for path, data in (extra_files or {}).items():
        ivfs.add_file(path, data, mode=0o755 if data[:2] == b"#!" or data[:4] == b"\x7fELF" else 0o644)
    log(f"  initramfs: busybox + {len(mods)} modules ({total // 1024} KiB uncompressed)")
    ivfs.fixup_nlinks()
    return build_initramfs(ivfs, compression=compression, level=19)
