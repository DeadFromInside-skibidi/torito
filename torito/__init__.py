"""
Torito — Rootless Linux ISO Compiler
======================================
A pure-userspace, Windows-native Linux ISO compiler that synthesises
bootable hybrid BIOS/UEFI ``.iso`` images without WSL2, Docker,
hypervisors, ``chroot``, or loopback mounts.
"""

__version__ = "1.0.0"
__author__ = "DeadFromInside"

from .iso9660 import Iso9660Builder, build_hybrid_iso, build_hybrid_iso_from_vfs

__all__ = [
    "Iso9660Builder",
    "build_hybrid_iso",
    "build_hybrid_iso_from_vfs",
]

