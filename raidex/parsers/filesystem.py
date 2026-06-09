"""Filesystem signature detection from raw image data."""

from __future__ import annotations

import logging
import os
import struct

logger = logging.getLogger(__name__)


def detect_fs_signature(data: bytes) -> str | None:
    """Check raw data for known filesystem signatures."""
    if len(data) > 7 and data[3:7] == b"NTFS":
        bps = struct.unpack_from("<H", data, 11)[0] if len(data) > 12 else 0
        if bps == 512:
            return "NTFS"
    if len(data) > 1082:
        if struct.unpack_from("<H", data, 1080)[0] == 0xEF53:
            return "ext"
    if len(data) > 90 and b"FAT32" in data[82:90]:
        return "FAT32"
    if len(data) > 62 and b"FAT" in data[54:62]:
        return "FAT16"
    return None


def detect_filesystem(raw_path: str) -> str | None:
    """Detect filesystem type at the start of a raw image."""
    try:
        with open(raw_path, "rb") as f:
            header = f.read(4096)
        return detect_fs_signature(header)
    except OSError:
        return None
