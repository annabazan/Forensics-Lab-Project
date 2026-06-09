"""Shared helpers and constants."""

from __future__ import annotations

import logging
import os
import subprocess

logger = logging.getLogger(__name__)

COMMON_STRIPE_SIZES = [
    64 * 1024,
    128 * 1024,
    256 * 1024,
    512 * 1024,
    32 * 1024,
    16 * 1024,
]

COMMON_DATA_OFFSETS = [
    0,
    63 * 512,
    2048 * 512,
    4096 * 512,
]


def run(cmd: list[str], **kwargs: object) -> tuple[int, bytes, bytes]:
    """Run a command, return (returncode, stdout, stderr)."""
    logger.debug("Running: %s", cmd)
    r = subprocess.run(cmd, capture_output=True, **kwargs)
    return r.returncode, r.stdout, r.stderr


def ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def fsstat_probe(raw_path: str, offset_sectors: int) -> str | None:
    """Run fsstat at given sector offset and return filesystem type, or None."""
    rc, out, _ = run(["fsstat", "-i", "raw", "-o", str(offset_sectors), raw_path])
    if rc != 0:
        return None
    for line in out.decode(errors="replace").splitlines():
        if "File System Type" in line:
            return line.split(":", 1)[1].strip()
    return None
