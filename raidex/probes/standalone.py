"""Standalone filesystem detection on individual disks."""

from __future__ import annotations

import logging

from raidex.parsers.partition import get_partitions
from raidex.util import fsstat_probe, run

logger = logging.getLogger(__name__)


def _probe_fs_at_offset(raw_path: str, offset: int) -> dict | None:
    """Probe for a valid filesystem at the given sector offset.

    Runs fsstat to check for a superblock, then fls to verify the
    filesystem is actually readable.
    """
    fs_type = fsstat_probe(raw_path, offset)
    if fs_type is None:
        return None
    rc, out, _ = run(["fls", "-i", "raw", "-o", str(offset), raw_path])
    if rc != 0 or not out.strip():
        return None
    return {"fs_offset": offset, "fs_type": fs_type}


def probe_standalone(raw_path: str) -> dict | None:
    """Try to identify a standalone filesystem at common offsets."""
    for offset in (63, 0, 2048):
        result = _probe_fs_at_offset(raw_path, offset)
        if result:
            return result

    parts = get_partitions(raw_path)
    for p in parts:
        result = _probe_fs_at_offset(raw_path, p["start"])
        if result:
            return result

    return None
