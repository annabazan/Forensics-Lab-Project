"""Hardware RAID detection — brute-force for arrays with no on-disk metadata."""

from __future__ import annotations

import itertools
import logging
import os

from raidex.parsers.partition import get_partitions
from raidex.util import COMMON_DATA_OFFSETS, COMMON_STRIPE_SIZES, fsstat_probe

logger = logging.getLogger(__name__)


def detect_hardware_raid_groups(
    classified: list[dict],
) -> list[list[dict]]:
    """Cluster unknown disks by file size into candidate hardware RAID groups."""
    unknowns = [d for d in classified if d["kind"] == "unknown"]
    if not unknowns:
        return []

    size_groups: dict[int, list[dict]] = {}
    for d in unknowns:
        try:
            size = os.path.getsize(d["raw"])
        except OSError:
            continue
        size_groups.setdefault(size, []).append(d)

    return [disks for disks in size_groups.values() if len(disks) >= 2]


def detect_standalone_mirrors(
    groups: dict[tuple, list[dict]],
) -> dict[tuple, list[dict]]:
    """Detect RAID 1 mirrors among standalone-classified disks."""
    standalone_keys = [k for k in groups if k[0] == "standalone"]
    if len(standalone_keys) < 2:
        return groups

    size_buckets: dict[int, list[tuple]] = {}
    for key in standalone_keys:
        d = groups[key][0]
        try:
            size = os.path.getsize(d["raw"])
        except OSError:
            continue
        size_buckets.setdefault(size, []).append(key)

    SAMPLE = 1024 * 1024

    hw_idx = (
        max(
            (int(k[1].split("_")[1]) for k in groups if k[0] == "hardware"),
            default=-1,
        )
        + 1
    )

    for size, keys in size_buckets.items():
        if len(keys) < 2:
            continue

        samples: dict[tuple, bytes] = {}
        for key in keys:
            raw = groups[key][0]["raw"]
            try:
                with open(raw, "rb") as f:
                    head = f.read(SAMPLE)
                    f.seek(max(0, size - SAMPLE))
                    tail = f.read(SAMPLE)
                samples[key] = head + tail
            except OSError:
                continue

        if len(samples) < 2:
            continue

        vals = list(samples.values())
        if all(v == vals[0] for v in vals[1:]):
            mirror_disks: list[dict] = []
            for key in samples:
                mirror_disks.extend(groups.pop(key))
            groups[("hardware", f"group_{hw_idx}")] = mirror_disks
            hw_idx += 1

    return groups


def try_hardware_raid1(disks: list[dict]) -> dict | None:
    """Check if any disk in the group has a standalone filesystem."""
    for d in disks:
        for offset_bytes in COMMON_DATA_OFFSETS:
            offset_sectors = offset_bytes // 512
            fs_type = fsstat_probe(d["raw"], offset_sectors)
            if fs_type is not None:
                return {
                    "level": 1,
                    "disk": d,
                    "fs_offset": offset_sectors,
                    "fs_type": fs_type,
                }

        parts = get_partitions(d["raw"])
        for p in parts:
            fs_type = fsstat_probe(d["raw"], p["start"])
            if fs_type is not None:
                return {
                    "level": 1,
                    "disk": d,
                    "fs_offset": p["start"],
                    "fs_type": fs_type,
                }
    return None


def try_hardware_raid0(disks: list[dict]) -> dict | None:
    """Try all RAID 0 configurations and return first valid one."""
    from raidex.reconstruction.raid0 import test_raid0_order

    raw_paths = [d["raw"] for d in disks]
    n_disks = len(disks)

    for offset_bytes in COMMON_DATA_OFFSETS:
        for chunk_bytes in COMMON_STRIPE_SIZES:
            for perm in itertools.permutations(range(n_disks)):
                ordered = [raw_paths[i] for i in perm]
                if test_raid0_order(ordered, chunk_bytes, offset_bytes, n_disks):
                    return {
                        "level": 0,
                        "ordered": ordered,
                        "chunk_bytes": chunk_bytes,
                        "data_offset_bytes": offset_bytes,
                    }
    return None


def try_hardware_raid5(
    disks: list[dict], *, try_degraded: bool = True
) -> dict | None:
    """Try all RAID 5 configurations and return first valid one."""
    from raidex.reconstruction.raid5 import test_raid5_order

    raw_paths = [d["raw"] for d in disks]
    n_disks = len(disks)

    if n_disks < 3:
        return None

    for offset_bytes in COMMON_DATA_OFFSETS:
        for chunk_bytes in COMMON_STRIPE_SIZES:
            for perm in itertools.permutations(range(n_disks)):
                ordered = [raw_paths[i] for i in perm]
                if test_raid5_order(ordered, chunk_bytes, offset_bytes, n_disks):
                    return {
                        "level": 5,
                        "ordered": ordered,
                        "chunk_bytes": chunk_bytes,
                        "data_offset_bytes": offset_bytes,
                        "n_columns": n_disks,
                        "missing_idx": None,
                    }

    if not try_degraded:
        return None

    for n_cols in range(n_disks + 1, n_disks + 3):
        for offset_bytes in COMMON_DATA_OFFSETS:
            for chunk_bytes in COMMON_STRIPE_SIZES:
                for missing_col in range(n_cols):
                    remaining_cols = [c for c in range(n_cols) if c != missing_col]
                    for perm in itertools.permutations(range(n_disks)):
                        ordered: list[str | None] = [None] * n_cols
                        for i, p_idx in enumerate(perm):
                            ordered[remaining_cols[i]] = raw_paths[p_idx]
                        if test_raid5_order(
                            ordered, chunk_bytes, offset_bytes, n_cols
                        ):
                            return {
                                "level": 5,
                                "ordered": ordered,
                                "chunk_bytes": chunk_bytes,
                                "data_offset_bytes": offset_bytes,
                                "n_columns": n_cols,
                                "missing_idx": missing_col,
                            }
    return None
