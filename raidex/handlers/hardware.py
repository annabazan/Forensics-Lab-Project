"""Handler for hardware RAID groups (no on-disk metadata)."""

from __future__ import annotations

import logging
import os

from raidex.extraction import extract_files_from_image
from raidex.parsers.filesystem import detect_filesystem
from raidex.parsers.partition import get_partitions
from raidex.probes.hardware import try_hardware_raid0, try_hardware_raid1, try_hardware_raid5
from raidex.reconstruction.raid0 import reconstruct_raid0
from raidex.reconstruction.raid5 import reconstruct_raid5_left_symmetric
from raidex.types import HwOverrides
from raidex.util import (
    COMMON_DATA_OFFSETS,
    COMMON_STRIPE_SIZES,
    ensure_dir,
    fsstat_probe,
    run,
)

logger = logging.getLogger(__name__)


def _apply_hw_overrides(
    disks: list[dict], overrides: HwOverrides
) -> dict | None:
    """Apply user-specified hardware RAID parameters."""
    level = overrides["level"]
    chunk_bytes = (overrides.get("stripe") or 64) * 1024
    data_offset_bytes = (overrides.get("offset") or 0) * 512

    if overrides.get("order"):
        name_to_disk = {d["e01"]: d for d in disks}
        ordered = []
        for name in overrides["order"]:
            key = name if name in name_to_disk else name + ".E01"
            if key not in name_to_disk:
                logger.warning("  Unknown disk in --hw-order: %s", name)
                return None
            ordered.append(name_to_disk[key]["raw"])
    else:
        ordered = [d["raw"] for d in disks]

    return {
        "level": level,
        "ordered": ordered,
        "chunk_bytes": chunk_bytes,
        "data_offset_bytes": data_offset_bytes,
        "n_columns": len(ordered),
        "missing_idx": None,
    }


def _report_hw_failure(disks: list[dict]) -> None:
    """Report failure to detect hardware RAID configuration."""
    logger.warning("  Could not detect hardware RAID configuration")
    logger.warning("  Tried:")
    levels = "0, 5" if len(disks) >= 3 else "1, 0"
    logger.warning("    RAID levels: %s", levels)
    logger.warning(
        "    Stripe sizes: %s",
        ", ".join(str(s // 1024) + "K" for s in COMMON_STRIPE_SIZES),
    )
    logger.warning(
        "    Data offsets (sectors): %s",
        ", ".join(str(o // 512) for o in COMMON_DATA_OFFSETS),
    )
    n_perm = 1
    for i in range(1, len(disks) + 1):
        n_perm *= i
    total = n_perm * len(COMMON_STRIPE_SIZES) * len(COMMON_DATA_OFFSETS)
    logger.warning(
        "    Permutations per config: %d (%d total trials per RAID level)",
        n_perm,
        total,
    )
    logger.info("  Retry with manual parameters:")
    logger.info("    --hw-raid-level {0,1,5}")
    logger.info("    --hw-stripe SIZE_KIB")
    logger.info("    --hw-order disk_A.E01,disk_B.E01,...")
    logger.info("    --hw-offset SECTORS")


def handle_hardware_raid_group(
    disks: list[dict],
    output_dir: str,
    keep_raw: bool,
    overrides: HwOverrides | None = None,
) -> None:
    """Handle a group of unknown disks as hardware RAID."""
    group_id = "_".join(sorted(d["e01"].replace(".E01", "") for d in disks))
    label = f"hw_{group_id}"
    out = os.path.join(output_dir, label)
    ensure_dir(out)

    disk_size = os.path.getsize(disks[0]["raw"])
    names = ", ".join(d["e01"] for d in disks)
    logger.info(
        "  Hardware RAID candidate: %d disks, %.2f GiB each",
        len(disks),
        disk_size / 1073741824,
    )
    logger.info("  Members: %s", names)

    if len(disks) >= 5:
        logger.warning(
            "  Warning: %d disks = many permutations. Consider --hw-* flags.",
            len(disks),
        )

    if overrides and overrides.get("level") is not None:
        result = _apply_hw_overrides(disks, overrides)
    else:
        result = None

        if len(disks) == 2:
            logger.info("  Trying RAID 1 (mirror)...")
            r1 = try_hardware_raid1(disks)
            if r1:
                logger.info(
                    "  [+] RAID 1 detected: %s has %s at sector %d",
                    r1["disk"]["e01"],
                    r1["fs_type"],
                    r1["fs_offset"],
                )
                logger.info("  Extracting files...")
                extract_files_from_image(
                    r1["disk"]["raw"], r1["fs_offset"], os.path.join(out, "files")
                )
                return

        if len(disks) >= 3:
            logger.info("  Trying RAID 5 (stripe + parity)...")
            result = try_hardware_raid5(disks, try_degraded=False)

        if not result:
            logger.info("  Trying RAID 0 (stripe)...")
            result = try_hardware_raid0(disks)

        if not result and len(disks) >= 3:
            logger.info("  Trying degraded RAID 5...")
            result = try_hardware_raid5(disks, try_degraded=True)

    if not result:
        _report_hw_failure(disks)
        return

    level = result["level"]
    ordered = result["ordered"]
    chunk_bytes = result["chunk_bytes"]
    data_offset_bytes = result["data_offset_bytes"]

    if level == 1:
        disk_path = ordered[0]
        fs_offset: int | None = data_offset_bytes // 512
        if not fs_offset:
            for try_bytes in COMMON_DATA_OFFSETS:
                try_sectors = try_bytes // 512
                if fsstat_probe(disk_path, try_sectors) is not None:
                    fs_offset = try_sectors
                    break
            if not fs_offset:
                parts = get_partitions(disk_path)
                for p in parts:
                    if fsstat_probe(disk_path, p["start"]) is not None:
                        fs_offset = p["start"]
                        break
        if fs_offset is not None:
            e01_name = next((d["e01"] for d in disks if d["raw"] == disk_path), "?")
            logger.info("  RAID 1: extracting from %s at sector %d", e01_name, fs_offset)
            extract_files_from_image(disk_path, fs_offset, os.path.join(out, "files"))
        else:
            logger.warning("  No filesystem found on RAID 1 member disk")
        return

    sectors_per_chunk = chunk_bytes // 512
    avail_sectors = (disk_size - data_offset_bytes) // 512
    data_size_sectors = (avail_sectors // sectors_per_chunk) * sectors_per_chunk

    logger.info("  Detected RAID %d parameters:", level)
    logger.info("    Chunk size: %d KiB", chunk_bytes // 1024)
    logger.info(
        "    Data offset: %d bytes (sector %d)", data_offset_bytes, data_offset_bytes // 512
    )
    logger.info(
        "    Data size/disk: %d sectors (%.2f GiB)",
        data_size_sectors,
        data_size_sectors * 512 / 1073741824,
    )

    for i, path in enumerate(ordered):
        if path:
            e01_name = next((d["e01"] for d in disks if d["raw"] == path), "?")
            logger.info("    Column %d: %s", i, e01_name)
        else:
            logger.info("    Column %d: MISSING (rebuild from parity)", i)

    if level == 0:
        raid_img = os.path.join(out, "raid0_reconstructed.raw")
        logger.info("  Reconstructing RAID 0...")
        reconstruct_raid0(
            disk_files=ordered,
            chunk_bytes=chunk_bytes,
            data_offset_bytes=data_offset_bytes,
            data_size_sectors=data_size_sectors,
            output_path=raid_img,
        )
    elif level == 5:
        raid_img = os.path.join(out, "raid5_reconstructed.raw")
        missing_idx = result.get("missing_idx")
        logger.info("  Reconstructing RAID 5...")
        reconstruct_raid5_left_symmetric(
            disk_files=ordered,
            chunk_bytes=chunk_bytes,
            data_offset_bytes=data_offset_bytes,
            data_size_sectors=data_size_sectors,
            output_path=raid_img,
            missing_disk_idx=missing_idx,
        )
    else:
        return

    fs_type = detect_filesystem(raid_img)
    if fs_type:
        logger.info("  [+] Detected %s filesystem", fs_type)
    else:
        logger.warning("  No recognized filesystem signature")

    logger.info("  Extracting files...")
    extract_files_from_image(raid_img, 0, os.path.join(out, "files"))

    if not keep_raw and os.path.exists(raid_img):
        os.remove(raid_img)
        logger.info("  Removed intermediate image")
