"""Handler for Linux md RAID groups."""

from __future__ import annotations

import logging
import os

from raidex.extraction import extract_files_from_image
from raidex.parsers.filesystem import detect_filesystem
from raidex.reconstruction.raid5 import reconstruct_raid5_left_symmetric
from raidex.types import ClassifiedDisk
from raidex.util import ensure_dir

logger = logging.getLogger(__name__)


def handle_md_group(
    uuid_str: str,
    disks: list[ClassifiedDisk],
    output_dir: str,
    keep_raw: bool,
) -> None:
    """Handle a group of Linux md RAID member disks."""
    d0 = disks[0]
    level = d0["level"]
    layout = d0["layout"]
    chunk_sectors = d0["chunk_sectors"]
    raid_disks = d0["raid_disks"]
    data_offset = d0["data_offset_sectors"]
    data_size = d0["data_size_sectors"]
    partition_base = d0.get("partition_byte_offset", 0)
    data_offset_bytes = partition_base + data_offset * 512

    label = f"md_{uuid_str[:8]}"
    out = os.path.join(output_dir, label)
    ensure_dir(out)

    layout_name = "left-symmetric" if layout == 2 else f"layout-{layout}"
    logger.info("  Array UUID: %s", uuid_str)
    logger.info("  Level: RAID %d, Layout: %d (%s)", level, layout, layout_name)
    logger.info(
        "  Chunk: %d KiB, Expected members: %d",
        chunk_sectors * 512 // 1024,
        raid_disks,
    )
    logger.info(
        "  Data offset: %d sectors (%d MiB)",
        data_offset,
        data_offset * 512 // 1048576,
    )
    logger.info(
        "  Data size/disk: %d sectors (%.1f GiB)",
        data_size,
        data_size * 512 / 1073741824,
    )
    logger.info("  Present: %d disk(s)", len(disks))

    if level != 5:
        logger.warning("  Only RAID 5 supported (got RAID %d)", level)
        return
    if layout != 2:
        logger.warning("  Only left-symmetric layout supported (got %d)", layout)
        return

    ordered_raw: list[str | None] = [None] * raid_disks
    for d in disks:
        role = d["role"]
        if role < raid_disks:
            ordered_raw[role] = d["raw"]
            logger.info("    %s: role %d", d["e01"], role)

    missing_indices = [i for i, p in enumerate(ordered_raw) if p is None]
    missing_idx = None

    if len(missing_indices) > 1:
        logger.warning("  Too many missing disks (%d)", len(missing_indices))
        return
    elif len(missing_indices) == 1:
        missing_idx = missing_indices[0]
        logger.info("    Missing: role %d (will rebuild from parity)", missing_idx)

    raid_img = os.path.join(out, "raid5_reconstructed.raw")
    logger.info("  Reconstructing RAID 5...")
    reconstruct_raid5_left_symmetric(
        disk_files=ordered_raw,
        chunk_bytes=chunk_sectors * 512,
        data_offset_bytes=data_offset_bytes,
        data_size_sectors=data_size,
        output_path=raid_img,
        missing_disk_idx=missing_idx,
    )

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
