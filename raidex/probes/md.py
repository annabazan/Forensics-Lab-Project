"""Linux md RAID superblock v1.2 detection."""

from __future__ import annotations

import logging
import os
import struct

from raidex.parsers.partition import get_partitions

logger = logging.getLogger(__name__)

MD_SUPERBLOCK_MAGIC = 0xA92B4EFC


def probe_md(raw_path: str) -> dict | None:
    """Check for Linux md superblock v1.x at multiple possible offsets."""
    result = read_md_superblock(raw_path, byte_offset=4096)
    if result:
        return result

    parts = get_partitions(raw_path)
    for p in parts:
        part_byte_offset = p["start"] * 512 + 4096
        result = read_md_superblock(raw_path, byte_offset=part_byte_offset)
        if result:
            result["partition_byte_offset"] = p["start"] * 512
            return result

    try:
        file_size = os.path.getsize(raw_path)
    except OSError:
        return None

    scan_limit = min(32 * 1024 * 1024, file_size)
    step = 512 * 512

    for offset in range(step, scan_limit, step):
        result = read_md_superblock(raw_path, byte_offset=offset + 4096)
        if result:
            result["partition_byte_offset"] = offset
            return result

    return None


def read_md_superblock(raw_path: str, *, byte_offset: int) -> dict | None:
    """Read and parse md superblock v1.2 at given byte offset."""
    try:
        with open(raw_path, "rb") as f:
            f.seek(byte_offset)
            sb = f.read(256)

        if len(sb) < 256:
            return None

        magic = struct.unpack_from("<I", sb, 0)[0]
        if magic != MD_SUPERBLOCK_MAGIC:
            return None

        set_uuid = sb[16:32]
        level = struct.unpack_from("<i", sb, 72)[0]
        layout = struct.unpack_from("<I", sb, 76)[0]
        chunk_sectors = struct.unpack_from("<I", sb, 88)[0]
        raid_disks = struct.unpack_from("<I", sb, 92)[0]
        data_offset = struct.unpack_from("<Q", sb, 128)[0]
        data_size = struct.unpack_from("<Q", sb, 136)[0]
        dev_number = struct.unpack_from("<I", sb, 160)[0]
        max_dev = struct.unpack_from("<I", sb, 220)[0]

        with open(raw_path, "rb") as f:
            f.seek(byte_offset + 256)
            roles_raw = f.read(max_dev * 2)
        roles = [
            struct.unpack_from("<H", roles_raw, i * 2)[0] for i in range(max_dev)
        ]
        role = roles[dev_number] if dev_number < len(roles) else 0xFFFF

        uuid_hex = set_uuid.hex()
        uuid_str = (
            f"{uuid_hex[:8]}-{uuid_hex[8:12]}-{uuid_hex[12:16]}"
            f"-{uuid_hex[16:20]}-{uuid_hex[20:]}"
        )

        return {
            "uuid": uuid_str,
            "level": level,
            "layout": layout,
            "chunk_sectors": chunk_sectors,
            "raid_disks": raid_disks,
            "data_offset_sectors": data_offset,
            "data_size_sectors": data_size,
            "dev_number": dev_number,
            "role": role,
            "sb_byte_offset": byte_offset,
        }
    except (OSError, struct.error):
        return None
