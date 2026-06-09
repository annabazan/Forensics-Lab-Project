"""Windows LDM (Logical Disk Manager) detection and VMDB/VBLK parsing."""

from __future__ import annotations

import logging
import os
import re
import struct

logger = logging.getLogger(__name__)

LDM_PRIVHEAD_SECTOR = 6
LDM_GROUP_GUID_OFFSET = 0xB0
LDM_PER_DISK_GUID_OFFSET = 0x30

_GUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I
)


def probe_ldm(raw_path: str) -> dict | None:
    """Check for Windows LDM PRIVHEAD at sector 6."""
    try:
        with open(raw_path, "rb") as f:
            f.seek(LDM_PRIVHEAD_SECTOR * 512)
            hdr = f.read(512)

        if hdr[:8] != b"PRIVHEAD":
            return None

        group_guid = (
            hdr[LDM_GROUP_GUID_OFFSET:0xF0].split(b"\x00")[0]
            .decode("ascii", errors="replace")
        )
        per_disk_guid = (
            hdr[LDM_PER_DISK_GUID_OFFSET:0x70].split(b"\x00")[0]
            .decode("ascii", errors="replace")
        )

        if not _GUID_RE.match(group_guid):
            return None

        return {
            "disk_group_guid": group_guid.lower(),
            "per_disk_guid": per_disk_guid.lower() if _GUID_RE.match(per_disk_guid) else None,
        }
    except OSError:
        return None


def _read_var(buf: bytes, pos: int) -> tuple[bytes, int]:
    """Read a length-prefixed field from VBLK body."""
    if pos >= len(buf):
        return b"", pos
    ln = buf[pos]
    end = pos + 1 + ln
    return buf[pos + 1 : end], end


def _read_var_num(buf: bytes, pos: int) -> tuple[int, int]:
    """Read length-prefixed big-endian integer."""
    data, pos = _read_var(buf, pos)
    return int.from_bytes(data, "big") if data else 0, pos


def _read_var_str(buf: bytes, pos: int) -> tuple[str, int]:
    """Read length-prefixed ASCII string."""
    data, pos = _read_var(buf, pos)
    return data.decode("ascii", errors="replace").rstrip("\x00"), pos


def parse_ldm_vmdb(raw_path: str) -> dict | None:
    """Parse LDM VMDB/VBLK database from end of disk.

    Returns dict with 'volumes', 'components', 'partitions', 'disks' lists,
    or None if VMDB not found.
    """
    try:
        disk_size = os.path.getsize(raw_path)
        region_size = min(disk_size, 2 * 1024 * 1024)

        with open(raw_path, "rb") as f:
            f.seek(disk_size - region_size)
            data = f.read(region_size)

        vmdb_off = data.find(b"VMDB")
        if vmdb_off < 0:
            return None

        vblk_size = struct.unpack_from(">I", data, vmdb_off + 8)[0]
        if vblk_size == 0 or vblk_size > 4096:
            vblk_size = 128

        records: dict[str, list] = {
            "volumes": [],
            "components": [],
            "partitions": [],
            "disks": [],
        }

        pos = vmdb_off
        while pos + vblk_size <= len(data):
            if data[pos : pos + 4] == b"VBLK":
                _parse_vblk(data, pos, vblk_size, records)
            pos += vblk_size

        return records if any(records.values()) else None
    except OSError:
        return None


def _parse_vblk(
    data: bytes, offset: int, vblk_size: int, records: dict[str, list]
) -> None:
    """Parse a single VBLK record.

    VBLK type codes (from LDM on-disk format):
      0x32 = Component (CMP3)
      0x33 = Partition (PRT3)
      0x34 = Disk (DISK3/4)
      0x35 = Disk Group (DGRP3)
      0x51 = Volume (VOL5)
    """
    rec = data[offset : offset + vblk_size]
    if len(rec) < 0x18:
        return

    rec_type = rec[0x13]
    body = rec[0x18:]

    try:
        if rec_type == 0x51:
            _parse_vblk_volume(body, records)
        elif rec_type == 0x34:
            _parse_vblk_disk(body, records)
        elif rec_type == 0x33:
            _parse_vblk_partition(body, records)
    except (IndexError, struct.error, ValueError):
        pass


def _parse_vblk_volume(body: bytes, records: dict[str, list]) -> None:
    pos = 0
    objid, pos = _read_var_num(body, pos)
    name, pos = _read_var_str(body, pos)
    vol_type, pos = _read_var_str(body, pos)
    records["volumes"].append({"id": objid, "name": name, "type": vol_type})


def _parse_vblk_disk(body: bytes, records: dict[str, list]) -> None:
    """Parse Disk VBLK (type 0x34)."""
    pos = 0
    objid, pos = _read_var_num(body, pos)
    name, pos = _read_var_str(body, pos)
    guid, pos = _read_var_str(body, pos)
    records["disks"].append({
        "id": objid,
        "name": name,
        "guid": guid.lower() if guid else "",
    })


def _parse_vblk_partition(body: bytes, records: dict[str, list]) -> None:
    """Parse Partition VBLK (type 0x33)."""
    pos = 0
    objid, pos = _read_var_num(body, pos)
    name, pos = _read_var_str(body, pos)

    remaining = body[pos:]

    end = len(remaining)
    while end > 0 and remaining[end - 1] == 0:
        end -= 1

    part_info: dict = {"id": objid, "name": name}
    try:
        for scan_pos in range(max(0, end - 20), end - 2):
            ln = remaining[scan_pos]
            if ln < 1 or ln > 4:
                continue
            if scan_pos + 1 + ln > end:
                continue
            val1 = int.from_bytes(remaining[scan_pos + 1 : scan_pos + 1 + ln], "big")
            next_pos = scan_pos + 1 + ln
            if next_pos >= end:
                continue
            ln2 = remaining[next_pos]
            if ln2 < 1 or ln2 > 4 or next_pos + 1 + ln2 > end:
                continue
            val2 = int.from_bytes(
                remaining[next_pos + 1 : next_pos + 1 + ln2], "big"
            )
            if 1000 < val1 < 10000 and 1000 < val2 < 10000:
                part_info["component_id"] = val1
                part_info["disk_id"] = val2
                for size_pos in range(max(0, scan_pos - 10), scan_pos):
                    sln = remaining[size_pos]
                    if sln < 1 or sln > 5:
                        continue
                    if size_pos + 1 + sln == scan_pos:
                        size_val = int.from_bytes(
                            remaining[size_pos + 1 : size_pos + 1 + sln], "big"
                        )
                        part_info["size_sectors"] = size_val
                        break
                if len(remaining) > 20:
                    vol_offset = struct.unpack_from(">Q", remaining, 12)[0]
                    part_info["volume_offset_sectors"] = vol_offset
                break
    except (IndexError, struct.error):
        pass

    records["partitions"].append(part_info)
