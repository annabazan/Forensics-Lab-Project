"""Partition table parsing — mmls with pure-Python GPT fallback."""

from __future__ import annotations

import logging
import re
import struct

from raidex.types import PartitionEntry
from raidex.util import run

logger = logging.getLogger(__name__)

GPT_HEADER_LBA = 1


def get_partitions(raw_path: str) -> list[PartitionEntry]:
    """Parse partition table via mmls, with pure-Python GPT fallback."""
    parts = parse_mmls(raw_path)
    if parts:
        return parts
    return parse_gpt(raw_path)


def parse_mmls(raw_path: str) -> list[PartitionEntry]:
    """Parse partition table using sleuthkit's mmls."""
    rc, out, _ = run(["mmls", "-i", "raw", raw_path])
    if rc != 0:
        return []
    parts: list[PartitionEntry] = []
    for line in out.decode(errors="replace").splitlines():
        line = line.strip()
        if not line or "Unallocated" in line or "Meta" in line:
            continue
        m = re.match(r"\d+:\s+\S+\s+(\d+)\s+(\d+)\s+(\d+)\s+(.*)", line)
        if m:
            parts.append(
                PartitionEntry(
                    start=int(m.group(1)),
                    end=int(m.group(2)),
                    length=int(m.group(3)),
                    desc=m.group(4).strip(),
                )
            )
    return parts


def parse_gpt(raw_path: str) -> list[PartitionEntry]:
    """GPT parser — no external tools needed.

    GPT layout:
      LBA 0  = Protective MBR
      LBA 1  = GPT Header
        +0:  signature "EFI PART" (8 bytes)
        +72: partition entry start LBA (LE64)
        +80: number of partition entries (LE32)
        +84: size of each entry (LE32)
      LBA 2+ = Partition entries (128 bytes each by default)
        +0:  type GUID (16 bytes) -- all zeros = unused
        +32: start LBA (LE64)
        +40: end LBA (LE64)
        +56: name (72 bytes UTF-16LE)
    """
    try:
        with open(raw_path, "rb") as f:
            f.seek(GPT_HEADER_LBA * 512)
            header = f.read(512)

        if header[:8] != b"EFI PART":
            return []

        num_entries = struct.unpack_from("<I", header, 80)[0]
        entry_size = struct.unpack_from("<I", header, 84)[0]
        entries_lba = struct.unpack_from("<Q", header, 72)[0]

        if entry_size == 0 or num_entries > 128:
            return []

        with open(raw_path, "rb") as f:
            f.seek(entries_lba * 512)
            entries_data = f.read(num_entries * entry_size)

        parts: list[PartitionEntry] = []
        for i in range(num_entries):
            entry = entries_data[i * entry_size : (i + 1) * entry_size]
            if len(entry) < 56:
                continue

            type_guid = entry[0:16]
            if type_guid == b"\x00" * 16:
                continue

            start_lba = struct.unpack_from("<Q", entry, 32)[0]
            end_lba = struct.unpack_from("<Q", entry, 40)[0]
            length = end_lba - start_lba + 1

            try:
                name = entry[56:128].decode("utf-16-le").rstrip("\x00")
            except UnicodeDecodeError:
                name = ""

            parts.append(
                PartitionEntry(
                    start=start_lba,
                    end=end_lba,
                    length=length,
                    desc=name,
                )
            )

        return parts

    except (OSError, struct.error):
        return []
