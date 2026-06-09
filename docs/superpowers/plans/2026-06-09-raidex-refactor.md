# Raidex Refactor Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Refactor the monolithic `detect_and_extract_raids.py` (1770 lines) into a properly structured `raidex` Python package with unit tests.

**Architecture:** Domain-driven module split — probes/, handlers/, reconstruction/, parsers/ sub-packages, plus extraction, mounting, pipeline, and CLI modules. Each module is 100-300 lines. All `print()` replaced with `logging`. TypedDicts for classified disk data. `ExitStack` for resource safety.

**Tech Stack:** Python 3.14+, stdlib only (no runtime deps), pytest for testing, uv for package management.

**Design spec:** `docs/superpowers/specs/2026-06-09-raidex-refactor-design.md`

---

## File Map

### New files to create

```
raidex/
  __init__.py
  __main__.py
  cli.py
  pipeline.py
  mounting.py
  extraction.py
  util.py
  types.py
  probes/
    __init__.py
    md.py
    ldm.py
    standalone.py
    hardware.py
  handlers/
    __init__.py
    md.py
    ldm.py
    standalone.py
    hardware.py
  reconstruction/
    __init__.py
    raid0.py
    raid1.py
    raid5.py
  parsers/
    __init__.py
    partition.py
    filesystem.py
tests/
  conftest.py
  test_parsers/
    test_partition.py
    test_filesystem.py
  test_probes/
    test_md.py
    test_ldm.py
  test_reconstruction/
    test_raid0.py
    test_raid5.py
  test_grouping.py
```

### Files to modify

- `pyproject.toml` — change package name, entry point, add pytest dev dep, update build config

### Files to delete

- `detect_and_extract_raids.py` — replaced by raidex/ package

---

## Task 1: Scaffold Package and Foundation

**Files:**
- Create: `raidex/__init__.py`, `raidex/__main__.py`, `raidex/types.py`, `raidex/util.py`
- Modify: `pyproject.toml`

- [ ] **Step 1: Create package directory structure**

```bash
mkdir -p raidex/probes raidex/handlers raidex/reconstruction raidex/parsers
```

- [ ] **Step 2: Create `raidex/__init__.py`**

```python
"""Raidex — auto-detecting RAID forensic data extraction from E01 images."""

__version__ = "0.1.0"
```

- [ ] **Step 3: Create `raidex/__main__.py`**

```python
"""Allow `python -m raidex`."""

from raidex.cli import main

main()
```

- [ ] **Step 4: Create `raidex/types.py`**

This defines all TypedDicts used across modules. The current code uses plain dicts with a `'class'` key — rename to `'kind'` since `class` is a reserved keyword.

```python
"""Typed structures for classified disk data."""

from __future__ import annotations

from typing import TypedDict


class DiskBase(TypedDict):
    kind: str
    e01: str
    raw: str


class MdDisk(DiskBase):
    uuid: str
    level: int
    layout: int
    chunk_sectors: int
    raid_disks: int
    data_offset_sectors: int
    data_size_sectors: int
    dev_number: int
    role: int
    sb_byte_offset: int
    partition_byte_offset: int


class LdmDisk(DiskBase):
    disk_group_guid: str
    per_disk_guid: str | None


class StandaloneDisk(DiskBase):
    fs_offset: int
    fs_type: str | None


class UnknownDisk(DiskBase):
    pass


type ClassifiedDisk = MdDisk | LdmDisk | StandaloneDisk | UnknownDisk


class HwOverrides(TypedDict, total=False):
    level: int | None
    stripe: int | None
    offset: int | None
    order: list[str] | None


class PartitionEntry(TypedDict):
    start: int
    end: int
    length: int
    desc: str
```

- [ ] **Step 5: Create `raidex/util.py`**

Move `run()`, `ensure_dir()`, and the shared constants from the monolith. Add the new `fsstat_probe()` dedup helper.

```python
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
```

- [ ] **Step 6: Update `pyproject.toml`**

```toml
[project]
name = "raidex"
version = "0.1.0"
description = "Auto-detecting RAID forensic data extraction from E01 images"
readme = "README.md"
requires-python = ">=3.14"
dependencies = []

[project.scripts]
detect-raids = "raidex.cli:main"

[tool.uv]
package = true
dev-dependencies = ["pytest>=8"]

[tool.hatch.build.targets.wheel]
packages = ["raidex"]

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[tool.pytest.ini_options]
testpaths = ["tests"]
```

- [ ] **Step 7: Create empty `__init__.py` files for sub-packages**

Create these files with one-line module docstrings:

`raidex/probes/__init__.py`:
```python
"""Disk type probes — detect md, LDM, standalone, and hardware RAID."""
```

`raidex/handlers/__init__.py`:
```python
"""Group handlers — process classified disk groups and extract data."""
```

`raidex/reconstruction/__init__.py`:
```python
"""RAID array reconstruction — reassemble data from member disks."""
```

`raidex/parsers/__init__.py`:
```python
"""Low-level parsers for partition tables and filesystem signatures."""
```

- [ ] **Step 8: Commit**

```bash
git add raidex/ pyproject.toml
git commit -m "feat: scaffold raidex package structure"
```

---

## Task 2: Parsers — Partition and Filesystem

**Files:**
- Create: `raidex/parsers/partition.py`, `raidex/parsers/filesystem.py`
- Create: `tests/test_parsers/test_partition.py`, `tests/test_parsers/test_filesystem.py`, `tests/conftest.py`

These are pure functions on bytes — ideal for TDD. No external tool dependencies for the Python-native parsers.

- [ ] **Step 1: Create `tests/conftest.py` and test directories**

```bash
mkdir -p tests/test_parsers tests/test_probes tests/test_reconstruction
```

`tests/conftest.py`:
```python
"""Shared test fixtures."""
```

`tests/test_parsers/__init__.py`, `tests/test_probes/__init__.py`, `tests/test_reconstruction/__init__.py`: empty files.

- [ ] **Step 2: Write failing tests for `detect_fs_signature()`**

`tests/test_parsers/test_filesystem.py`:
```python
"""Tests for filesystem signature detection."""

import struct

from raidex.parsers.filesystem import detect_fs_signature, detect_filesystem


class TestDetectFsSignature:
    def test_ntfs_signature(self):
        data = bytearray(2048)
        data[3:7] = b"NTFS"
        struct.pack_into("<H", data, 11, 512)  # bytes per sector
        assert detect_fs_signature(bytes(data)) == "NTFS"

    def test_ntfs_wrong_bps_returns_none(self):
        data = bytearray(2048)
        data[3:7] = b"NTFS"
        struct.pack_into("<H", data, 11, 1024)
        assert detect_fs_signature(bytes(data)) is None

    def test_ext_signature(self):
        data = bytearray(2048)
        struct.pack_into("<H", data, 1080, 0xEF53)
        assert detect_fs_signature(bytes(data)) == "ext"

    def test_fat32_signature(self):
        data = bytearray(128)
        data[82:87] = b"FAT32"
        assert detect_fs_signature(bytes(data)) == "FAT32"

    def test_fat16_signature(self):
        data = bytearray(128)
        data[54:57] = b"FAT"
        assert detect_fs_signature(bytes(data)) == "FAT16"

    def test_empty_data_returns_none(self):
        assert detect_fs_signature(b"\x00" * 2048) is None

    def test_short_data_returns_none(self):
        assert detect_fs_signature(b"\x00" * 4) is None


class TestDetectFilesystem:
    def test_reads_file_header(self, tmp_path):
        img = tmp_path / "disk.raw"
        data = bytearray(4096)
        struct.pack_into("<H", data, 1080, 0xEF53)
        img.write_bytes(bytes(data))
        assert detect_filesystem(str(img)) == "ext"

    def test_missing_file_returns_none(self, tmp_path):
        assert detect_filesystem(str(tmp_path / "nonexistent")) is None
```

- [ ] **Step 3: Run tests to verify they fail**

```bash
uv run pytest tests/test_parsers/test_filesystem.py -v
```

Expected: FAIL — `ModuleNotFoundError: No module named 'raidex.parsers.filesystem'`

- [ ] **Step 4: Implement `raidex/parsers/filesystem.py`**

Move from `detect_and_extract_raids.py` lines 333-357. Add type hints and logging.

```python
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
```

- [ ] **Step 5: Run tests to verify they pass**

```bash
uv run pytest tests/test_parsers/test_filesystem.py -v
```

Expected: all PASS.

- [ ] **Step 6: Write failing tests for GPT parser**

`tests/test_parsers/test_partition.py`:
```python
"""Tests for partition table parsing."""

import struct

from raidex.parsers.partition import parse_gpt


def _build_gpt_image(partitions: list[tuple[int, int, str]]) -> bytes:
    """Build a minimal GPT image with given partitions.

    Each partition is (start_lba, end_lba, name).
    Returns raw bytes for the entire image.
    """
    sector = 512
    num_entries = max(len(partitions), 4)
    entry_size = 128

    # LBA 0: protective MBR (empty)
    mbr = b"\x00" * sector

    # LBA 1: GPT header
    header = bytearray(sector)
    header[0:8] = b"EFI PART"
    struct.pack_into("<Q", header, 72, 2)  # entries start at LBA 2
    struct.pack_into("<I", header, 80, num_entries)
    struct.pack_into("<I", header, 84, entry_size)

    # LBA 2+: partition entries
    entries = bytearray(num_entries * entry_size)
    for i, (start, end, name) in enumerate(partitions):
        off = i * entry_size
        # type GUID — non-zero means used
        entries[off : off + 16] = b"\x01" * 16
        struct.pack_into("<Q", entries, off + 32, start)
        struct.pack_into("<Q", entries, off + 40, end)
        name_bytes = name.encode("utf-16-le")[:72]
        entries[off + 56 : off + 56 + len(name_bytes)] = name_bytes

    return mbr + bytes(header) + bytes(entries)


class TestParseGpt:
    def test_single_partition(self, tmp_path):
        img = tmp_path / "disk.raw"
        img.write_bytes(_build_gpt_image([(2048, 4095, "Linux")]))
        parts = parse_gpt(str(img))
        assert len(parts) == 1
        assert parts[0]["start"] == 2048
        assert parts[0]["end"] == 4095
        assert parts[0]["length"] == 2048
        assert parts[0]["desc"] == "Linux"

    def test_multiple_partitions(self, tmp_path):
        img = tmp_path / "disk.raw"
        img.write_bytes(
            _build_gpt_image([(2048, 4095, "EFI"), (4096, 8191, "Root")])
        )
        parts = parse_gpt(str(img))
        assert len(parts) == 2
        assert parts[0]["desc"] == "EFI"
        assert parts[1]["desc"] == "Root"

    def test_no_gpt_signature(self, tmp_path):
        img = tmp_path / "disk.raw"
        img.write_bytes(b"\x00" * 2048)
        assert parse_gpt(str(img)) == []

    def test_missing_file(self, tmp_path):
        assert parse_gpt(str(tmp_path / "nope")) == []

    def test_skips_empty_entries(self, tmp_path):
        img_bytes = bytearray(_build_gpt_image([(2048, 4095, "Data")]))
        # Zero out the type GUID of entry 0 to mark it unused
        entry_off = 512 * 2
        img_bytes[entry_off : entry_off + 16] = b"\x00" * 16
        img = tmp_path / "disk.raw"
        img.write_bytes(bytes(img_bytes))
        assert parse_gpt(str(img)) == []
```

- [ ] **Step 7: Run tests to verify they fail**

```bash
uv run pytest tests/test_parsers/test_partition.py -v
```

Expected: FAIL — `ModuleNotFoundError`

- [ ] **Step 8: Implement `raidex/parsers/partition.py`**

Move from `detect_and_extract_raids.py` lines 235-328. Rename `_get_partitions_gpt` to `parse_gpt` and `_get_partitions_mmls` to `parse_mmls` (public within the module). `get_partitions()` stays as the main dispatcher.

```python
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
```

- [ ] **Step 9: Run all parser tests**

```bash
uv run pytest tests/test_parsers/ -v
```

Expected: all PASS.

- [ ] **Step 10: Commit**

```bash
git add raidex/parsers/ tests/test_parsers/ tests/conftest.py tests/test_probes/__init__.py tests/test_reconstruction/__init__.py
git commit -m "feat: add parsers module with partition and filesystem detection"
```

---

## Task 3: Probes — md Superblock

**Files:**
- Create: `raidex/probes/md.py`
- Create: `tests/test_probes/test_md.py`

- [ ] **Step 1: Write failing tests for md superblock parsing**

`tests/test_probes/test_md.py`:
```python
"""Tests for Linux md superblock parsing."""

import struct

from raidex.probes.md import read_md_superblock

MD_MAGIC = 0xA92B4EFC


def _build_md_superblock(
    *,
    level: int = 5,
    layout: int = 2,
    chunk_sectors: int = 1024,
    raid_disks: int = 3,
    data_offset: int = 2048,
    data_size: int = 190464,
    dev_number: int = 0,
    max_dev: int = 3,
    roles: list[int] | None = None,
    uuid_bytes: bytes = b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10",
) -> bytes:
    """Build a minimal md superblock v1.2 (512 bytes) + role map."""
    sb = bytearray(512)
    struct.pack_into("<I", sb, 0, MD_MAGIC)
    sb[16:32] = uuid_bytes
    struct.pack_into("<I", sb, 72, level)
    struct.pack_into("<I", sb, 76, layout)
    struct.pack_into("<I", sb, 88, chunk_sectors)
    struct.pack_into("<I", sb, 92, raid_disks)
    struct.pack_into("<Q", sb, 128, data_offset)
    struct.pack_into("<Q", sb, 136, data_size)
    struct.pack_into("<I", sb, 160, dev_number)
    struct.pack_into("<I", sb, 220, max_dev)

    if roles is None:
        roles = list(range(max_dev))
    roles_raw = b"".join(struct.pack("<H", r) for r in roles)

    # Pad roles to start at offset 256 within the superblock region
    # The caller writes sb at some byte_offset; roles follow at byte_offset+256
    return bytes(sb) + b"\x00" * (256 - len(sb)) + roles_raw


class TestReadMdSuperblock:
    def test_valid_superblock(self, tmp_path):
        img = tmp_path / "disk.raw"
        sb_data = _build_md_superblock(
            level=5, layout=2, chunk_sectors=1024, raid_disks=3,
            data_offset=2048, data_size=190464, dev_number=1,
            max_dev=3, roles=[0, 1, 2],
        )
        # Place superblock at offset 4096 (standard v1.2 location)
        raw = b"\x00" * 4096 + sb_data
        img.write_bytes(raw)

        result = read_md_superblock(str(img), byte_offset=4096)
        assert result is not None
        assert result["level"] == 5
        assert result["layout"] == 2
        assert result["chunk_sectors"] == 1024
        assert result["raid_disks"] == 3
        assert result["data_offset_sectors"] == 2048
        assert result["data_size_sectors"] == 190464
        assert result["dev_number"] == 1
        assert result["role"] == 1
        assert result["sb_byte_offset"] == 4096

    def test_wrong_magic_returns_none(self, tmp_path):
        img = tmp_path / "disk.raw"
        img.write_bytes(b"\x00" * 8192)
        assert read_md_superblock(str(img), byte_offset=4096) is None

    def test_short_file_returns_none(self, tmp_path):
        img = tmp_path / "disk.raw"
        img.write_bytes(b"\x00" * 100)
        assert read_md_superblock(str(img), byte_offset=4096) is None

    def test_missing_file_returns_none(self, tmp_path):
        assert read_md_superblock(str(tmp_path / "nope"), byte_offset=0) is None
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
uv run pytest tests/test_probes/test_md.py -v
```

Expected: FAIL — `ModuleNotFoundError`

- [ ] **Step 3: Implement `raidex/probes/md.py`**

Move from `detect_and_extract_raids.py` lines 361-441. Rename `_read_md_superblock` to `read_md_superblock` (public). Keep `probe_md` as the top-level probe function. Add type hints, logging.

```python
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
    step = 512 * 512  # 256 KiB

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
            sb = f.read(512)

        if len(sb) < 512:
            return None

        magic = struct.unpack_from("<I", sb, 0)[0]
        if magic != MD_SUPERBLOCK_MAGIC:
            return None

        set_uuid = sb[16:32]
        level = struct.unpack_from("<I", sb, 72)[0]
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
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
uv run pytest tests/test_probes/test_md.py -v
```

Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add raidex/probes/md.py tests/test_probes/test_md.py
git commit -m "feat: add md superblock probe with tests"
```

---

## Task 4: Probes — LDM (PRIVHEAD + VMDB/VBLK)

**Files:**
- Create: `raidex/probes/ldm.py`
- Create: `tests/test_probes/test_ldm.py`

- [ ] **Step 1: Write failing tests for LDM PRIVHEAD parsing**

`tests/test_probes/test_ldm.py`:
```python
"""Tests for Windows LDM PRIVHEAD and VMDB/VBLK parsing."""

import struct

from raidex.probes.ldm import probe_ldm, parse_ldm_vmdb

LDM_PRIVHEAD_SECTOR = 6


def _build_privhead(
    group_guid: str = "12345678-1234-1234-1234-123456789abc",
    per_disk_guid: str = "aabbccdd-1111-2222-3333-444455556666",
) -> bytes:
    """Build a minimal disk image with PRIVHEAD at sector 6."""
    data = bytearray(8 * 512)  # 8 sectors minimum
    off = LDM_PRIVHEAD_SECTOR * 512
    data[off : off + 8] = b"PRIVHEAD"

    # Per-disk GUID at 0x30
    per_bytes = per_disk_guid.encode("ascii") + b"\x00"
    data[off + 0x30 : off + 0x30 + len(per_bytes)] = per_bytes

    # Disk group GUID at 0xB0
    grp_bytes = group_guid.encode("ascii") + b"\x00"
    data[off + 0xB0 : off + 0xB0 + len(grp_bytes)] = grp_bytes

    return bytes(data)


class TestProbeLdm:
    def test_valid_privhead(self, tmp_path):
        img = tmp_path / "disk.raw"
        img.write_bytes(_build_privhead())
        result = probe_ldm(str(img))
        assert result is not None
        assert result["disk_group_guid"] == "12345678-1234-1234-1234-123456789abc"
        assert result["per_disk_guid"] == "aabbccdd-1111-2222-3333-444455556666"

    def test_no_privhead_returns_none(self, tmp_path):
        img = tmp_path / "disk.raw"
        img.write_bytes(b"\x00" * 8192)
        assert probe_ldm(str(img)) is None

    def test_invalid_guid_returns_none(self, tmp_path):
        img = tmp_path / "disk.raw"
        data = bytearray(8 * 512)
        off = LDM_PRIVHEAD_SECTOR * 512
        data[off : off + 8] = b"PRIVHEAD"
        data[off + 0xB0 : off + 0xB5] = b"bogus"
        img.write_bytes(bytes(data))
        assert probe_ldm(str(img)) is None

    def test_missing_file_returns_none(self, tmp_path):
        assert probe_ldm(str(tmp_path / "nope")) is None
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
uv run pytest tests/test_probes/test_ldm.py -v
```

Expected: FAIL — `ModuleNotFoundError`

- [ ] **Step 3: Implement `raidex/probes/ldm.py`**

Move from `detect_and_extract_raids.py` lines 452-706. This includes `probe_ldm()`, `parse_ldm_vmdb()`, all `_parse_vblk*` functions, and the `_read_var*` helpers. Add type hints, logging, named constants.

```python
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


# ── VMDB/VBLK Database Parsing ──


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
    """Parse Disk VBLK (type 0x34).

    Body at offset 0x18:
      [vnum: object_id] [vstr: name e.g. "Disk1"]
      [vstr: per-disk GUID e.g. "fe3079a9-24f6-..."]
    """
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
    """Parse Partition VBLK (type 0x33).

    Extract disk_id, component_id and volume offset by scanning for the
    two trailing vnum fields (component_id, disk_id) near the end of the
    record body.
    """
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
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
uv run pytest tests/test_probes/test_ldm.py -v
```

Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add raidex/probes/ldm.py tests/test_probes/test_ldm.py
git commit -m "feat: add LDM probe with PRIVHEAD and VMDB parsing"
```

---

## Task 5: Probes — Standalone and Hardware + Grouping

**Files:**
- Create: `raidex/probes/standalone.py`, `raidex/probes/hardware.py`
- Create: `tests/test_grouping.py`

- [ ] **Step 1: Implement `raidex/probes/standalone.py`**

Move from `detect_and_extract_raids.py` lines 487-527. Use the new `fsstat_probe()` helper from util.

```python
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
```

- [ ] **Step 2: Implement `raidex/probes/hardware.py`**

Move from `detect_and_extract_raids.py` lines 912-1087. This includes `detect_hardware_raid_groups()`, `_detect_standalone_mirrors()`, and `_try_hardware_raid{0,1,5}()`.

```python
"""Hardware RAID detection — brute-force for arrays with no on-disk metadata."""

from __future__ import annotations

import itertools
import logging
import os

from raidex.parsers.partition import get_partitions
from raidex.reconstruction.raid0 import test_raid0_order
from raidex.reconstruction.raid5 import test_raid5_order
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
```

- [ ] **Step 3: Update `raidex/probes/__init__.py` with probe_disk dispatcher**

```python
"""Disk type probes — detect md, LDM, standalone, and hardware RAID."""

from __future__ import annotations

import logging

from raidex.probes.ldm import probe_ldm
from raidex.probes.md import probe_md
from raidex.probes.standalone import probe_standalone

logger = logging.getLogger(__name__)


def probe_disk(raw_path: str, e01_name: str) -> dict:
    """Classify a single disk by probing md -> LDM -> standalone -> unknown."""
    md = probe_md(raw_path)
    if md:
        logger.info(
            "  -> Linux md RAID %d (UUID %s..., role %d)",
            md["level"],
            md["uuid"][:13],
            md["role"],
        )
        return {"kind": "md", "e01": e01_name, "raw": raw_path, **md}

    ldm = probe_ldm(raw_path)
    if ldm:
        logger.info(
            "  -> Windows LDM (group %s...)", ldm["disk_group_guid"][:13]
        )
        return {"kind": "ldm", "e01": e01_name, "raw": raw_path, **ldm}

    standalone = probe_standalone(raw_path)
    if standalone:
        logger.info(
            "  -> Standalone %s at sector %d",
            standalone["fs_type"],
            standalone["fs_offset"],
        )
        return {
            "kind": "standalone",
            "e01": e01_name,
            "raw": raw_path,
            **standalone,
        }

    logger.info("  -> Unknown disk type")
    return {"kind": "unknown", "e01": e01_name, "raw": raw_path}
```

- [ ] **Step 4: Write failing tests for grouping logic**

`tests/test_grouping.py`:
```python
"""Tests for hardware RAID grouping and mirror detection."""

import os

from raidex.probes.hardware import detect_hardware_raid_groups, detect_standalone_mirrors


class TestDetectHardwareRaidGroups:
    def test_groups_unknowns_by_size(self, tmp_path):
        # Create two files of same size
        for name in ("a.raw", "b.raw"):
            p = tmp_path / name
            p.write_bytes(b"\x00" * 1024)

        classified = [
            {"kind": "unknown", "e01": "a.E01", "raw": str(tmp_path / "a.raw")},
            {"kind": "unknown", "e01": "b.E01", "raw": str(tmp_path / "b.raw")},
        ]
        groups = detect_hardware_raid_groups(classified)
        assert len(groups) == 1
        assert len(groups[0]) == 2

    def test_different_sizes_not_grouped(self, tmp_path):
        (tmp_path / "a.raw").write_bytes(b"\x00" * 1024)
        (tmp_path / "b.raw").write_bytes(b"\x00" * 2048)

        classified = [
            {"kind": "unknown", "e01": "a.E01", "raw": str(tmp_path / "a.raw")},
            {"kind": "unknown", "e01": "b.E01", "raw": str(tmp_path / "b.raw")},
        ]
        groups = detect_hardware_raid_groups(classified)
        assert len(groups) == 0

    def test_ignores_non_unknown(self, tmp_path):
        (tmp_path / "a.raw").write_bytes(b"\x00" * 1024)
        (tmp_path / "b.raw").write_bytes(b"\x00" * 1024)

        classified = [
            {"kind": "md", "e01": "a.E01", "raw": str(tmp_path / "a.raw")},
            {"kind": "standalone", "e01": "b.E01", "raw": str(tmp_path / "b.raw")},
        ]
        groups = detect_hardware_raid_groups(classified)
        assert len(groups) == 0

    def test_single_unknown_not_grouped(self, tmp_path):
        (tmp_path / "a.raw").write_bytes(b"\x00" * 1024)
        classified = [
            {"kind": "unknown", "e01": "a.E01", "raw": str(tmp_path / "a.raw")},
        ]
        groups = detect_hardware_raid_groups(classified)
        assert len(groups) == 0


class TestDetectStandaloneMirrors:
    def test_identical_standalones_become_hardware_group(self, tmp_path):
        content = b"\xab" * 2048
        for name in ("a.raw", "b.raw"):
            (tmp_path / name).write_bytes(content)

        groups = {
            ("standalone", "a.E01"): [
                {"kind": "standalone", "e01": "a.E01", "raw": str(tmp_path / "a.raw")}
            ],
            ("standalone", "b.E01"): [
                {"kind": "standalone", "e01": "b.E01", "raw": str(tmp_path / "b.raw")}
            ],
        }
        result = detect_standalone_mirrors(groups)
        hw_keys = [k for k in result if k[0] == "hardware"]
        assert len(hw_keys) == 1
        assert len(result[hw_keys[0]]) == 2

    def test_different_content_stays_standalone(self, tmp_path):
        (tmp_path / "a.raw").write_bytes(b"\xab" * 2048)
        (tmp_path / "b.raw").write_bytes(b"\xcd" * 2048)

        groups = {
            ("standalone", "a.E01"): [
                {"kind": "standalone", "e01": "a.E01", "raw": str(tmp_path / "a.raw")}
            ],
            ("standalone", "b.E01"): [
                {"kind": "standalone", "e01": "b.E01", "raw": str(tmp_path / "b.raw")}
            ],
        }
        result = detect_standalone_mirrors(groups)
        assert ("standalone", "a.E01") in result
        assert ("standalone", "b.E01") in result

    def test_single_standalone_unchanged(self, tmp_path):
        (tmp_path / "a.raw").write_bytes(b"\x00" * 1024)
        groups = {
            ("standalone", "a.E01"): [
                {"kind": "standalone", "e01": "a.E01", "raw": str(tmp_path / "a.raw")}
            ],
        }
        result = detect_standalone_mirrors(groups)
        assert result == groups
```

- [ ] **Step 5: Run tests to verify they fail**

```bash
uv run pytest tests/test_grouping.py -v
```

Expected: FAIL — `ModuleNotFoundError`

- [ ] **Step 6: Run tests to verify they pass**

```bash
uv run pytest tests/test_grouping.py -v
```

Expected: all PASS (the code was created in steps 1-2).

- [ ] **Step 7: Commit**

```bash
git add raidex/probes/ tests/test_grouping.py
git commit -m "feat: add standalone, hardware probes and grouping logic"
```

---

## Task 6: Reconstruction — RAID 0 and RAID 5

**Files:**
- Create: `raidex/reconstruction/raid0.py`, `raidex/reconstruction/raid5.py`, `raidex/reconstruction/raid1.py`
- Create: `tests/test_reconstruction/test_raid0.py`, `tests/test_reconstruction/test_raid5.py`

- [ ] **Step 1: Write failing tests for RAID 0 reconstruction**

`tests/test_reconstruction/test_raid0.py`:
```python
"""Tests for RAID 0 reconstruction."""

from raidex.reconstruction.raid0 import reconstruct_raid0


class TestReconstructRaid0:
    def test_three_disk_512b_chunk(self, tmp_path):
        """Three disks, 512-byte chunks, 2 stripes."""
        chunk = 512
        d0 = tmp_path / "d0.raw"
        d1 = tmp_path / "d1.raw"
        d2 = tmp_path / "d2.raw"
        # Stripe 0: d0=AA, d1=BB, d2=CC
        # Stripe 1: d0=DD, d1=EE, d2=FF
        d0.write_bytes(b"\xAA" * chunk + b"\xDD" * chunk)
        d1.write_bytes(b"\xBB" * chunk + b"\xEE" * chunk)
        d2.write_bytes(b"\xCC" * chunk + b"\xFF" * chunk)

        out = tmp_path / "raid.raw"
        reconstruct_raid0(
            disk_files=[str(d0), str(d1), str(d2)],
            chunk_bytes=chunk,
            data_offset_bytes=0,
            data_size_sectors=2,  # 2 sectors per disk (each sector = 1 chunk)
            output_path=str(out),
        )
        result = out.read_bytes()
        expected = (
            b"\xAA" * chunk + b"\xBB" * chunk + b"\xCC" * chunk
            + b"\xDD" * chunk + b"\xEE" * chunk + b"\xFF" * chunk
        )
        assert result == expected

    def test_data_offset_skips_bytes(self, tmp_path):
        """Data offset causes seeks to skip leading bytes on each disk."""
        chunk = 512
        offset = 1024  # skip first 1024 bytes
        d0 = tmp_path / "d0.raw"
        d1 = tmp_path / "d1.raw"
        # Junk at start, real data after offset
        d0.write_bytes(b"\x00" * offset + b"\x11" * chunk)
        d1.write_bytes(b"\x00" * offset + b"\x22" * chunk)

        out = tmp_path / "raid.raw"
        reconstruct_raid0(
            disk_files=[str(d0), str(d1)],
            chunk_bytes=chunk,
            data_offset_bytes=offset,
            data_size_sectors=1,
            output_path=str(out),
        )
        result = out.read_bytes()
        assert result == b"\x11" * chunk + b"\x22" * chunk
```

- [ ] **Step 2: Write failing tests for RAID 5 reconstruction**

`tests/test_reconstruction/test_raid5.py`:
```python
"""Tests for RAID 5 left-symmetric reconstruction."""

from raidex.reconstruction.raid5 import reconstruct_raid5_left_symmetric


def _xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


class TestReconstructRaid5:
    def test_three_disk_basic(self, tmp_path):
        """3-disk RAID 5, left-symmetric, 512-byte chunk, 3 stripes.

        Left-symmetric parity rotation for 3 disks:
          stripe 0: parity on disk 2, data on disk[0], disk[1]
          stripe 1: parity on disk 1, data on disk[2], disk[0]
          stripe 2: parity on disk 0, data on disk[1], disk[2]
        """
        chunk = 512
        n = 3

        # Define data chunks (what we expect in the output)
        # Stripe 0: D0_s0 from disk0, D1_s0 from disk1
        # Stripe 1: D0_s1 from disk2, D1_s1 from disk0
        # Stripe 2: D0_s2 from disk1, D1_s2 from disk2
        d = {}
        d[(0, 0)] = b"\x11" * chunk  # stripe 0, data chunk 0
        d[(0, 1)] = b"\x22" * chunk  # stripe 0, data chunk 1
        d[(1, 0)] = b"\x33" * chunk  # stripe 1, data chunk 0
        d[(1, 1)] = b"\x44" * chunk  # stripe 1, data chunk 1
        d[(2, 0)] = b"\x55" * chunk  # stripe 2, data chunk 0
        d[(2, 1)] = b"\x66" * chunk  # stripe 2, data chunk 1

        # Compute parity for each stripe
        p0 = _xor_bytes(d[(0, 0)], d[(0, 1)])
        p1 = _xor_bytes(d[(1, 0)], d[(1, 1)])
        p2 = _xor_bytes(d[(2, 0)], d[(2, 1)])

        # Build disk contents:
        # stripe 0: pd=2, data order: disk (2+1)%3=0, (2+2)%3=1
        #   disk0 = d(0,0), disk1 = d(0,1), disk2 = p0
        # stripe 1: pd=1, data order: disk (1+1)%3=2, (1+2)%3=0
        #   disk2 = d(1,0), disk0 = d(1,1), disk1 = p1
        # stripe 2: pd=0, data order: disk (0+1)%3=1, (0+2)%3=2
        #   disk1 = d(2,0), disk2 = d(2,1), disk0 = p2
        disk0_data = d[(0, 0)] + d[(1, 1)] + p2
        disk1_data = d[(0, 1)] + p1 + d[(2, 0)]
        disk2_data = p0 + d[(1, 0)] + d[(2, 1)]

        disk0 = tmp_path / "d0.raw"
        disk1 = tmp_path / "d1.raw"
        disk2 = tmp_path / "d2.raw"
        disk0.write_bytes(disk0_data)
        disk1.write_bytes(disk1_data)
        disk2.write_bytes(disk2_data)

        out = tmp_path / "raid.raw"
        reconstruct_raid5_left_symmetric(
            disk_files=[str(disk0), str(disk1), str(disk2)],
            chunk_bytes=chunk,
            data_offset_bytes=0,
            data_size_sectors=3,  # 3 chunks per disk = 3 stripes
            output_path=str(out),
        )

        result = out.read_bytes()
        expected = (
            d[(0, 0)] + d[(0, 1)]
            + d[(1, 0)] + d[(1, 1)]
            + d[(2, 0)] + d[(2, 1)]
        )
        assert result == expected

    def test_missing_disk_rebuilt_from_parity(self, tmp_path):
        """With one disk missing, data is rebuilt via XOR of remaining."""
        chunk = 512

        d00 = b"\x11" * chunk
        d01 = b"\x22" * chunk
        p0 = _xor_bytes(d00, d01)

        # stripe 0: pd=2 -> disk0=d00, disk1=d01, disk2=p0
        # Remove disk1 (missing_disk_idx=1)
        disk0 = tmp_path / "d0.raw"
        disk1_placeholder = None
        disk2 = tmp_path / "d2.raw"
        disk0.write_bytes(d00)
        disk2.write_bytes(p0)

        out = tmp_path / "raid.raw"
        reconstruct_raid5_left_symmetric(
            disk_files=[str(disk0), None, str(disk2)],
            chunk_bytes=chunk,
            data_offset_bytes=0,
            data_size_sectors=1,
            output_path=str(out),
            missing_disk_idx=1,
        )

        result = out.read_bytes()
        # stripe 0 data: d00 + d01 (d01 rebuilt from XOR of d00 and p0)
        assert result == d00 + d01
```

- [ ] **Step 3: Run tests to verify they fail**

```bash
uv run pytest tests/test_reconstruction/ -v
```

Expected: FAIL — `ModuleNotFoundError`

- [ ] **Step 4: Implement `raidex/reconstruction/raid0.py`**

Move from `detect_and_extract_raids.py` lines 194-231 (reconstruct) and 765-804 (test order). Use `ExitStack` for FD management. Add type hints, logging.

```python
"""RAID 0 reconstruction — interleave chunks across disks."""

from __future__ import annotations

import logging
import os
import sys
import tempfile
from contextlib import ExitStack

from raidex.util import run

logger = logging.getLogger(__name__)


def reconstruct_raid0(
    disk_files: list[str],
    chunk_bytes: int,
    data_offset_bytes: int,
    data_size_sectors: int,
    output_path: str,
) -> None:
    """Reconstruct a RAID 0 array by interleaving chunks across disks."""
    n_disks = len(disk_files)
    total_data_bytes = data_size_sectors * 512 * n_disks

    logger.info(
        "    RAID-0: %d disks, %d KiB chunk, data offset %d bytes",
        n_disks,
        chunk_bytes // 1024,
        data_offset_bytes,
    )
    logger.info(
        "    Total RAID volume size: %.2f GiB",
        total_data_bytes / 1024 / 1024 / 1024,
    )

    sectors_per_chunk = chunk_bytes // 512
    num_stripes = data_size_sectors // sectors_per_chunk
    report_interval = max(1, num_stripes // 20)

    with ExitStack() as stack:
        fds = [stack.enter_context(open(path, "rb")) for path in disk_files]

        with open(output_path, "wb") as out:
            bytes_written = 0
            for stripe in range(num_stripes):
                for disk_idx in range(n_disks):
                    disk_off = data_offset_bytes + stripe * chunk_bytes
                    fds[disk_idx].seek(disk_off)
                    chunk = fds[disk_idx].read(chunk_bytes)
                    if len(chunk) < chunk_bytes:
                        chunk += b"\x00" * (chunk_bytes - len(chunk))
                    out.write(chunk)
                    bytes_written += chunk_bytes

                if stripe % report_interval == 0 and stripe > 0:
                    pct = stripe / num_stripes * 100
                    print(
                        f"    Progress: {pct:.0f}%",
                        end="\r",
                        flush=True,
                        file=sys.stderr,
                    )

    logger.info(
        "    Wrote %.1f MiB to %s",
        bytes_written / 1024 / 1024,
        os.path.basename(output_path),
    )


def test_raid0_order(
    ordered_paths: list[str | None],
    chunk_bytes: int,
    data_offset_bytes: int,
    n_disks: int,
) -> bool:
    """Reconstruct first ~16 MiB of RAID 0 and check for valid filesystem."""
    if n_disks * chunk_bytes == 0:
        return False
    test_stripes = max(n_disks * 2, 16 * 1024 * 1024 // (n_disks * chunk_bytes))

    with ExitStack() as stack:
        fds: dict[int, object] = {}
        for i, p in enumerate(ordered_paths):
            if p is not None:
                fds[i] = stack.enter_context(open(p, "rb"))

        tmp_fd, tmp_path = tempfile.mkstemp(suffix=".raw")
        try:
            with os.fdopen(tmp_fd, "wb") as out:
                for stripe in range(test_stripes):
                    for disk_idx in range(n_disks):
                        disk_off = data_offset_bytes + stripe * chunk_bytes
                        if disk_idx not in fds:
                            out.write(b"\x00" * chunk_bytes)
                        else:
                            fds[disk_idx].seek(disk_off)
                            chunk = fds[disk_idx].read(chunk_bytes)
                            if len(chunk) < chunk_bytes:
                                chunk += b"\x00" * (chunk_bytes - len(chunk))
                            out.write(chunk)

            rc, _, _ = run(["fsstat", "-i", "raw", "-o", "0", tmp_path])
            if rc != 0:
                return False
            rc2, fls_out, _ = run(["fls", "-i", "raw", "-o", "0", tmp_path])
            return rc2 == 0 and len(fls_out) > 0
        except OSError:
            return False
        finally:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
```

- [ ] **Step 5: Implement `raidex/reconstruction/raid5.py`**

Move from `detect_and_extract_raids.py` lines 126-192 (reconstruct) and 710-763 (test order). Use `ExitStack`. Add type hints, logging.

```python
"""RAID 5 left-symmetric reconstruction."""

from __future__ import annotations

import logging
import os
import sys
import tempfile
from contextlib import ExitStack

from raidex.util import run

logger = logging.getLogger(__name__)


def reconstruct_raid5_left_symmetric(
    disk_files: list[str | None],
    chunk_bytes: int,
    data_offset_bytes: int,
    data_size_sectors: int,
    output_path: str,
    missing_disk_idx: int | None = None,
) -> None:
    """Reconstruct a RAID 5 array with left-symmetric layout.

    Parity disk for stripe s: (n - 1) - (s % n).
    Data chunks start from disk (parity + 1) % n.
    Missing disk rebuilt via XOR of remaining disks.
    """
    n_disks = len(disk_files)
    data_disks_count = n_disks - 1
    sectors_per_chunk = chunk_bytes // 512
    total_data_bytes = data_size_sectors * 512 * data_disks_count

    logger.info(
        "    RAID-5: %d disks, %d KiB chunk, left-symmetric, data offset %d bytes",
        n_disks,
        chunk_bytes // 1024,
        data_offset_bytes,
    )
    logger.info(
        "    Total RAID volume size: %.2f GiB",
        total_data_bytes / 1024 / 1024 / 1024,
    )
    if missing_disk_idx is not None:
        logger.info(
            "    Recovering missing disk index %d from parity", missing_disk_idx
        )

    num_stripes = data_size_sectors // sectors_per_chunk
    report_interval = max(1, num_stripes // 20)

    with ExitStack() as stack:
        fds: list = []
        for path in disk_files:
            fds.append(
                stack.enter_context(open(path, "rb")) if path is not None else None
            )

        with open(output_path, "wb") as out:
            bytes_written = 0
            for stripe in range(num_stripes):
                pd = (n_disks - 1) - (stripe % n_disks)

                for dd in range(data_disks_count):
                    disk_idx = (pd + 1 + dd) % n_disks
                    disk_off = data_offset_bytes + stripe * chunk_bytes

                    if disk_idx == missing_disk_idx:
                        accum = 0
                        for other_idx in range(n_disks):
                            if other_idx == missing_disk_idx:
                                continue
                            fds[other_idx].seek(disk_off)
                            other = fds[other_idx].read(chunk_bytes)
                            if len(other) < chunk_bytes:
                                other += b"\x00" * (chunk_bytes - len(other))
                            accum ^= int.from_bytes(other, "little")
                        out.write(accum.to_bytes(chunk_bytes, "little"))
                    else:
                        fds[disk_idx].seek(disk_off)
                        chunk = fds[disk_idx].read(chunk_bytes)
                        if len(chunk) < chunk_bytes:
                            chunk += b"\x00" * (chunk_bytes - len(chunk))
                        out.write(chunk)

                    bytes_written += chunk_bytes

                if stripe % report_interval == 0 and stripe > 0:
                    pct = stripe / num_stripes * 100
                    print(
                        f"    Progress: {pct:.0f}%",
                        end="\r",
                        flush=True,
                        file=sys.stderr,
                    )

    logger.info(
        "    Wrote %.1f MiB to %s",
        bytes_written / 1024 / 1024,
        os.path.basename(output_path),
    )


def test_raid5_order(
    ordered_paths: list[str | None],
    chunk_bytes: int,
    data_offset_bytes: int,
    n_disks: int,
) -> bool:
    """Reconstruct first ~16 MiB of RAID and check for valid filesystem."""
    n_data = n_disks - 1
    if n_data * chunk_bytes == 0:
        return False
    test_stripes = max(n_disks * 2, 16 * 1024 * 1024 // (n_data * chunk_bytes))

    with ExitStack() as stack:
        fds: dict[int, object] = {}
        for i, p in enumerate(ordered_paths):
            if p is not None:
                fds[i] = stack.enter_context(open(p, "rb"))

        tmp_fd, tmp_path = tempfile.mkstemp(suffix=".raw")
        try:
            with os.fdopen(tmp_fd, "wb") as out:
                for stripe in range(test_stripes):
                    pd = (n_disks - 1) - (stripe % n_disks)
                    for dd in range(n_data):
                        disk_idx = (pd + 1 + dd) % n_disks
                        disk_off = data_offset_bytes + stripe * chunk_bytes

                        if disk_idx not in fds:
                            accum = 0
                            for i, fd in fds.items():
                                fd.seek(disk_off)
                                d = fd.read(chunk_bytes)
                                if len(d) < chunk_bytes:
                                    d += b"\x00" * (chunk_bytes - len(d))
                                accum ^= int.from_bytes(d, "little")
                            out.write(accum.to_bytes(chunk_bytes, "little"))
                        else:
                            fds[disk_idx].seek(disk_off)
                            chunk = fds[disk_idx].read(chunk_bytes)
                            if len(chunk) < chunk_bytes:
                                chunk += b"\x00" * (chunk_bytes - len(chunk))
                            out.write(chunk)

            rc, _, _ = run(["fsstat", "-i", "raw", "-o", "0", tmp_path])
            if rc != 0:
                return False
            rc2, fls_out, _ = run(["fls", "-i", "raw", "-o", "0", tmp_path])
            return rc2 == 0 and len(fls_out) > 0
        except OSError:
            return False
        finally:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
```

- [ ] **Step 6: Create `raidex/reconstruction/raid1.py`**

Thin module — RAID 1 just reads from one mirror.

```python
"""RAID 1 — read directly from a mirror disk."""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)
```

- [ ] **Step 7: Update `raidex/reconstruction/__init__.py`**

```python
"""RAID array reconstruction — reassemble data from member disks."""
```

- [ ] **Step 8: Run all reconstruction tests**

```bash
uv run pytest tests/test_reconstruction/ -v
```

Expected: all PASS.

- [ ] **Step 9: Commit**

```bash
git add raidex/reconstruction/ tests/test_reconstruction/
git commit -m "feat: add RAID 0 and RAID 5 reconstruction with tests"
```

---

## Task 7: Extraction and Mounting

**Files:**
- Create: `raidex/extraction.py`, `raidex/mounting.py`

No tests for these — extraction calls external tools (fls/icat), mounting requires FUSE/root.

- [ ] **Step 1: Implement `raidex/extraction.py`**

Move from `detect_and_extract_raids.py` lines 71-121. Add type hints, replace print with logging.

```python
"""File extraction from filesystem images using sleuthkit's fls/icat."""

from __future__ import annotations

import logging
import os

from raidex.util import ensure_dir, run

logger = logging.getLogger(__name__)


def extract_files_from_image(
    image_path: str,
    sector_offset: int,
    out_dir: str,
    image_type: str = "raw",
) -> None:
    """Use fls/icat to recursively extract user files from a filesystem image."""
    ensure_dir(out_dir)

    type_flag = ["-i", image_type] if image_type else []
    offset_flag = ["-o", str(sector_offset)] if sector_offset else []

    def _extract_dir(inode: str, rel_path: str) -> None:
        cur_dir = os.path.join(out_dir, rel_path) if rel_path else out_dir
        ensure_dir(cur_dir)
        cmd = ["fls"] + type_flag + offset_flag + [image_path]
        if inode:
            cmd.append(str(inode))
        rc, out, _ = run(cmd)
        if rc != 0:
            return

        for line in out.decode(errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue

            parts = line.split("\t", 1)
            if len(parts) < 2:
                continue
            meta_part = parts[0].strip()
            name = parts[1].strip()

            if name.startswith("$") or name in (".", "..", "(Volume Label Entry)"):
                continue

            tokens = meta_part.split()
            if len(tokens) < 2:
                continue
            type_str = tokens[0]
            inode_str = tokens[1].rstrip(":")

            entry_path = os.path.join(rel_path, name) if rel_path else name

            if type_str.startswith("d/d") or type_str.startswith("d/"):
                _extract_dir(inode_str, entry_path)
            elif type_str.startswith("r/r") or type_str.startswith("r/"):
                dest = os.path.join(out_dir, entry_path)
                cmd2 = ["icat"] + type_flag + offset_flag + [image_path, inode_str]
                rc2, data, _ = run(cmd2)
                if rc2 == 0 and data:
                    with open(dest, "wb") as f:
                        f.write(data)
                    logger.info(
                        "    Extracted: %s (%s bytes)", entry_path, f"{len(data):,}"
                    )

    _extract_dir("", "")
```

- [ ] **Step 2: Implement `raidex/mounting.py`**

Move from `detect_and_extract_raids.py` lines 41-62. Add type hints, logging.

```python
"""EWF image mounting via ewfmount (read-only FUSE)."""

from __future__ import annotations

import logging
import os
import tempfile

from raidex.util import run

logger = logging.getLogger(__name__)


class EwfMount:
    """Context manager to mount an E01 image via ewfmount."""

    def __init__(self, e01_path: str) -> None:
        self.e01_path = e01_path
        self.mountpoint: str | None = None

    def __enter__(self) -> str:
        self.mountpoint = tempfile.mkdtemp(prefix="ewf_")
        rc, _, err = run(["ewfmount", self.e01_path, self.mountpoint])
        if rc != 0:
            os.rmdir(self.mountpoint)
            raise RuntimeError(
                f"ewfmount failed for {self.e01_path}: {err.decode()}"
            )
        return os.path.join(self.mountpoint, "ewf1")

    def __exit__(self, *exc: object) -> None:
        if self.mountpoint:
            run(["fusermount", "-u", self.mountpoint])
            try:
                os.rmdir(self.mountpoint)
            except OSError:
                pass
```

- [ ] **Step 3: Commit**

```bash
git add raidex/extraction.py raidex/mounting.py
git commit -m "feat: add extraction and mounting modules"
```

---

## Task 8: Handlers

**Files:**
- Create: `raidex/handlers/md.py`, `raidex/handlers/ldm.py`, `raidex/handlers/standalone.py`, `raidex/handlers/hardware.py`
- Update: `raidex/handlers/__init__.py`

These are the largest modules — they wire probes, reconstruction, and extraction together. Move from the monolith, replace print with logging, use `fsstat_probe` where applicable.

- [ ] **Step 1: Implement `raidex/handlers/md.py`**

Move from `detect_and_extract_raids.py` lines 1144-1216.

```python
"""Handler for Linux md RAID groups."""

from __future__ import annotations

import logging
import os

from raidex.extraction import extract_files_from_image
from raidex.parsers.filesystem import detect_filesystem
from raidex.reconstruction.raid5 import reconstruct_raid5_left_symmetric
from raidex.util import ensure_dir

logger = logging.getLogger(__name__)


def handle_md_group(
    uuid_str: str,
    disks: list[dict],
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
```

- [ ] **Step 2: Implement `raidex/handlers/ldm.py`**

Move from `detect_and_extract_raids.py` lines 1219-1416. This is the largest handler. Replace inline fsstat calls with `fsstat_probe()`.

```python
"""Handler for Windows LDM Dynamic Disk groups."""

from __future__ import annotations

import itertools
import logging
import os
import re

from raidex.extraction import extract_files_from_image
from raidex.parsers.filesystem import detect_filesystem
from raidex.parsers.partition import get_partitions
from raidex.probes.ldm import parse_ldm_vmdb
from raidex.reconstruction.raid5 import reconstruct_raid5_left_symmetric
from raidex.util import ensure_dir, fsstat_probe, run

logger = logging.getLogger(__name__)


def _resolve_ldm_disk_order(
    vmdb: dict | None, disks: list[dict]
) -> tuple[list[str | None], int] | None:
    """Determine column order from VMDB Disk records + PRIVHEAD per-disk GUIDs."""
    if not vmdb or not vmdb.get("disks"):
        return None

    guid_to_column: dict[str, int] = {}
    for d in vmdb["disks"]:
        name = d.get("name", "")
        guid = d.get("guid", "")
        m = re.match(r"Disk(\d+)", name)
        if m and guid:
            col = int(m.group(1)) - 1
            guid_to_column[guid] = col

    if not guid_to_column:
        return None

    n_columns = max(guid_to_column.values()) + 1
    ordered: list[str | None] = [None] * n_columns
    for d in disks:
        per_guid = d.get("per_disk_guid", "")
        if per_guid in guid_to_column:
            col = guid_to_column[per_guid]
            if col < n_columns:
                ordered[col] = d["raw"]

    return ordered, n_columns


def _detect_stripe_size(
    ordered_paths: list[str | None], data_offset_bytes: int, n_columns: int
) -> int | None:
    """Try common stripe sizes and return the one that produces valid FS."""
    from raidex.reconstruction.raid5 import test_raid5_order
    from raidex.util import COMMON_STRIPE_SIZES

    for chunk_bytes in COMMON_STRIPE_SIZES:
        if test_raid5_order(ordered_paths, chunk_bytes, data_offset_bytes, n_columns):
            return chunk_bytes
    return None


def _detect_disk_order_bruteforce(
    raw_paths: list[str], chunk_bytes: int, data_offset_bytes: int, n_columns: int
) -> list[str] | None:
    """Try all permutations to find correct RAID disk ordering."""
    from raidex.reconstruction.raid5 import test_raid5_order

    n_perm = 1
    for i in range(1, len(raw_paths) + 1):
        n_perm *= i
    logger.debug("    Brute-force: trying %d permutations...", n_perm)
    for perm in itertools.permutations(range(len(raw_paths))):
        ordered = [raw_paths[i] for i in perm]
        if test_raid5_order(ordered, chunk_bytes, data_offset_bytes, n_columns):
            return ordered
    return None


def _detect_degraded_disk_order(
    present_raw_paths: list[str],
    chunk_bytes: int,
    data_offset_bytes: int,
    n_columns: int,
) -> tuple[list[str | None] | None, int | None]:
    """For degraded RAID, determine column positions of present disks."""
    from raidex.reconstruction.raid5 import test_raid5_order

    n_present = len(present_raw_paths)
    if n_columns - n_present != 1:
        logger.warning("    Cannot handle %d missing disks", n_columns - n_present)
        return None, None

    for missing_col in range(n_columns):
        remaining_cols = [i for i in range(n_columns) if i != missing_col]
        for perm in itertools.permutations(range(n_present)):
            ordered: list[str | None] = [None] * n_columns
            for i, p_idx in enumerate(perm):
                ordered[remaining_cols[i]] = present_raw_paths[p_idx]
            if test_raid5_order(ordered, chunk_bytes, data_offset_bytes, n_columns):
                return ordered, missing_col

    logger.warning("    No valid ordering found")
    return None, None


def handle_ldm_group(
    guid: str,
    disks: list[dict],
    output_dir: str,
    keep_raw: bool,
) -> None:
    """Handle a group of Windows LDM Dynamic Disk members."""
    label = f"ldm_{guid[:8]}"
    out = os.path.join(output_dir, label)
    ensure_dir(out)

    logger.info("  Disk Group GUID: %s", guid)
    logger.info("  Members: %d disk(s)", len(disks))
    for d in disks:
        logger.info(
            "    %s (per-disk: %s...)", d["e01"], d.get("per_disk_guid", "?")[:13]
        )

    standalone: list[dict] = []
    for d in disks:
        parts = get_partitions(d["raw"])
        for p in parts:
            fs_type = fsstat_probe(d["raw"], p["start"])
            if fs_type is not None:
                vol_label = None
                rc, fsout, _ = run(
                    ["fsstat", "-i", "raw", "-o", str(p["start"]), d["raw"]]
                )
                if rc == 0:
                    for line in fsout.decode(errors="replace").splitlines():
                        if "Volume Name" in line or "Volume Label" in line:
                            vol_label = line.split(":", 1)[1].strip()
                standalone.append({
                    "disk": d,
                    "offset": p["start"],
                    "fs_type": fs_type,
                    "label": vol_label or d["e01"].replace(".E01", ""),
                })

    if standalone:
        vmdb = parse_ldm_vmdb(disks[0]["raw"])
        if vmdb and vmdb.get("partitions"):
            guid_to_disk = {d.get("per_disk_guid", ""): d for d in disks}
            vmdb_disk_guid = {
                rec["id"]: rec.get("guid", "") for rec in vmdb.get("disks", [])
            }

            for prt in vmdb["partitions"]:
                vol_off = prt.get("volume_offset_sectors", 0)
                disk_id = prt.get("disk_id")
                if not vol_off or not disk_id:
                    continue

                disk_guid = vmdb_disk_guid.get(disk_id, "")
                phys_disk = guid_to_disk.get(disk_guid)
                if not phys_disk:
                    continue

                disk_parts = get_partitions(phys_disk["raw"])
                if not disk_parts:
                    continue
                ldm_start = disk_parts[0]["start"]

                abs_offset = ldm_start + vol_off
                fs_type = fsstat_probe(phys_disk["raw"], abs_offset)
                if fs_type is not None:
                    vol_label = None
                    rc, fsout, _ = run(
                        ["fsstat", "-i", "raw", "-o", str(abs_offset), phys_disk["raw"]]
                    )
                    if rc == 0:
                        for line in fsout.decode(errors="replace").splitlines():
                            if "Volume Name" in line or "Volume Label" in line:
                                vol_label = line.split(":", 1)[1].strip()
                    standalone.append({
                        "disk": phys_disk,
                        "offset": abs_offset,
                        "fs_type": fs_type,
                        "label": vol_label or prt.get("name", "volume"),
                    })

    if standalone:
        logger.info("  -> Individual volumes (not RAID): %d found", len(standalone))
        for s in standalone:
            safe_label = re.sub(r"[^\w.-]", "_", s["label"]).strip("_") or "volume"
            vol_out = os.path.join(out, safe_label)
            logger.info(
                "  [%s] %s volume '%s' at sector %d",
                s["disk"]["e01"],
                s["fs_type"] or "?",
                s["label"],
                s["offset"],
            )
            extract_files_from_image(s["disk"]["raw"], s["offset"], vol_out)
        return

    logger.info("  -> No standalone filesystems found. Analyzing RAID configuration...")

    vmdb = parse_ldm_vmdb(disks[0]["raw"])
    raid_vol = None
    if vmdb:
        for v in vmdb["volumes"]:
            logger.info("    VMDB Volume: '%s' type='%s'", v["name"], v["type"])
            if v["type"] == "raid5":
                raid_vol = v
        for d_rec in vmdb.get("disks", []):
            logger.info(
                "    VMDB Disk: '%s' guid=%s...", d_rec["name"], d_rec["guid"][:20]
            )

    if not raid_vol:
        logger.info("    No RAID 5 volume found in VMDB. Assuming RAID 5.")

    parts = get_partitions(disks[0]["raw"])
    if not parts:
        logger.warning("  No partition table found on disks")
        return

    part = parts[0]
    part_offset_bytes = part["start"] * 512

    ordered: list[str | None] | None = None
    n_columns = len(disks)
    missing_idx: int | None = None

    result = _resolve_ldm_disk_order(vmdb, disks)
    if result:
        ordered, n_columns = result
        present = sum(1 for p in ordered if p is not None)
        missing_indices = [i for i, p in enumerate(ordered) if p is None]
        logger.info("  Disk order from VMDB: %d columns, %d present", n_columns, present)
        if len(missing_indices) == 1:
            missing_idx = missing_indices[0]
        elif len(missing_indices) > 1:
            logger.warning("  Too many missing disks (%d)", len(missing_indices))
            return

    chunk_bytes: int | None = None
    if ordered:
        chunk_bytes = _detect_stripe_size(ordered, part_offset_bytes, n_columns)
        if chunk_bytes:
            logger.info("  Detected stripe size: %d KiB", chunk_bytes // 1024)

    if not chunk_bytes:
        chunk_bytes = 64 * 1024
        logger.info("  Using default stripe size: %d KiB", chunk_bytes // 1024)

    if not ordered:
        raw_paths = [d["raw"] for d in disks]
        logger.info("  VMDB disk order unavailable, trying brute-force...")
        ordered = _detect_disk_order_bruteforce(
            raw_paths, chunk_bytes, part_offset_bytes, n_columns
        )
        if not ordered:
            for try_cols in range(len(disks) + 1, len(disks) + 3):
                logger.info("  Trying as degraded %d-disk array...", try_cols)
                ordered, missing_idx = _detect_degraded_disk_order(
                    raw_paths, chunk_bytes, part_offset_bytes, try_cols
                )
                if ordered:
                    n_columns = try_cols
                    break
        if not ordered:
            logger.warning("  Could not determine disk order")
            return

    sectors_per_chunk = chunk_bytes // 512
    data_size_sectors = (part["length"] // sectors_per_chunk) * sectors_per_chunk

    logger.info("  RAID 5 parameters:")
    logger.info("    Chunk size: %d KiB", chunk_bytes // 1024)
    logger.info("    Columns: %d", n_columns)
    logger.info("    Partition offset: sector %d", part["start"])
    logger.info(
        "    Data size/disk: %d sectors (%.2f GiB)",
        data_size_sectors,
        data_size_sectors * 512 / 1073741824,
    )
    logger.info("    Layout: left-symmetric")

    for i, path in enumerate(ordered):
        if path:
            e01_name = next((d["e01"] for d in disks if d["raw"] == path), "?")
            logger.info("    Column %d: %s", i, e01_name)
        else:
            logger.info("    Column %d: MISSING (rebuild from parity)", i)

    raid_img = os.path.join(out, "raid5_reconstructed.raw")
    logger.info("  Reconstructing RAID 5...")
    reconstruct_raid5_left_symmetric(
        disk_files=ordered,
        chunk_bytes=chunk_bytes,
        data_offset_bytes=part_offset_bytes,
        data_size_sectors=data_size_sectors,
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
```

- [ ] **Step 3: Implement `raidex/handlers/standalone.py`**

```python
"""Handler for standalone (non-RAID) volumes."""

from __future__ import annotations

import logging
import os

from raidex.extraction import extract_files_from_image

logger = logging.getLogger(__name__)


def handle_standalone(
    disk: dict,
    output_dir: str,
) -> None:
    """Extract files from a standalone volume."""
    vol_out = os.path.join(output_dir, disk["e01"].replace(".E01", ""))
    extract_files_from_image(disk["raw"], disk["fs_offset"], vol_out)
```

- [ ] **Step 4: Implement `raidex/handlers/hardware.py`**

Move from `detect_and_extract_raids.py` lines 1419-1566. Replace print with logging, use `fsstat_probe`.

```python
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
```

- [ ] **Step 5: Update `raidex/handlers/__init__.py` with dispatcher**

```python
"""Group handlers — process classified disk groups and extract data."""

from __future__ import annotations

import logging

from raidex.handlers.hardware import handle_hardware_raid_group
from raidex.handlers.ldm import handle_ldm_group
from raidex.handlers.md import handle_md_group
from raidex.handlers.standalone import handle_standalone
from raidex.types import HwOverrides

logger = logging.getLogger(__name__)


def dispatch_group(
    gtype: str,
    gid: str,
    disks: list[dict],
    output_dir: str,
    keep_raw: bool,
    hw_overrides: HwOverrides | None = None,
) -> None:
    """Route a disk group to the appropriate handler."""
    if gtype == "md":
        logger.info("GROUP: Linux md RAID (%d disk(s))", len(disks))
        handle_md_group(gid, disks, output_dir, keep_raw)
    elif gtype == "ldm":
        logger.info("GROUP: Windows LDM Dynamic Disks (%d disk(s))", len(disks))
        handle_ldm_group(gid, disks, output_dir, keep_raw)
    elif gtype == "standalone":
        logger.info("GROUP: Standalone volume (%s)", disks[0]["e01"])
        handle_standalone(disks[0], output_dir)
    elif gtype == "hardware":
        logger.info("GROUP: Hardware RAID candidate (%d disk(s))", len(disks))
        handle_hardware_raid_group(disks, output_dir, keep_raw, hw_overrides)
    else:
        logger.warning("GROUP: Unknown (%s) — skipped", disks[0]["e01"])
```

- [ ] **Step 6: Commit**

```bash
git add raidex/handlers/
git commit -m "feat: add group handlers for md, ldm, standalone, hardware"
```

---

## Task 9: Pipeline and CLI

**Files:**
- Create: `raidex/pipeline.py`, `raidex/cli.py`

- [ ] **Step 1: Implement `raidex/pipeline.py`**

Move the 3-phase orchestrator from `detect_and_extract_raids.py` lines 1631-1757. Use `ExitStack` for mounts. Use `probe_disk` dispatcher and `dispatch_group`.

```python
"""Three-phase pipeline: mount -> classify -> group -> extract."""

from __future__ import annotations

import glob
import logging
import os
import shutil
import sys
from contextlib import ExitStack

from raidex.handlers import dispatch_group
from raidex.mounting import EwfMount
from raidex.probes import probe_disk
from raidex.probes.hardware import detect_hardware_raid_groups, detect_standalone_mirrors
from raidex.types import HwOverrides
from raidex.util import ensure_dir

logger = logging.getLogger(__name__)

REQUIRED_TOOLS = ["ewfmount", "fusermount", "fls", "icat", "mmls", "fsstat"]


def run_pipeline(
    input_dir: str,
    output_dir: str,
    keep_raw: bool = False,
    hw_overrides: HwOverrides | None = None,
) -> None:
    """Run the full RAID detection and extraction pipeline."""
    for tool in REQUIRED_TOOLS:
        if not shutil.which(tool):
            logger.error("Required tool not found: %s", tool)
            sys.exit(1)

    e01_files = sorted(glob.glob(os.path.join(input_dir, "*.E01")))
    if not e01_files:
        e01_files = sorted(
            glob.glob(os.path.join(input_dir, "**", "*.E01"), recursive=True)
        )
    if not e01_files:
        logger.error("No E01 files found in %s", input_dir)
        sys.exit(1)

    seen: dict[str, str] = {}
    unique_e01: list[str] = []
    for path in e01_files:
        name = os.path.basename(path)
        if name not in seen:
            seen[name] = path
            unique_e01.append(path)
    e01_files = unique_e01

    logger.info("Found %d unique E01 image(s) in %s", len(e01_files), input_dir)
    ensure_dir(output_dir)

    # Phase 1: Mount and classify
    logger.info("=" * 60)
    logger.info("Phase 1: Mounting and classifying disks")
    logger.info("=" * 60)

    classified: list[dict] = []

    with ExitStack() as mount_stack:
        for e01 in e01_files:
            name = os.path.basename(e01)
            logger.info("[*] %s", name)

            mount = EwfMount(e01)
            try:
                raw = mount_stack.enter_context(mount)
            except RuntimeError as e:
                logger.warning("  Mount failed: %s", e)
                continue

            disk = probe_disk(raw, name)
            classified.append(disk)

        if not classified:
            logger.error("No disks could be mounted/classified")
            sys.exit(1)

        # Phase 2: Group disks
        groups: dict[tuple, list[dict]] = {}
        for d in classified:
            if d["kind"] == "md":
                key = ("md", d["uuid"])
            elif d["kind"] == "ldm":
                key = ("ldm", d["disk_group_guid"])
            elif d["kind"] == "standalone":
                key = ("standalone", d["e01"])
            else:
                key = ("unknown", d["e01"])
            groups.setdefault(key, []).append(d)

        hw_groups = detect_hardware_raid_groups(classified)
        if hw_groups:
            hw_disk_e01s = set()
            for hg in hw_groups:
                for d in hg:
                    hw_disk_e01s.add(d["e01"])
            groups = {
                k: v
                for k, v in groups.items()
                if k[0] != "unknown" or k[1] not in hw_disk_e01s
            }
            for i, hg in enumerate(hw_groups):
                groups[("hardware", f"group_{i}")] = hg

        groups = detect_standalone_mirrors(groups)

        logger.info("=" * 60)
        logger.info("Phase 2: Identified %d disk group(s)", len(groups))
        logger.info("=" * 60)

        for (gtype, gid), gdisks in groups.items():
            names = ", ".join(d["e01"] for d in gdisks)
            logger.info("  [%s] %s... -> %d disk(s): %s", gtype, gid[:20], len(gdisks), names)

        # Phase 3: Reconstruct and extract
        logger.info("=" * 60)
        logger.info("Phase 3: Reconstruction and extraction")
        logger.info("=" * 60)

        for (gtype, gid), gdisks in groups.items():
            logger.info("=" * 60)
            dispatch_group(gtype, gid, gdisks, output_dir, keep_raw, hw_overrides)

    # Mounts cleaned up by ExitStack

    logger.info("=" * 60)
    logger.info("Done! Extracted files are in: %s", output_dir)
    logger.info("=" * 60)
```

- [ ] **Step 2: Implement `raidex/cli.py`**

Move from `detect_and_extract_raids.py` lines 1570-1601. Add logging setup, `-v`/`-q` flags.

```python
"""Command-line interface for raidex."""

from __future__ import annotations

import argparse
import logging
import os

from raidex.pipeline import run_pipeline


def main() -> None:
    """Entry point for the detect-raids CLI command."""
    parser = argparse.ArgumentParser(
        description="Auto-detect and extract data from RAID E01 forensic images"
    )
    parser.add_argument(
        "input_dir",
        nargs="?",
        default=".",
        help="Directory containing E01 files (default: current dir)",
    )
    parser.add_argument(
        "-o", "--output", default=None, help="Output directory"
    )
    parser.add_argument(
        "--keep-raw", action="store_true", help="Keep intermediate raw RAID images"
    )
    parser.add_argument(
        "--hw-raid-level",
        type=int,
        choices=[0, 1, 5],
        help="Force RAID level for unknown disks",
    )
    parser.add_argument(
        "--hw-stripe", type=int, help="Force stripe size in KiB"
    )
    parser.add_argument(
        "--hw-order", help="Force disk order (comma-separated E01 filenames)"
    )
    parser.add_argument(
        "--hw-offset", type=int, help="Force data offset in sectors"
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Verbose output (debug level)"
    )
    parser.add_argument(
        "-q", "--quiet", action="store_true", help="Quiet output (warnings only)"
    )
    args = parser.parse_args()

    # Configure logging
    if args.verbose:
        level = logging.DEBUG
    elif args.quiet:
        level = logging.WARNING
    else:
        level = logging.INFO

    logging.basicConfig(
        level=level,
        format="%(message)s",
    )

    input_dir = os.path.abspath(args.input_dir)
    output_dir = (
        os.path.abspath(args.output)
        if args.output
        else os.path.join(input_dir, "auto_extracted")
    )

    hw_overrides = None
    if (
        args.hw_raid_level is not None
        or args.hw_stripe
        or args.hw_order
        or args.hw_offset is not None
    ):
        hw_overrides = {
            "level": args.hw_raid_level,
            "stripe": args.hw_stripe,
            "offset": args.hw_offset,
            "order": args.hw_order.split(",") if args.hw_order else None,
        }

    run_pipeline(input_dir, output_dir, args.keep_raw, hw_overrides)
```

- [ ] **Step 3: Verify the package imports work**

```bash
uv run python -c "from raidex.cli import main; print('OK')"
```

Expected: `OK`

- [ ] **Step 4: Commit**

```bash
git add raidex/pipeline.py raidex/cli.py raidex/__init__.py raidex/__main__.py
git commit -m "feat: add pipeline orchestrator and CLI entry point"
```

---

## Task 10: Delete Old File, Update Config

**Files:**
- Delete: `detect_and_extract_raids.py`
- Modify: `AGENTS.md`

- [ ] **Step 1: Delete the old monolith**

```bash
git rm detect_and_extract_raids.py
```

- [ ] **Step 2: Update `AGENTS.md`**

Replace the entire contents with updated documentation reflecting the new package structure:

```markdown
# AGENTS.md

This file provides guidance to LLM when working with code in this repository.

## Project Overview

Forensic tool that auto-detects RAID configurations from E01 disk images, reconstructs arrays, and extracts user data. Targets Linux md RAID, Windows LDM/Dynamic Disk, and hardware RAID controllers (RAID 0/1/5, left-symmetric layout for RAID 5). No prior knowledge of disk grouping or RAID parameters required.

## Commands

```bash
# Run directly
uv run detect-raids [input_dir] [-o output_dir] [--keep-raw] [-v] [-q]

# Or via module
uv run python -m raidex [input_dir] [-o output_dir]

# Run tests
uv run pytest tests/
```

Validation: `sudo ./gen_test_data.sh` generates `test_data/` with E01 files, then `uv run detect-raids test_data/` runs the full pipeline.

## System Dependencies

Requires these CLI tools on PATH (not Python packages):
- `ewfmount` / `fusermount` — from libewf, for mounting E01 images via FUSE
- `fls`, `icat`, `mmls`, `fsstat` — from sleuthkit, for filesystem traversal

## Architecture

The `raidex/` package runs a 3-phase pipeline:

1. **Mount & Classify** (`pipeline.py` + `probes/`) — each E01 is FUSE-mounted via `EwfMount`, then probed: `probe_md()` -> `probe_ldm()` -> `probe_standalone()` -> unknown.

2. **Group** (`pipeline.py` + `probes/hardware.py`) — disks grouped by md UUID, LDM GUID, or file size (hardware RAID). Standalone mirrors detected by content comparison.

3. **Reconstruct & Extract** (`handlers/` + `reconstruction/` + `extraction.py`) — each group dispatched to its handler, which reconstructs the array and extracts files.

### Module Map

- `cli.py` — argparse, logging setup, entry point
- `pipeline.py` — 3-phase orchestrator, ExitStack for mount lifecycle
- `mounting.py` — EwfMount context manager
- `probes/` — disk type detection (md superblock, LDM PRIVHEAD/VMDB, standalone FS, hardware brute-force)
- `handlers/` — group processing (md, ldm, standalone, hardware)
- `reconstruction/` — RAID 0/5 data reassembly, order validation
- `parsers/` — partition tables (mmls + GPT), filesystem signatures
- `extraction.py` — fls/icat file extraction
- `util.py` — shared helpers, constants
- `types.py` — TypedDicts for classified disk data

### Dependency Flow

```
cli -> pipeline -> handlers -> {reconstruction, extraction, probes}
                            -> parsers
                   probes -> parsers
                   reconstruction -> util (for subprocess)
                   all modules -> util
```

## Conventions

- Python 3.14+, stdlib only (no third-party runtime deps)
- `uv` for package management, `pytest` for testing
- All subprocess calls go through `util.run()`
- Filesystem detection uses raw byte signatures, not external tools
- Logging via `logging` module; `print()` only for transient progress bars
- Type hints throughout; TypedDicts for classified disk data
```

- [ ] **Step 3: Sync the uv environment**

```bash
uv sync
```

- [ ] **Step 4: Run all tests to verify nothing is broken**

```bash
uv run pytest tests/ -v
```

Expected: all tests PASS.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "refactor: replace monolith with raidex package"
```

---

## Task 11: Write README

**Files:**
- Rewrite: `README.md`

- [ ] **Step 1: Write `README.md`**

Write a comprehensive README covering forensic methodology context and technical methodology. Structure:

```markdown
# Raidex

Auto-detecting RAID forensic data extraction from E01 disk images.

## Overview

One-paragraph description: what it does, what RAID types it supports, that it works without prior knowledge of disk grouping.

## Forensic Methodology

How this tool fits into a digital forensics workflow:

- **Evidence acquisition**: Expects E01 (Expert Witness Format) images — the standard forensic imaging format that preserves integrity via internal checksums. The tool operates read-only on mounted images.
- **Chain of custody**: All operations are non-destructive. E01 images are FUSE-mounted read-only. Intermediate reconstructed images can be retained (`--keep-raw`) for verification. No original evidence is modified.
- **Tool validation**: The included test data generator (`gen_test_data.sh`) creates known-good RAID configurations. Running the tool against test data validates correct reconstruction before applying to real evidence.
- **Reproducibility**: Given the same E01 inputs, the tool produces deterministic output. RAID parameters (detected or overridden) are logged for audit trails.

## Technical Methodology

### Detection Pipeline

The tool operates in three phases:

1. **Mount & Classify** — Each E01 image is FUSE-mounted via `ewfmount` to expose the raw disk. Each disk is probed in priority order:
   - **Linux md RAID**: Parse md superblock v1.2 at offset 4096 (or inside partitions). Extract UUID, RAID level, layout, chunk size, member role.
   - **Windows LDM**: Check for PRIVHEAD signature at sector 6. Parse VMDB/VBLK database from the last 2 MiB for volume and disk metadata.
   - **Standalone filesystem**: Try `fsstat` at common offsets (sectors 0, 63, 2048) and partition table entries.
   - **Unknown**: Disks not matching any probe — candidates for hardware RAID detection.

2. **Group** — Classified disks are grouped:
   - md members by array UUID
   - LDM members by disk group GUID
   - Unknown disks clustered by identical file size (hardware RAID candidates)
   - Standalone disks with identical content reclassified as RAID 1 mirrors

3. **Reconstruct & Extract** — Each group is processed by its handler:
   - **md RAID 5**: Roles from superblock determine disk order. Left-symmetric parity layout. Degraded arrays rebuilt via XOR.
   - **LDM RAID 5**: Disk order from VMDB Disk records matched by per-disk GUID. Stripe size auto-detected. Falls back to brute-force permutation.
   - **Hardware RAID**: No metadata available. Brute-force all permutations × stripe sizes × data offsets. Validates each candidate by checking for a valid filesystem (`fsstat` + `fls`). Tries RAID 5 → RAID 0 → degraded RAID 5.
   - File extraction uses sleuthkit's `fls`/`icat` for filesystem-aware recovery.

### RAID Reconstruction

- **RAID 0** (striping): Interleave chunks from each disk in order. Output size = N × per-disk data size.
- **RAID 1** (mirroring): Read directly from any mirror member.
- **RAID 5** (striping + parity): Left-symmetric layout. Parity disk for stripe s = (N-1) - (s mod N). Data chunks read from disk (parity+1) mod N onward. Missing disks rebuilt via XOR of remaining members.

## Requirements

- Python 3.14+
- `ewfmount` / `fusermount` (libewf) — for mounting E01 images
- `fls`, `icat`, `mmls`, `fsstat` (sleuthkit) — for filesystem analysis
- No root/sudo required for the tool itself (ewfmount uses FUSE)

## Installation

```bash
uv sync
```

## Usage

```bash
# Basic usage — scan current directory
detect-raids

# Specify input and output directories
detect-raids /path/to/e01/files -o /path/to/output

# Keep intermediate raw images for verification
detect-raids evidence/ --keep-raw

# Verbose output (debug-level logging)
detect-raids evidence/ -v

# Override hardware RAID parameters
detect-raids evidence/ --hw-raid-level 5 --hw-stripe 64 --hw-order disk_A.E01,disk_B.E01,disk_C.E01

# Run as module
python -m raidex /path/to/e01/files
```

## Testing

```bash
# Run unit tests
uv run pytest tests/

# Generate test data (requires root, mdadm, ewfacquire)
sudo ./gen_test_data.sh

# Validate against test data
detect-raids test_data/
```

## Project Structure

```
raidex/
├── cli.py              # Command-line interface
├── pipeline.py         # 3-phase orchestrator
├── mounting.py         # E01 image mounting
├── probes/             # Disk type detection
├── handlers/           # Group processing
├── reconstruction/     # RAID array reassembly
├── parsers/            # Partition and filesystem parsing
├── extraction.py       # File extraction via sleuthkit
├── util.py             # Shared helpers
└── types.py            # Type definitions
```
```

- [ ] **Step 2: Commit**

```bash
git add README.md
git commit -m "docs: write comprehensive README with forensic and technical methodology"
```

---

## Task 12: Final Verification

- [ ] **Step 1: Verify CLI entry point works**

```bash
uv run detect-raids --help
```

Expected: help output showing all arguments including `-v`, `-q`.

- [ ] **Step 2: Verify `python -m raidex` works**

```bash
uv run python -m raidex --help
```

Expected: same help output.

- [ ] **Step 3: Run full test suite**

```bash
uv run pytest tests/ -v
```

Expected: all PASS.

- [ ] **Step 4: Verify against test data (if available)**

If `test_data/` exists with E01 files:

```bash
uv run detect-raids test_data/ -o /tmp/raidex_test_output --keep-raw
```

Expected: same behavior as old `detect_and_extract_raids.py`.

- [ ] **Step 5: Final commit if any fixups needed**

```bash
git status
# If clean, done. If fixups needed, commit them.
```
