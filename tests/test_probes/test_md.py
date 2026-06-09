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
    """Build a minimal md superblock v1.2 (256 bytes header) + role map."""
    sb = bytearray(256)
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

    return bytes(sb) + b"\x00" * (256 - len(sb)) + roles_raw


class TestReadMdSuperblock:
    def test_valid_superblock(self, tmp_path):
        img = tmp_path / "disk.raw"
        sb_data = _build_md_superblock(
            level=5, layout=2, chunk_sectors=1024, raid_disks=3,
            data_offset=2048, data_size=190464, dev_number=1,
            max_dev=3, roles=[0, 1, 2],
        )
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
