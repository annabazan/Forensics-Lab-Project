"""Tests for partition table parsing."""

import struct

from raidex.parsers.partition import parse_gpt


def _build_gpt_image(partitions: list[tuple[int, int, str]]) -> bytes:
    """Build a minimal GPT image with given partitions."""
    sector = 512
    num_entries = max(len(partitions), 4)
    entry_size = 128

    mbr = b"\x00" * sector

    header = bytearray(sector)
    header[0:8] = b"EFI PART"
    struct.pack_into("<Q", header, 72, 2)
    struct.pack_into("<I", header, 80, num_entries)
    struct.pack_into("<I", header, 84, entry_size)

    entries = bytearray(num_entries * entry_size)
    for i, (start, end, name) in enumerate(partitions):
        off = i * entry_size
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
        entry_off = 512 * 2
        img_bytes[entry_off : entry_off + 16] = b"\x00" * 16
        img = tmp_path / "disk.raw"
        img.write_bytes(bytes(img_bytes))
        assert parse_gpt(str(img)) == []
