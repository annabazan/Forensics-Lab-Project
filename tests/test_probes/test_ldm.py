"""Tests for Windows LDM PRIVHEAD and VMDB/VBLK parsing."""

import struct

from raidex.probes.ldm import probe_ldm, parse_ldm_vmdb

LDM_PRIVHEAD_SECTOR = 6


def _build_privhead(
    group_guid: str = "12345678-1234-1234-1234-123456789abc",
    per_disk_guid: str = "aabbccdd-1111-2222-3333-444455556666",
) -> bytes:
    """Build a minimal disk image with PRIVHEAD at sector 6."""
    data = bytearray(8 * 512)
    off = LDM_PRIVHEAD_SECTOR * 512
    data[off : off + 8] = b"PRIVHEAD"

    per_bytes = per_disk_guid.encode("ascii") + b"\x00"
    data[off + 0x30 : off + 0x30 + len(per_bytes)] = per_bytes

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
