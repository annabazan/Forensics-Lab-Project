"""Tests for filesystem signature detection."""

import struct

from raidex.parsers.filesystem import detect_fs_signature, detect_filesystem


class TestDetectFsSignature:
    def test_ntfs_signature(self):
        data = bytearray(2048)
        data[3:7] = b"NTFS"
        struct.pack_into("<H", data, 11, 512)
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
