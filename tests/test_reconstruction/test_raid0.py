"""Tests for RAID 0 reconstruction."""

from raidex.reconstruction.raid0 import reconstruct_raid0


class TestReconstructRaid0:
    def test_three_disk_512b_chunk(self, tmp_path):
        """Three disks, 512-byte chunks, 2 stripes."""
        chunk = 512
        d0 = tmp_path / "d0.raw"
        d1 = tmp_path / "d1.raw"
        d2 = tmp_path / "d2.raw"
        d0.write_bytes(b"\xAA" * chunk + b"\xDD" * chunk)
        d1.write_bytes(b"\xBB" * chunk + b"\xEE" * chunk)
        d2.write_bytes(b"\xCC" * chunk + b"\xFF" * chunk)

        out = tmp_path / "raid.raw"
        reconstruct_raid0(
            disk_files=[str(d0), str(d1), str(d2)],
            chunk_bytes=chunk,
            data_offset_bytes=0,
            data_size_sectors=2,
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
        offset = 1024
        d0 = tmp_path / "d0.raw"
        d1 = tmp_path / "d1.raw"
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
