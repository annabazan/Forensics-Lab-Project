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
        d = {}
        d[(0, 0)] = b"\x11" * chunk
        d[(0, 1)] = b"\x22" * chunk
        d[(1, 0)] = b"\x33" * chunk
        d[(1, 1)] = b"\x44" * chunk
        d[(2, 0)] = b"\x55" * chunk
        d[(2, 1)] = b"\x66" * chunk

        p0 = _xor_bytes(d[(0, 0)], d[(0, 1)])
        p1 = _xor_bytes(d[(1, 0)], d[(1, 1)])
        p2 = _xor_bytes(d[(2, 0)], d[(2, 1)])

        # stripe 0: pd=2, data order: disk (2+1)%3=0, (2+2)%3=1
        # stripe 1: pd=1, data order: disk (1+1)%3=2, (1+2)%3=0
        # stripe 2: pd=0, data order: disk (0+1)%3=1, (0+2)%3=2
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
            data_size_sectors=3,
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

        disk0 = tmp_path / "d0.raw"
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
        assert result == d00 + d01
