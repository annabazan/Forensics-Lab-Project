"""Tests for brute-force permutation cap on hardware RAID detection."""

from raidex.probes.hardware import try_hardware_raid0, try_hardware_raid5

MAX_BRUTE_FORCE_DISKS = 5


class TestBruteForceCap:
    def test_raid0_refuses_above_cap(self):
        disks = [
            {"kind": "unknown", "e01": f"d{i}.E01", "raw": f"/fake/d{i}.raw"}
            for i in range(MAX_BRUTE_FORCE_DISKS + 1)
        ]
        result = try_hardware_raid0(disks)
        assert result is None

    def test_raid5_refuses_above_cap(self):
        disks = [
            {"kind": "unknown", "e01": f"d{i}.E01", "raw": f"/fake/d{i}.raw"}
            for i in range(MAX_BRUTE_FORCE_DISKS + 1)
        ]
        result = try_hardware_raid5(disks)
        assert result is None
