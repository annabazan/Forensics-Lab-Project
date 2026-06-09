"""Tests for hardware RAID grouping and mirror detection."""

import os

from raidex.probes.hardware import detect_hardware_raid_groups, detect_standalone_mirrors


class TestDetectHardwareRaidGroups:
    def test_groups_unknowns_by_size(self, tmp_path):
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
