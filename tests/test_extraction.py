"""Tests for file extraction safety."""

import os
import subprocess
from unittest.mock import patch, MagicMock

from raidex.extraction import extract_files_from_image


def _mock_run_for_fls(lines: list[str]):
    """Build a mock for raidex.extraction.run that returns fls output."""
    encoded = "\n".join(lines).encode()

    def side_effect(cmd, **kwargs):
        if cmd[0] == "fls":
            return (0, encoded, b"")
        return (1, b"", b"")

    return side_effect


class TestPathTraversal:
    def test_rejects_dot_dot_traversal(self, tmp_path):
        out_dir = str(tmp_path / "out")
        fls_lines = ["r/r 5:\t../../etc/evil"]
        with patch("raidex.extraction.run", side_effect=_mock_run_for_fls(fls_lines)):
            extract_files_from_image("/fake/image", 0, out_dir)
        assert not (tmp_path / "etc").exists()

    def test_rejects_absolute_path(self, tmp_path):
        out_dir = str(tmp_path / "out")
        fls_lines = ["r/r 5:\t/etc/passwd"]
        with patch("raidex.extraction.run", side_effect=_mock_run_for_fls(fls_lines)):
            extract_files_from_image("/fake/image", 0, out_dir)
        files = [e for e in os.listdir(out_dir) if os.path.isfile(os.path.join(out_dir, e))]
        assert files == []

    def test_allows_normal_paths(self, tmp_path):
        out_dir = str(tmp_path / "out")
        fls_lines = ["r/r 5:\tnormal_file.txt"]
        mock_proc = MagicMock(returncode=0)
        with (
            patch("raidex.extraction.run", side_effect=_mock_run_for_fls(fls_lines)),
            patch("raidex.extraction.subprocess.run", return_value=mock_proc),
        ):
            extract_files_from_image("/fake/image", 0, out_dir)
        assert (tmp_path / "out" / "normal_file.txt").exists()

    def test_rejects_directory_traversal(self, tmp_path):
        out_dir = str(tmp_path / "out")
        fls_lines = ["d/d 10:\t../../escape"]
        with patch("raidex.extraction.run", side_effect=_mock_run_for_fls(fls_lines)):
            extract_files_from_image("/fake/image", 0, out_dir)
        assert not (tmp_path / "escape").exists()


class TestStreamingExtraction:
    def test_icat_streams_to_file_not_memory(self, tmp_path):
        """Verify icat uses subprocess.run(stdout=file) for streaming."""
        out_dir = str(tmp_path / "out")
        fls_lines = ["r/r 5:\ttest.bin"]
        mock_proc = MagicMock(returncode=0)
        with (
            patch("raidex.extraction.run", side_effect=_mock_run_for_fls(fls_lines)),
            patch("raidex.extraction.subprocess.run", return_value=mock_proc) as mock_subproc,
        ):
            extract_files_from_image("/fake/image", 0, out_dir)
        mock_subproc.assert_called_once()
        _, kwargs = mock_subproc.call_args
        assert hasattr(kwargs["stdout"], "write")
