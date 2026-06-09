"""File extraction from filesystem images using sleuthkit's fls/icat."""

from __future__ import annotations

import logging
import os
import subprocess

from raidex.util import ensure_dir, run

logger = logging.getLogger(__name__)


def _is_safe_path(base: str, target: str) -> bool:
    """Return True iff target resolves to a path inside base."""
    real_base = os.path.realpath(base)
    real_target = os.path.realpath(target)
    return real_target == real_base or real_target.startswith(real_base + os.sep)


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
        if not _is_safe_path(out_dir, cur_dir):
            logger.warning("Skipping unsafe directory path: %s", cur_dir)
            return
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
                if not _is_safe_path(out_dir, dest):
                    logger.warning("Skipping unsafe file path: %s", dest)
                    continue
                cmd2 = ["icat"] + type_flag + offset_flag + [image_path, inode_str]
                ensure_dir(os.path.dirname(dest))
                with open(dest, "wb") as f:
                    result = subprocess.run(cmd2, stdout=f, stderr=subprocess.PIPE)
                if result.returncode == 0:
                    file_size = os.path.getsize(dest)
                    logger.info(
                        "    Extracted: %s (%s bytes)", entry_path, f"{file_size:,}"
                    )
                else:
                    try:
                        os.remove(dest)
                    except OSError:
                        pass

    _extract_dir("", "")
