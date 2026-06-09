"""File extraction from filesystem images using sleuthkit's fls/icat."""

from __future__ import annotations

import logging
import os

from raidex.util import ensure_dir, run

logger = logging.getLogger(__name__)


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
                cmd2 = ["icat"] + type_flag + offset_flag + [image_path, inode_str]
                rc2, data, _ = run(cmd2)
                if rc2 == 0 and data:
                    with open(dest, "wb") as f:
                        f.write(data)
                    logger.info(
                        "    Extracted: %s (%s bytes)", entry_path, f"{len(data):,}"
                    )

    _extract_dir("", "")
