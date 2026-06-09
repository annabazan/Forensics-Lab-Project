"""Handler for standalone (non-RAID) volumes."""

from __future__ import annotations

import logging
import os

from raidex.extraction import extract_files_from_image
from raidex.types import ClassifiedDisk

logger = logging.getLogger(__name__)


def handle_standalone(
    disk: ClassifiedDisk,
    output_dir: str,
) -> None:
    """Extract files from a standalone volume."""
    vol_out = os.path.join(output_dir, disk["e01"].replace(".E01", ""))
    extract_files_from_image(disk["raw"], disk["fs_offset"], vol_out)
