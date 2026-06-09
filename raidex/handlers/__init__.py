"""Group handlers — process classified disk groups and extract data."""

from __future__ import annotations

import logging

from raidex.handlers.hardware import handle_hardware_raid_group
from raidex.handlers.ldm import handle_ldm_group
from raidex.handlers.md import handle_md_group
from raidex.handlers.standalone import handle_standalone
from raidex.types import HwOverrides

logger = logging.getLogger(__name__)


def dispatch_group(
    gtype: str,
    gid: str,
    disks: list[dict],
    output_dir: str,
    keep_raw: bool,
    hw_overrides: HwOverrides | None = None,
) -> None:
    """Route a disk group to the appropriate handler."""
    if gtype == "md":
        logger.info("GROUP: Linux md RAID (%d disk(s))", len(disks))
        handle_md_group(gid, disks, output_dir, keep_raw)
    elif gtype == "ldm":
        logger.info("GROUP: Windows LDM Dynamic Disks (%d disk(s))", len(disks))
        handle_ldm_group(gid, disks, output_dir, keep_raw)
    elif gtype == "standalone":
        logger.info("GROUP: Standalone volume (%s)", disks[0]["e01"])
        handle_standalone(disks[0], output_dir)
    elif gtype == "hardware":
        logger.info("GROUP: Hardware RAID candidate (%d disk(s))", len(disks))
        handle_hardware_raid_group(disks, output_dir, keep_raw, hw_overrides)
    else:
        logger.warning("GROUP: Unknown (%s) — skipped", disks[0]["e01"])
