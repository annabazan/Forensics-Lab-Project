"""Disk type probes — detect md, LDM, standalone, and hardware RAID."""

from __future__ import annotations

import logging

from raidex.probes.ldm import probe_ldm
from raidex.probes.md import probe_md
from raidex.probes.standalone import probe_standalone
from raidex.types import ClassifiedDisk

logger = logging.getLogger(__name__)


def probe_disk(raw_path: str, e01_name: str) -> ClassifiedDisk:
    """Classify a single disk by probing md -> LDM -> standalone -> unknown."""
    md = probe_md(raw_path)
    if md:
        logger.info(
            "  -> Linux md RAID %d (UUID %s..., role %d)",
            md["level"],
            md["uuid"][:13],
            md["role"],
        )
        return {"kind": "md", "e01": e01_name, "raw": raw_path, **md}

    ldm = probe_ldm(raw_path)
    if ldm:
        logger.info(
            "  -> Windows LDM (group %s...)", ldm["disk_group_guid"][:13]
        )
        return {"kind": "ldm", "e01": e01_name, "raw": raw_path, **ldm}

    standalone = probe_standalone(raw_path)
    if standalone:
        logger.info(
            "  -> Standalone %s at sector %d",
            standalone["fs_type"],
            standalone["fs_offset"],
        )
        return {
            "kind": "standalone",
            "e01": e01_name,
            "raw": raw_path,
            **standalone,
        }

    logger.info("  -> Unknown disk type")
    return {"kind": "unknown", "e01": e01_name, "raw": raw_path}
