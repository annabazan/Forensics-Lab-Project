"""Three-phase pipeline: mount -> classify -> group -> extract."""

from __future__ import annotations

import glob
import logging
import os
import shutil
import sys
from contextlib import ExitStack

from raidex.handlers import dispatch_group
from raidex.mounting import EwfMount
from raidex.probes import probe_disk
from raidex.probes.hardware import detect_hardware_raid_groups, detect_standalone_mirrors
from raidex.types import HwOverrides
from raidex.util import ensure_dir

logger = logging.getLogger(__name__)

REQUIRED_TOOLS = ["ewfmount", "fusermount", "fls", "icat", "mmls", "fsstat"]


def run_pipeline(
    input_dir: str,
    output_dir: str,
    keep_raw: bool = False,
    hw_overrides: HwOverrides | None = None,
) -> None:
    """Run the full RAID detection and extraction pipeline."""
    for tool in REQUIRED_TOOLS:
        if not shutil.which(tool):
            logger.error("Required tool not found: %s", tool)
            sys.exit(1)

    e01_files = sorted(
        glob.glob(os.path.join(input_dir, "*.E01"))
        + glob.glob(os.path.join(input_dir, "*.e01"))
    )
    if not e01_files:
        e01_files = sorted(
            glob.glob(os.path.join(input_dir, "**", "*.E01"), recursive=True)
            + glob.glob(os.path.join(input_dir, "**", "*.e01"), recursive=True)
        )
    if not e01_files:
        logger.error("No E01 files found in %s", input_dir)
        sys.exit(1)

    seen: dict[str, str] = {}
    unique_e01: list[str] = []
    for path in e01_files:
        name = os.path.basename(path)
        if name not in seen:
            seen[name] = path
            unique_e01.append(path)
    e01_files = unique_e01

    logger.info("Found %d unique E01 image(s) in %s", len(e01_files), input_dir)
    ensure_dir(output_dir)

    # Phase 1: Mount and classify
    logger.info("=" * 60)
    logger.info("Phase 1: Mounting and classifying disks")
    logger.info("=" * 60)

    classified: list[dict] = []

    with ExitStack() as mount_stack:
        for e01 in e01_files:
            name = os.path.basename(e01)
            logger.info("[*] %s", name)

            mount = EwfMount(e01)
            try:
                raw = mount_stack.enter_context(mount)
            except RuntimeError as e:
                logger.warning("  Mount failed: %s", e)
                continue

            disk = probe_disk(raw, name)
            classified.append(disk)

        if not classified:
            logger.error("No disks could be mounted/classified")
            sys.exit(1)

        # Phase 2: Group disks
        groups: dict[tuple, list[dict]] = {}
        for d in classified:
            if d["kind"] == "md":
                key = ("md", d["uuid"])
            elif d["kind"] == "ldm":
                key = ("ldm", d["disk_group_guid"])
            elif d["kind"] == "standalone":
                key = ("standalone", d["e01"])
            else:
                key = ("unknown", d["e01"])
            groups.setdefault(key, []).append(d)

        hw_groups = detect_hardware_raid_groups(classified)
        if hw_groups:
            hw_disk_e01s = set()
            for hg in hw_groups:
                for d in hg:
                    hw_disk_e01s.add(d["e01"])
            groups = {
                k: v
                for k, v in groups.items()
                if k[0] != "unknown" or k[1] not in hw_disk_e01s
            }
            for i, hg in enumerate(hw_groups):
                groups[("hardware", f"group_{i}")] = hg

        groups = detect_standalone_mirrors(groups)

        logger.info("=" * 60)
        logger.info("Phase 2: Identified %d disk group(s)", len(groups))
        logger.info("=" * 60)

        for (gtype, gid), gdisks in groups.items():
            names = ", ".join(d["e01"] for d in gdisks)
            logger.info("  [%s] %s... -> %d disk(s): %s", gtype, gid[:20], len(gdisks), names)

        # Phase 3: Reconstruct and extract
        logger.info("=" * 60)
        logger.info("Phase 3: Reconstruction and extraction")
        logger.info("=" * 60)

        for (gtype, gid), gdisks in groups.items():
            logger.info("=" * 60)
            dispatch_group(gtype, gid, gdisks, output_dir, keep_raw, hw_overrides)

    # Mounts cleaned up by ExitStack

    logger.info("=" * 60)
    logger.info("Done! Extracted files are in: %s", output_dir)
    logger.info("=" * 60)
