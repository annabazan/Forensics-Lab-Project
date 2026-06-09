"""Handler for Windows LDM Dynamic Disk groups."""

from __future__ import annotations

import itertools
import logging
import os
import re

from raidex.extraction import extract_files_from_image
from raidex.parsers.filesystem import detect_filesystem
from raidex.parsers.partition import get_partitions
from raidex.probes.ldm import parse_ldm_vmdb
from raidex.reconstruction.raid5 import reconstruct_raid5_left_symmetric
from raidex.util import ensure_dir, fsstat_probe, run

logger = logging.getLogger(__name__)


def _resolve_ldm_disk_order(
    vmdb: dict | None, disks: list[dict]
) -> tuple[list[str | None], int] | None:
    """Determine column order from VMDB Disk records + PRIVHEAD per-disk GUIDs."""
    if not vmdb or not vmdb.get("disks"):
        return None

    guid_to_column: dict[str, int] = {}
    for d in vmdb["disks"]:
        name = d.get("name", "")
        guid = d.get("guid", "")
        m = re.match(r"Disk(\d+)", name)
        if m and guid:
            col = int(m.group(1)) - 1
            guid_to_column[guid] = col

    if not guid_to_column:
        return None

    n_columns = max(guid_to_column.values()) + 1
    ordered: list[str | None] = [None] * n_columns
    for d in disks:
        per_guid = d.get("per_disk_guid", "")
        if per_guid in guid_to_column:
            col = guid_to_column[per_guid]
            if col < n_columns:
                ordered[col] = d["raw"]

    return ordered, n_columns


def _detect_stripe_size(
    ordered_paths: list[str | None], data_offset_bytes: int, n_columns: int
) -> int | None:
    """Try common stripe sizes and return the one that produces valid FS."""
    from raidex.reconstruction.raid5 import test_raid5_order
    from raidex.util import COMMON_STRIPE_SIZES

    for chunk_bytes in COMMON_STRIPE_SIZES:
        if test_raid5_order(ordered_paths, chunk_bytes, data_offset_bytes, n_columns):
            return chunk_bytes
    return None


def _detect_disk_order_bruteforce(
    raw_paths: list[str], chunk_bytes: int, data_offset_bytes: int, n_columns: int
) -> list[str] | None:
    """Try all permutations to find correct RAID disk ordering."""
    from raidex.reconstruction.raid5 import test_raid5_order

    n_perm = 1
    for i in range(1, len(raw_paths) + 1):
        n_perm *= i
    logger.debug("    Brute-force: trying %d permutations...", n_perm)
    for perm in itertools.permutations(range(len(raw_paths))):
        ordered = [raw_paths[i] for i in perm]
        if test_raid5_order(ordered, chunk_bytes, data_offset_bytes, n_columns):
            return ordered
    return None


def _detect_degraded_disk_order(
    present_raw_paths: list[str],
    chunk_bytes: int,
    data_offset_bytes: int,
    n_columns: int,
) -> tuple[list[str | None] | None, int | None]:
    """For degraded RAID, determine column positions of present disks."""
    from raidex.reconstruction.raid5 import test_raid5_order

    n_present = len(present_raw_paths)
    if n_columns - n_present != 1:
        logger.warning("    Cannot handle %d missing disks", n_columns - n_present)
        return None, None

    for missing_col in range(n_columns):
        remaining_cols = [i for i in range(n_columns) if i != missing_col]
        for perm in itertools.permutations(range(n_present)):
            ordered: list[str | None] = [None] * n_columns
            for i, p_idx in enumerate(perm):
                ordered[remaining_cols[i]] = present_raw_paths[p_idx]
            if test_raid5_order(ordered, chunk_bytes, data_offset_bytes, n_columns):
                return ordered, missing_col

    logger.warning("    No valid ordering found")
    return None, None


def handle_ldm_group(
    guid: str,
    disks: list[dict],
    output_dir: str,
    keep_raw: bool,
) -> None:
    """Handle a group of Windows LDM Dynamic Disk members."""
    label = f"ldm_{guid[:8]}"
    out = os.path.join(output_dir, label)
    ensure_dir(out)

    logger.info("  Disk Group GUID: %s", guid)
    logger.info("  Members: %d disk(s)", len(disks))
    for d in disks:
        logger.info(
            "    %s (per-disk: %s...)", d["e01"], d.get("per_disk_guid", "?")[:13]
        )

    standalone: list[dict] = []
    for d in disks:
        parts = get_partitions(d["raw"])
        for p in parts:
            fs_type = fsstat_probe(d["raw"], p["start"])
            if fs_type is not None:
                vol_label = None
                rc, fsout, _ = run(
                    ["fsstat", "-i", "raw", "-o", str(p["start"]), d["raw"]]
                )
                if rc == 0:
                    for line in fsout.decode(errors="replace").splitlines():
                        if "Volume Name" in line or "Volume Label" in line:
                            vol_label = line.split(":", 1)[1].strip()
                standalone.append({
                    "disk": d,
                    "offset": p["start"],
                    "fs_type": fs_type,
                    "label": vol_label or d["e01"].replace(".E01", ""),
                })

    if standalone:
        vmdb = parse_ldm_vmdb(disks[0]["raw"])
        if vmdb and vmdb.get("partitions"):
            guid_to_disk = {d.get("per_disk_guid", ""): d for d in disks}
            vmdb_disk_guid = {
                rec["id"]: rec.get("guid", "") for rec in vmdb.get("disks", [])
            }

            for prt in vmdb["partitions"]:
                vol_off = prt.get("volume_offset_sectors", 0)
                disk_id = prt.get("disk_id")
                if not vol_off or not disk_id:
                    continue

                disk_guid = vmdb_disk_guid.get(disk_id, "")
                phys_disk = guid_to_disk.get(disk_guid)
                if not phys_disk:
                    continue

                disk_parts = get_partitions(phys_disk["raw"])
                if not disk_parts:
                    continue
                ldm_start = disk_parts[0]["start"]

                abs_offset = ldm_start + vol_off
                fs_type = fsstat_probe(phys_disk["raw"], abs_offset)
                if fs_type is not None:
                    vol_label = None
                    rc, fsout, _ = run(
                        ["fsstat", "-i", "raw", "-o", str(abs_offset), phys_disk["raw"]]
                    )
                    if rc == 0:
                        for line in fsout.decode(errors="replace").splitlines():
                            if "Volume Name" in line or "Volume Label" in line:
                                vol_label = line.split(":", 1)[1].strip()
                    standalone.append({
                        "disk": phys_disk,
                        "offset": abs_offset,
                        "fs_type": fs_type,
                        "label": vol_label or prt.get("name", "volume"),
                    })

    if standalone:
        logger.info("  -> Individual volumes (not RAID): %d found", len(standalone))
        for s in standalone:
            safe_label = re.sub(r"[^\w.-]", "_", s["label"]).strip("_") or "volume"
            vol_out = os.path.join(out, safe_label)
            logger.info(
                "  [%s] %s volume '%s' at sector %d",
                s["disk"]["e01"],
                s["fs_type"] or "?",
                s["label"],
                s["offset"],
            )
            extract_files_from_image(s["disk"]["raw"], s["offset"], vol_out)
        return

    logger.info("  -> No standalone filesystems found. Analyzing RAID configuration...")

    vmdb = parse_ldm_vmdb(disks[0]["raw"])
    raid_vol = None
    if vmdb:
        for v in vmdb["volumes"]:
            logger.info("    VMDB Volume: '%s' type='%s'", v["name"], v["type"])
            if v["type"] == "raid5":
                raid_vol = v
        for d_rec in vmdb.get("disks", []):
            logger.info(
                "    VMDB Disk: '%s' guid=%s...", d_rec["name"], d_rec["guid"][:20]
            )

    if not raid_vol:
        logger.info("    No RAID 5 volume found in VMDB. Assuming RAID 5.")

    parts = get_partitions(disks[0]["raw"])
    if not parts:
        logger.warning("  No partition table found on disks")
        return

    part = parts[0]
    part_offset_bytes = part["start"] * 512

    ordered: list[str | None] | None = None
    n_columns = len(disks)
    missing_idx: int | None = None

    result = _resolve_ldm_disk_order(vmdb, disks)
    if result:
        ordered, n_columns = result
        present = sum(1 for p in ordered if p is not None)
        missing_indices = [i for i, p in enumerate(ordered) if p is None]
        logger.info("  Disk order from VMDB: %d columns, %d present", n_columns, present)
        if len(missing_indices) == 1:
            missing_idx = missing_indices[0]
        elif len(missing_indices) > 1:
            logger.warning("  Too many missing disks (%d)", len(missing_indices))
            return

    chunk_bytes: int | None = None
    if ordered:
        chunk_bytes = _detect_stripe_size(ordered, part_offset_bytes, n_columns)
        if chunk_bytes:
            logger.info("  Detected stripe size: %d KiB", chunk_bytes // 1024)

    if not chunk_bytes:
        chunk_bytes = 64 * 1024
        logger.info("  Using default stripe size: %d KiB", chunk_bytes // 1024)

    if not ordered:
        raw_paths = [d["raw"] for d in disks]
        logger.info("  VMDB disk order unavailable, trying brute-force...")
        ordered = _detect_disk_order_bruteforce(
            raw_paths, chunk_bytes, part_offset_bytes, n_columns
        )
        if not ordered:
            for try_cols in range(len(disks) + 1, len(disks) + 3):
                logger.info("  Trying as degraded %d-disk array...", try_cols)
                ordered, missing_idx = _detect_degraded_disk_order(
                    raw_paths, chunk_bytes, part_offset_bytes, try_cols
                )
                if ordered:
                    n_columns = try_cols
                    break
        if not ordered:
            logger.warning("  Could not determine disk order")
            return

    sectors_per_chunk = chunk_bytes // 512
    data_size_sectors = (part["length"] // sectors_per_chunk) * sectors_per_chunk

    logger.info("  RAID 5 parameters:")
    logger.info("    Chunk size: %d KiB", chunk_bytes // 1024)
    logger.info("    Columns: %d", n_columns)
    logger.info("    Partition offset: sector %d", part["start"])
    logger.info(
        "    Data size/disk: %d sectors (%.2f GiB)",
        data_size_sectors,
        data_size_sectors * 512 / 1073741824,
    )
    logger.info("    Layout: left-symmetric")

    for i, path in enumerate(ordered):
        if path:
            e01_name = next((d["e01"] for d in disks if d["raw"] == path), "?")
            logger.info("    Column %d: %s", i, e01_name)
        else:
            logger.info("    Column %d: MISSING (rebuild from parity)", i)

    raid_img = os.path.join(out, "raid5_reconstructed.raw")
    logger.info("  Reconstructing RAID 5...")
    reconstruct_raid5_left_symmetric(
        disk_files=ordered,
        chunk_bytes=chunk_bytes,
        data_offset_bytes=part_offset_bytes,
        data_size_sectors=data_size_sectors,
        output_path=raid_img,
        missing_disk_idx=missing_idx,
    )

    fs_type = detect_filesystem(raid_img)
    if fs_type:
        logger.info("  [+] Detected %s filesystem", fs_type)
    else:
        logger.warning("  No recognized filesystem signature")

    logger.info("  Extracting files...")
    extract_files_from_image(raid_img, 0, os.path.join(out, "files"))

    if not keep_raw and os.path.exists(raid_img):
        os.remove(raid_img)
        logger.info("  Removed intermediate image")
