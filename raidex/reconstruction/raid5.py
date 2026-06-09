"""RAID 5 left-symmetric reconstruction."""

from __future__ import annotations

import logging
import os
import sys
import tempfile
from contextlib import ExitStack

from raidex.util import run

logger = logging.getLogger(__name__)


def reconstruct_raid5_left_symmetric(
    disk_files: list[str | None],
    chunk_bytes: int,
    data_offset_bytes: int,
    data_size_sectors: int,
    output_path: str,
    missing_disk_idx: int | None = None,
) -> None:
    """Reconstruct a RAID 5 array with left-symmetric layout.

    Parity disk for stripe s: (n - 1) - (s % n).
    Data chunks start from disk (parity + 1) % n.
    Missing disk rebuilt via XOR of remaining disks.
    """
    n_disks = len(disk_files)
    data_disks_count = n_disks - 1
    sectors_per_chunk = chunk_bytes // 512
    total_data_bytes = data_size_sectors * 512 * data_disks_count

    logger.info(
        "    RAID-5: %d disks, %d KiB chunk, left-symmetric, data offset %d bytes",
        n_disks,
        chunk_bytes // 1024,
        data_offset_bytes,
    )
    logger.info(
        "    Total RAID volume size: %.2f GiB",
        total_data_bytes / 1024 / 1024 / 1024,
    )
    if missing_disk_idx is not None:
        logger.info(
            "    Recovering missing disk index %d from parity", missing_disk_idx
        )

    num_stripes = data_size_sectors // sectors_per_chunk
    report_interval = max(1, num_stripes // 20)

    with ExitStack() as stack:
        fds: list = []
        for path in disk_files:
            fds.append(
                stack.enter_context(open(path, "rb")) if path is not None else None
            )

        with open(output_path, "wb") as out:
            bytes_written = 0
            for stripe in range(num_stripes):
                pd = (n_disks - 1) - (stripe % n_disks)

                for dd in range(data_disks_count):
                    disk_idx = (pd + 1 + dd) % n_disks
                    disk_off = data_offset_bytes + stripe * chunk_bytes

                    if disk_idx == missing_disk_idx:
                        accum = 0
                        for other_idx in range(n_disks):
                            if other_idx == missing_disk_idx:
                                continue
                            fds[other_idx].seek(disk_off)
                            other = fds[other_idx].read(chunk_bytes)
                            if len(other) < chunk_bytes:
                                other += b"\x00" * (chunk_bytes - len(other))
                            accum ^= int.from_bytes(other, "little")
                        out.write(accum.to_bytes(chunk_bytes, "little"))
                    else:
                        fds[disk_idx].seek(disk_off)
                        chunk = fds[disk_idx].read(chunk_bytes)
                        if len(chunk) < chunk_bytes:
                            chunk += b"\x00" * (chunk_bytes - len(chunk))
                        out.write(chunk)

                    bytes_written += chunk_bytes

                if stripe % report_interval == 0 and stripe > 0:
                    pct = stripe / num_stripes * 100
                    print(
                        f"    Progress: {pct:.0f}%",
                        end="\r",
                        flush=True,
                        file=sys.stderr,
                    )

    logger.info(
        "    Wrote %.1f MiB to %s",
        bytes_written / 1024 / 1024,
        os.path.basename(output_path),
    )


def test_raid5_order(
    ordered_paths: list[str | None],
    chunk_bytes: int,
    data_offset_bytes: int,
    n_disks: int,
) -> bool:
    """Reconstruct first ~16 MiB of RAID and check for valid filesystem."""
    n_data = n_disks - 1
    if n_data * chunk_bytes == 0:
        return False
    test_stripes = max(n_disks * 2, 16 * 1024 * 1024 // (n_data * chunk_bytes))

    with ExitStack() as stack:
        fds: dict[int, object] = {}
        for i, p in enumerate(ordered_paths):
            if p is not None:
                fds[i] = stack.enter_context(open(p, "rb"))

        tmp_fd, tmp_path = tempfile.mkstemp(suffix=".raw")
        try:
            with os.fdopen(tmp_fd, "wb") as out:
                for stripe in range(test_stripes):
                    pd = (n_disks - 1) - (stripe % n_disks)
                    for dd in range(n_data):
                        disk_idx = (pd + 1 + dd) % n_disks
                        disk_off = data_offset_bytes + stripe * chunk_bytes

                        if disk_idx not in fds:
                            accum = 0
                            for i, fd in fds.items():
                                fd.seek(disk_off)
                                d = fd.read(chunk_bytes)
                                if len(d) < chunk_bytes:
                                    d += b"\x00" * (chunk_bytes - len(d))
                                accum ^= int.from_bytes(d, "little")
                            out.write(accum.to_bytes(chunk_bytes, "little"))
                        else:
                            fds[disk_idx].seek(disk_off)
                            chunk = fds[disk_idx].read(chunk_bytes)
                            if len(chunk) < chunk_bytes:
                                chunk += b"\x00" * (chunk_bytes - len(chunk))
                            out.write(chunk)

            rc, _, _ = run(["fsstat", "-i", "raw", "-o", "0", tmp_path])
            if rc != 0:
                return False
            rc2, fls_out, _ = run(["fls", "-i", "raw", "-o", "0", tmp_path])
            return rc2 == 0 and len(fls_out) > 0
        except OSError:
            return False
        finally:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
