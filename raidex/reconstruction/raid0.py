"""RAID 0 reconstruction — interleave chunks across disks."""

from __future__ import annotations

import logging
import os
import sys
import tempfile
from contextlib import ExitStack

from raidex.util import run

logger = logging.getLogger(__name__)


def reconstruct_raid0(
    disk_files: list[str],
    chunk_bytes: int,
    data_offset_bytes: int,
    data_size_sectors: int,
    output_path: str,
) -> None:
    """Reconstruct a RAID 0 array by interleaving chunks across disks."""
    n_disks = len(disk_files)
    total_data_bytes = data_size_sectors * 512 * n_disks

    logger.info(
        "    RAID-0: %d disks, %d KiB chunk, data offset %d bytes",
        n_disks,
        chunk_bytes // 1024,
        data_offset_bytes,
    )
    logger.info(
        "    Total RAID volume size: %.2f GiB",
        total_data_bytes / 1024 / 1024 / 1024,
    )

    sectors_per_chunk = chunk_bytes // 512
    num_stripes = data_size_sectors // sectors_per_chunk
    report_interval = max(1, num_stripes // 20)

    with ExitStack() as stack:
        fds = [stack.enter_context(open(path, "rb")) for path in disk_files]

        with open(output_path, "wb") as out:
            bytes_written = 0
            for stripe in range(num_stripes):
                for disk_idx in range(n_disks):
                    disk_off = data_offset_bytes + stripe * chunk_bytes
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


def test_raid0_order(
    ordered_paths: list[str | None],
    chunk_bytes: int,
    data_offset_bytes: int,
    n_disks: int,
) -> bool:
    """Reconstruct first ~16 MiB of RAID 0 and check for valid filesystem."""
    if n_disks * chunk_bytes == 0:
        return False
    test_stripes = max(n_disks * 2, 16 * 1024 * 1024 // (n_disks * chunk_bytes))

    with ExitStack() as stack:
        fds: dict[int, object] = {}
        for i, p in enumerate(ordered_paths):
            if p is not None:
                fds[i] = stack.enter_context(open(p, "rb"))

        tmp_fd, tmp_path = tempfile.mkstemp(suffix=".raw")
        try:
            with os.fdopen(tmp_fd, "wb") as out:
                for stripe in range(test_stripes):
                    for disk_idx in range(n_disks):
                        disk_off = data_offset_bytes + stripe * chunk_bytes
                        if disk_idx not in fds:
                            out.write(b"\x00" * chunk_bytes)
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
