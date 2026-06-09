"""Command-line interface for raidex."""

from __future__ import annotations

import argparse
import logging
import os

from raidex.pipeline import run_pipeline


def main() -> None:
    """Entry point for the detect-raids CLI command."""
    parser = argparse.ArgumentParser(
        description="Auto-detect and extract data from RAID E01 forensic images"
    )
    parser.add_argument(
        "input_dir",
        nargs="?",
        default=".",
        help="Directory containing E01 files (default: current dir)",
    )
    parser.add_argument(
        "-o", "--output", default=None, help="Output directory"
    )
    parser.add_argument(
        "--keep-raw", action="store_true", help="Keep intermediate raw RAID images"
    )
    parser.add_argument(
        "--hw-raid-level",
        type=int,
        choices=[0, 1, 5],
        help="Force RAID level for unknown disks",
    )
    parser.add_argument(
        "--hw-stripe", type=int, help="Force stripe size in KiB"
    )
    parser.add_argument(
        "--hw-order", help="Force disk order (comma-separated E01 filenames)"
    )
    parser.add_argument(
        "--hw-offset", type=int, help="Force data offset in sectors"
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Verbose output (debug level)"
    )
    parser.add_argument(
        "-q", "--quiet", action="store_true", help="Quiet output (warnings only)"
    )
    args = parser.parse_args()

    # Configure logging
    if args.verbose:
        level = logging.DEBUG
    elif args.quiet:
        level = logging.WARNING
    else:
        level = logging.INFO

    logging.basicConfig(
        level=level,
        format="%(message)s",
    )

    input_dir = os.path.abspath(args.input_dir)
    output_dir = (
        os.path.abspath(args.output)
        if args.output
        else os.path.join(input_dir, "auto_extracted")
    )

    hw_overrides = None
    if (
        args.hw_raid_level is not None
        or args.hw_stripe
        or args.hw_order
        or args.hw_offset is not None
    ):
        hw_overrides = {
            "level": args.hw_raid_level,
            "stripe": args.hw_stripe,
            "offset": args.hw_offset,
            "order": args.hw_order.split(",") if args.hw_order else None,
        }

    run_pipeline(input_dir, output_dir, args.keep_raw, hw_overrides)
