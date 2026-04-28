# AGENTS.md

This file provides guidance to LLM when working with code in this repository.

## Project Overview

Single-file forensic tool that auto-detects RAID configurations from E01 disk images, reconstructs arrays, and extracts user data. Targets Linux md RAID and Windows LDM/Dynamic Disk (RAID 5, left-symmetric layout). No prior knowledge of disk grouping or RAID parameters required.

## Commands

```bash
# Run directly
python detect_and_extract_raids.py [input_dir] [-o output_dir] [--keep-raw]

# Or via installed entry point (after uv sync)
uv sync
detect-raids [input_dir] [-o output_dir] [--keep-raw]
```

No test suite exists.

## System Dependencies

Requires these CLI tools on PATH (not Python packages):
- `ewfmount` / `fusermount` — from libewf, for mounting E01 images via FUSE
- `fls`, `icat`, `mmls`, `fsstat` — from sleuthkit, for filesystem traversal and extraction

## Architecture

Everything lives in `detect_and_extract_raids.py`. The pipeline runs in three phases:

1. **Mount & Classify** — each E01 is FUSE-mounted via `EwfMount` context manager, then probed in order: `probe_md()` → `probe_ldm()` → `probe_standalone()`. Classification determines disk type.

2. **Group** — disks are grouped by md UUID or LDM disk-group GUID.

3. **Reconstruct & Extract** — `handle_md_group()` or `handle_ldm_group()` reconstructs RAID 5 via `reconstruct_raid5_left_symmetric()`, then `extract_files_from_image()` pulls files using sleuthkit's fls/icat.

Key internals:
- md superblock v1.2 is parsed from raw bytes at offset 4096 (`probe_md`)
- LDM PRIVHEAD is at sector 6; VMDB/VBLK database is parsed from the last 2 MiB of disk (`parse_ldm_vmdb`)
- Disk ordering: md uses role from superblock; LDM matches per-disk GUIDs from PRIVHEAD against VMDB Disk records. Falls back to brute-force permutation if VMDB fails.
- Degraded arrays (one missing disk) are rebuilt via XOR of remaining disks during reconstruction
- Stripe size auto-detection tries common Windows sizes (16–512 KiB) against fsstat validation

## Conventions

- Python 3.14+, stdlib only (no third-party Python dependencies)
- `uv` for package management
- All subprocess calls go through the `run()` helper
- Filesystem detection uses raw byte signatures, not external tools
