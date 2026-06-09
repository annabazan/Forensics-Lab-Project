# AGENTS.md

This file provides guidance to LLM when working with code in this repository.

## Project Overview

Forensic tool that auto-detects RAID configurations from E01 disk images, reconstructs arrays, and extracts user data. Targets Linux md RAID, Windows LDM/Dynamic Disk, and hardware RAID controllers (RAID 0/1/5, left-symmetric layout for RAID 5). No prior knowledge of disk grouping or RAID parameters required.

## Commands

```bash
# Run directly
uv run detect-raids [input_dir] [-o output_dir] [--keep-raw] [-v] [-q]

# Or via module
uv run python -m raidex [input_dir] [-o output_dir]

# Run tests
uv run pytest tests/
```

Validation: `sudo ./gen_test_data.sh` generates `test_data/` with E01 files, then `uv run detect-raids test_data/` runs the full pipeline.

## System Dependencies

Requires these CLI tools on PATH (not Python packages):
- `ewfmount` / `fusermount` — from libewf, for mounting E01 images via FUSE
- `fls`, `icat`, `mmls`, `fsstat` — from sleuthkit, for filesystem traversal

## Architecture

The `raidex/` package runs a 3-phase pipeline:

1. **Mount & Classify** (`pipeline.py` + `probes/`) — each E01 is FUSE-mounted via `EwfMount`, then probed: `probe_md()` -> `probe_ldm()` -> `probe_standalone()` -> unknown.

2. **Group** (`pipeline.py` + `probes/hardware.py`) — disks grouped by md UUID, LDM GUID, or file size (hardware RAID). Standalone mirrors detected by content comparison.

3. **Reconstruct & Extract** (`handlers/` + `reconstruction/` + `extraction.py`) — each group dispatched to its handler, which reconstructs the array and extracts files.

### Module Map

- `cli.py` — argparse, logging setup, entry point
- `pipeline.py` — 3-phase orchestrator, ExitStack for mount lifecycle
- `mounting.py` — EwfMount context manager
- `probes/` — disk type detection (md superblock, LDM PRIVHEAD/VMDB, standalone FS, hardware brute-force)
- `handlers/` — group processing (md, ldm, standalone, hardware)
- `reconstruction/` — RAID 0/5 data reassembly, order validation
- `parsers/` — partition tables (mmls + GPT), filesystem signatures
- `extraction.py` — fls/icat file extraction
- `util.py` — shared helpers, constants
- `types.py` — TypedDicts for classified disk data

### Dependency Flow

```
cli -> pipeline -> handlers -> {reconstruction, extraction, probes}
                            -> parsers
                   probes -> parsers
                   reconstruction -> util (for subprocess)
                   all modules -> util
```

## Conventions

- Python 3.14+, stdlib only (no third-party runtime deps)
- `uv` for package management, `pytest` for testing
- All subprocess calls go through `util.run()`
- Filesystem detection uses raw byte signatures, not external tools
- Logging via `logging` module; `print()` only for transient progress bars
- Type hints throughout; TypedDicts for classified disk data
