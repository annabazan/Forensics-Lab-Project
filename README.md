# Raidex

Auto-detecting RAID forensic data extraction from E01 disk images.

## Overview

Raidex scans a directory of E01 forensic disk images, auto-detects RAID configurations (Linux md, Windows LDM/Dynamic Disk, hardware RAID), groups related disks, reconstructs arrays, and extracts user data. It supports RAID 0, 1, and 5 with left-symmetric layout for RAID 5. No prior knowledge of which disks belong together or what RAID parameters are used is required — the tool figures it out.

## Forensic Methodology

Raidex is designed to operate within a standard digital forensics workflow:

- **Evidence acquisition**: Expects E01 (Expert Witness Format) images — the standard forensic imaging format that preserves integrity via internal checksums. The tool operates read-only on FUSE-mounted images and never modifies the original evidence.

- **Chain of custody**: All operations are non-destructive. E01 images are mounted read-only via `ewfmount`. Intermediate reconstructed images can be retained with `--keep-raw` for independent verification. No original evidence is altered at any point.

- **Tool validation**: The included test data generator (`gen_test_data.sh`) creates known-good RAID configurations with planted evidence files. Running the tool against test data validates correct reconstruction before applying to real evidence. Unit tests verify parser correctness against crafted binary fixtures.

- **Reproducibility**: Given the same E01 inputs, the tool produces deterministic output. All detected RAID parameters (level, stripe size, disk order, data offsets) are logged. Manual overrides (`--hw-*` flags) allow re-running with specific parameters for verification.

- **Audit trail**: The tool logs each phase of operation — which disks were classified as what type, how they were grouped, what RAID parameters were detected or assumed, and what files were extracted. Verbose mode (`-v`) provides additional detail for forensic reports.

## Technical Methodology

### Detection Pipeline

The tool operates in three phases:

**Phase 1 — Mount & Classify.** Each E01 image is FUSE-mounted via `ewfmount` to expose the raw disk bytes. Each disk is then probed in priority order:

1. **Linux md RAID**: Parse the md superblock v1.2 at byte offset 4096 (or inside partitions via a GPT/MBR scan). Extract the array UUID, RAID level, layout, chunk size, and this disk's role within the array.

2. **Windows LDM**: Check for the PRIVHEAD signature at sector 6. Parse the VMDB/VBLK database from the last 2 MiB of the disk to extract volume metadata, disk group GUIDs, and per-disk identifiers.

3. **Standalone filesystem**: Run `fsstat` at common partition offsets (sectors 0, 63, 2048) and at partition table entries. Validate with `fls` to confirm the filesystem is readable, not just a superblock fragment.

4. **Unknown**: Disks matching no probe become candidates for hardware RAID detection.

**Phase 2 — Group.** Classified disks are grouped by their metadata:

- md members are grouped by array UUID
- LDM members are grouped by disk group GUID
- Unknown disks are clustered by identical file size (hardware RAID controllers produce same-sized member disks)
- Standalone disks with identical content (sampled at head and tail) are reclassified as RAID 1 mirrors

**Phase 3 — Reconstruct & Extract.** Each group is processed by its handler:

- **md RAID 5**: Disk roles from the superblock determine column order directly. The array is reconstructed using left-symmetric parity layout. Degraded arrays (one missing disk) are rebuilt via XOR of remaining members.

- **LDM RAID 5**: Disk order is determined by matching per-disk GUIDs from the PRIVHEAD against VMDB Disk records ("Disk1", "Disk2", etc.). Stripe size is auto-detected by trying common Windows sizes (16–512 KiB) and validating with `fsstat`. Falls back to brute-force permutation if VMDB ordering fails.

- **Hardware RAID** (no metadata): With no on-disk metadata available, the tool brute-forces all combinations of disk permutations, stripe sizes, and data offsets. Each candidate configuration is validated by reconstructing the first ~16 MiB and checking for a valid filesystem. The search order is: RAID 5 (full) → RAID 0 → degraded RAID 5. For 2-disk groups, RAID 1 is tried first.

- **Standalone volumes**: Files are extracted directly using `fls`/`icat`.

### RAID Reconstruction Algorithms

**RAID 0** (striping): Chunks are interleaved from each disk in column order. For N disks with chunk size C, stripe S reads: disk[0] at offset S×C, disk[1] at offset S×C, ..., disk[N-1] at offset S×C. Output size = N × per-disk data size.

**RAID 1** (mirroring): Data is read directly from any available mirror member. No reconstruction needed.

**RAID 5** (striping + distributed parity): Left-symmetric layout with rotating parity. For N disks and stripe S:
- Parity disk: `(N - 1) - (S mod N)`
- Data chunks start from disk `(parity + 1) mod N`
- Missing disks are rebuilt via XOR: `missing_chunk = XOR(all other chunks at same stripe offset)`

### Partition Table Support

- **MBR**: Parsed via sleuthkit's `mmls`
- **GPT**: Pure-Python parser reads the GPT header at LBA 1 and partition entries at LBA 2+. No external tools required. Used as fallback when `mmls` fails.

### Filesystem Detection

Two layers of detection:
1. **Raw signature scan**: Checks magic bytes for NTFS (offset 3), ext2/3/4 (superblock magic 0xEF53 at offset 1080), FAT32/FAT16 (boot sector strings)
2. **Tool validation**: `fsstat` confirms the filesystem is structurally valid; `fls` confirms it's readable

## Requirements

### Python

- Python 3.14+
- No third-party runtime dependencies (stdlib only)
- `pytest` for running tests

### System Tools

- `ewfmount` / `fusermount` (libewf) — FUSE-based E01 image mounting
- `fls`, `icat`, `mmls`, `fsstat` (sleuthkit) — filesystem analysis and extraction
- No root/sudo required (ewfmount uses FUSE user mounts)

### Test Data Generation (optional)

- `mdadm` — Linux software RAID management
- `ewfacquire` (libewf) — E01 image creation
- `mkfs.ext4`, `mkfs.fat` — filesystem creation
- `sfdisk`, `sgdisk` — partition table creation
- Root access required for `gen_test_data.sh`

## Installation

```bash
# Install system dependencies (Fedora/RHEL)
sudo dnf install libewf-tools sleuthkit

# Install system dependencies (Debian/Ubuntu)
sudo apt install ewf-tools sleuthkit

# Install the tool
uv sync
```

## Usage

```bash
# Basic — scan current directory for E01 files
detect-raids

# Specify input and output
detect-raids /path/to/evidence -o /path/to/output

# Keep intermediate reconstructed images for verification
detect-raids evidence/ --keep-raw

# Verbose logging (debug level)
detect-raids evidence/ -v

# Quiet mode (warnings only)
detect-raids evidence/ -q

# Override hardware RAID detection parameters
detect-raids evidence/ \
    --hw-raid-level 5 \
    --hw-stripe 64 \
    --hw-order disk_A.E01,disk_B.E01,disk_C.E01 \
    --hw-offset 2048

# Run as Python module
python -m raidex /path/to/evidence
```

### CLI Reference

| Flag | Description |
|------|-------------|
| `input_dir` | Directory containing E01 files (default: `.`) |
| `-o`, `--output` | Output directory (default: `<input_dir>/auto_extracted`) |
| `--keep-raw` | Retain intermediate raw RAID images |
| `--hw-raid-level` | Force RAID level for unknown disks (0, 1, or 5) |
| `--hw-stripe` | Force stripe size in KiB |
| `--hw-order` | Force disk order (comma-separated E01 filenames) |
| `--hw-offset` | Force data offset in sectors |
| `-v`, `--verbose` | Debug-level logging |
| `-q`, `--quiet` | Warning-level logging only |

## Testing

```bash
# Run unit tests
uv run pytest tests/ -v

# Generate test data (requires root + mdadm + ewfacquire)
sudo ./gen_test_data.sh

# End-to-end validation against test data
detect-raids test_data/
```

### Test Coverage

| Module | What's Tested |
|--------|--------------|
| `parsers/filesystem` | FS signature detection (NTFS, ext, FAT32, FAT16) |
| `parsers/partition` | GPT parser with crafted binary fixtures |
| `probes/md` | md superblock v1.2 parsing from raw bytes |
| `probes/ldm` | LDM PRIVHEAD parsing and GUID extraction |
| `probes/hardware` | Hardware RAID grouping, standalone mirror detection |
| `reconstruction/raid0` | Chunk interleaving across synthetic disks |
| `reconstruction/raid5` | Left-symmetric reconstruction + degraded rebuild via XOR |

## Project Structure

```
raidex/
├── cli.py              # Command-line interface and logging setup
├── pipeline.py         # 3-phase orchestrator (mount → classify → group → extract)
├── mounting.py         # E01 image mounting via ewfmount (FUSE)
├── probes/             # Disk type detection
│   ├── md.py           #   Linux md superblock v1.2
│   ├── ldm.py          #   Windows LDM PRIVHEAD + VMDB/VBLK
│   ├── standalone.py   #   Standalone filesystem detection
│   └── hardware.py     #   Hardware RAID brute-force detection
├── handlers/           # Group processing and extraction
│   ├── md.py           #   md RAID 5 reconstruction + extraction
│   ├── ldm.py          #   LDM volume/RAID handling
│   ├── standalone.py   #   Direct extraction
│   └── hardware.py     #   Hardware RAID reconstruction
├── reconstruction/     # RAID array reassembly
│   ├── raid0.py        #   Stripe interleaving
│   ├── raid1.py        #   Mirror read
│   └── raid5.py        #   Left-symmetric parity reconstruction
├── parsers/            # Low-level binary parsing
│   ├── partition.py    #   MBR (via mmls) + GPT (pure Python)
│   └── filesystem.py   #   Raw signature detection
├── extraction.py       # File recovery via sleuthkit fls/icat
├── util.py             # Shared helpers and constants
└── types.py            # TypedDict definitions
```
