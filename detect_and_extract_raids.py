#!/usr/bin/env python3
"""
Auto-detecting RAID Forensic Data Extraction
=============================================
Scans a directory of E01 forensic disk images, auto-detects RAID configurations
(Linux md, Windows LDM/Dynamic Disk), groups related disks, reconstructs arrays,
and extracts user data.

Works with a flat directory of E01 files -- no prior knowledge of which disks
belong together or what RAID parameters are used.

Requirements: ewfmount (libewf), fls/icat/mmls/fsstat (sleuthkit), Python 3
No root/sudo required.
"""

import argparse
import glob
import itertools
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile


# ─── Helpers ────────────────────────────────────────────────────────────────

def run(cmd, **kwargs):
    """Run a command, return (returncode, stdout, stderr)."""
    r = subprocess.run(cmd, capture_output=True, **kwargs)
    return r.returncode, r.stdout, r.stderr


class EwfMount:
    """Context manager to mount an E01 image via ewfmount (read-only FUSE)."""

    def __init__(self, e01_path):
        self.e01_path = e01_path
        self.mountpoint = None

    def __enter__(self):
        self.mountpoint = tempfile.mkdtemp(prefix="ewf_")
        rc, _, err = run(["ewfmount", self.e01_path, self.mountpoint])
        if rc != 0:
            os.rmdir(self.mountpoint)
            raise RuntimeError(f"ewfmount failed for {self.e01_path}: {err.decode()}")
        return os.path.join(self.mountpoint, "ewf1")

    def __exit__(self, *exc):
        if self.mountpoint:
            run(["fusermount", "-u", self.mountpoint])
            try:
                os.rmdir(self.mountpoint)
            except OSError:
                pass


def ensure_dir(path):
    os.makedirs(path, exist_ok=True)


# ─── File extraction via Sleuth Kit ────────────────────────────────────────

def extract_files_from_image(image_path, sector_offset, out_dir, image_type="raw"):
    """Use fls/icat to recursively extract user files from a filesystem image."""
    ensure_dir(out_dir)

    type_flag = ["-i", image_type] if image_type else []
    offset_flag = ["-o", str(sector_offset)] if sector_offset else []

    def _extract_dir(inode, rel_path):
        cur_dir = os.path.join(out_dir, rel_path) if rel_path else out_dir
        ensure_dir(cur_dir)
        cmd = ["fls"] + type_flag + offset_flag + [image_path]
        if inode:
            cmd.append(str(inode))
        rc, out, _ = run(cmd)
        if rc != 0:
            return

        for line in out.decode(errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue

            parts = line.split("\t", 1)
            if len(parts) < 2:
                continue
            meta_part = parts[0].strip()
            name = parts[1].strip()

            if name.startswith("$") or name in (".", "..", "(Volume Label Entry)"):
                continue

            tokens = meta_part.split()
            if len(tokens) < 2:
                continue
            type_str = tokens[0]
            inode_str = tokens[1].rstrip(":")

            entry_path = os.path.join(rel_path, name) if rel_path else name

            if type_str.startswith("d/d") or type_str.startswith("d/"):
                _extract_dir(inode_str, entry_path)
            elif type_str.startswith("r/r") or type_str.startswith("r/"):
                dest = os.path.join(out_dir, entry_path)
                cmd2 = ["icat"] + type_flag + offset_flag + [image_path, inode_str]
                rc2, data, _ = run(cmd2)
                if rc2 == 0 and data:
                    with open(dest, "wb") as f:
                        f.write(data)
                    print(f"    Extracted: {entry_path} ({len(data):,} bytes)")

    _extract_dir("", "")


# ─── RAID 5 Reconstruction ─────────────────────────────────────────────────

def reconstruct_raid5_left_symmetric(disk_files, chunk_bytes, data_offset_bytes,
                                     data_size_sectors, output_path,
                                     missing_disk_idx=None):
    """
    Reconstruct a RAID 5 array with left-symmetric layout.

    Parity disk for stripe s: (n - 1) - (s % n).
    Data chunks start from disk (parity + 1) % n.
    Missing disk rebuilt via XOR of remaining disks.
    """
    n_disks = len(disk_files)
    data_disks_count = n_disks - 1
    sectors_per_chunk = chunk_bytes // 512
    total_data_bytes = data_size_sectors * 512 * data_disks_count

    print(f"    RAID-5: {n_disks} disks, {chunk_bytes // 1024} KiB chunk, "
          f"left-symmetric, data offset {data_offset_bytes} bytes")
    print(f"    Total RAID volume size: {total_data_bytes / 1024 / 1024 / 1024:.2f} GiB")
    if missing_disk_idx is not None:
        print(f"    Recovering missing disk index {missing_disk_idx} from parity")

    fds = []
    for path in disk_files:
        fds.append(open(path, "rb") if path is not None else None)

    num_stripes = data_size_sectors // sectors_per_chunk
    report_interval = max(1, num_stripes // 20)

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
                            other += b'\x00' * (chunk_bytes - len(other))
                        accum ^= int.from_bytes(other, 'little')
                    out.write(accum.to_bytes(chunk_bytes, 'little'))
                else:
                    fds[disk_idx].seek(disk_off)
                    chunk = fds[disk_idx].read(chunk_bytes)
                    if len(chunk) < chunk_bytes:
                        chunk += b'\x00' * (chunk_bytes - len(chunk))
                    out.write(chunk)

                bytes_written += chunk_bytes

            if stripe % report_interval == 0 and stripe > 0:
                pct = stripe / num_stripes * 100
                print(f"    Progress: {pct:.0f}%", end="\r", flush=True)

    print(f"    Wrote {bytes_written / 1024 / 1024:.1f} MiB to {os.path.basename(output_path)}")

    for fd in fds:
        if fd:
            fd.close()


# ─── Partition table parsing ───────────────────────────────────────────────

def get_partitions(raw_path):
    """Parse mmls output to find data partitions."""
    rc, out, _ = run(["mmls", "-i", "raw", raw_path])
    if rc != 0:
        return []

    parts = []
    for line in out.decode(errors='replace').splitlines():
        line = line.strip()
        if not line or 'Unallocated' in line or 'Meta' in line:
            continue
        # Match: "002:  000:000   0000000063   0016771859   0016771797   Description"
        m = re.match(r'\d+:\s+\S+\s+(\d+)\s+(\d+)\s+(\d+)\s+(.*)', line)
        if m:
            parts.append({
                'start': int(m.group(1)),
                'end': int(m.group(2)),
                'length': int(m.group(3)),
                'desc': m.group(4).strip(),
            })
    return parts


# ─── Filesystem detection ──────────────────────────────────────────────────

def detect_fs_signature(data):
    """Check raw data for known filesystem signatures."""
    if len(data) > 7 and data[3:7] == b'NTFS':
        bps = struct.unpack_from('<H', data, 11)[0] if len(data) > 12 else 0
        if bps == 512:
            return 'NTFS'
    if len(data) > 1082:
        if struct.unpack_from('<H', data, 1080)[0] == 0xEF53:
            return 'ext'
    if len(data) > 90 and b'FAT32' in data[82:90]:
        return 'FAT32'
    if len(data) > 62 and b'FAT' in data[54:62]:
        return 'FAT16'
    return None


def detect_filesystem(raw_path):
    """Detect filesystem type at the start of a raw image."""
    try:
        with open(raw_path, 'rb') as f:
            header = f.read(4096)
        return detect_fs_signature(header)
    except OSError:
        return None


# ─── Probes ────────────────────────────────────────────────────────────────

def probe_md(raw_path):
    """Check for Linux md superblock v1.2 at offset 4096.

    mdp_superblock_1 layout (all little-endian):
      +0:   magic (0xa92b4efc)
      +4:   major_version (1)
      +16:  set_uuid[16]
      +72:  level (0=RAID0, 1=RAID1, 5=RAID5, ...)
      +76:  layout (2=left-symmetric for RAID5)
      +88:  chunksize (in 512-byte sectors)
      +92:  raid_disks
      +128: data_offset (sectors)
      +136: data_size (sectors)
      +160: dev_number
      +220: max_dev
      +256: dev_roles[max_dev] (LE16 each)
    """
    try:
        with open(raw_path, 'rb') as f:
            f.seek(4096)
            sb = f.read(512)

        magic = struct.unpack_from('<I', sb, 0)[0]
        if magic != 0xa92b4efc:
            return None

        set_uuid = sb[16:32]
        level = struct.unpack_from('<I', sb, 72)[0]
        layout = struct.unpack_from('<I', sb, 76)[0]
        chunk_sectors = struct.unpack_from('<I', sb, 88)[0]
        raid_disks = struct.unpack_from('<I', sb, 92)[0]
        data_offset = struct.unpack_from('<Q', sb, 128)[0]
        data_size = struct.unpack_from('<Q', sb, 136)[0]
        dev_number = struct.unpack_from('<I', sb, 160)[0]
        max_dev = struct.unpack_from('<I', sb, 220)[0]

        with open(raw_path, 'rb') as f:
            f.seek(4096 + 256)
            roles_raw = f.read(max_dev * 2)
        roles = [struct.unpack_from('<H', roles_raw, i * 2)[0] for i in range(max_dev)]
        role = roles[dev_number] if dev_number < len(roles) else 0xFFFF

        uuid_hex = set_uuid.hex()
        uuid_str = (f"{uuid_hex[:8]}-{uuid_hex[8:12]}-{uuid_hex[12:16]}"
                    f"-{uuid_hex[16:20]}-{uuid_hex[20:]}")

        return {
            'uuid': uuid_str,
            'level': level,
            'layout': layout,
            'chunk_sectors': chunk_sectors,
            'raid_disks': raid_disks,
            'data_offset_sectors': data_offset,
            'data_size_sectors': data_size,
            'dev_number': dev_number,
            'role': role,
        }
    except (OSError, struct.error):
        return None


def _find_guid(data):
    """Find a GUID pattern in binary data."""
    text = data.decode('ascii', errors='replace')
    m = re.search(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
                  text, re.I)
    return m.group(0).lower() if m else None


def probe_ldm(raw_path):
    """Check for Windows LDM PRIVHEAD at sector 6.

    PRIVHEAD layout:
      0x00: "PRIVHEAD" signature
      0x30: Per-disk GUID (unique per disk, 64-byte null-terminated ASCII)
      0x70: Host GUID (same across host)
      0xB0: Disk Group GUID (same for all disks in the group)
    """
    try:
        with open(raw_path, 'rb') as f:
            f.seek(6 * 512)
            hdr = f.read(512)

        if hdr[:8] != b'PRIVHEAD':
            return None

        # Disk group GUID at offset 0xB0 (176)
        group_guid = hdr[0xB0:0xF0].split(b'\x00')[0].decode('ascii', errors='replace')
        # Per-disk GUID at offset 0x30 (48)
        per_disk_guid = hdr[0x30:0x70].split(b'\x00')[0].decode('ascii', errors='replace')

        # Validate they look like GUIDs
        guid_re = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.I)
        if not guid_re.match(group_guid):
            return None

        return {
            'disk_group_guid': group_guid.lower(),
            'per_disk_guid': per_disk_guid.lower() if guid_re.match(per_disk_guid) else None,
        }
    except OSError:
        return None


def probe_standalone(raw_path):
    """Try to identify a standalone filesystem at common offsets.

    Also checks partition table for non-LDM partitions (e.g. extended
    partitions with NTFS/FAT inside).
    """
    # First try common fixed offsets
    for offset in (63, 0, 2048):
        rc, out, _ = run(["fsstat", "-i", "raw", "-o", str(offset), raw_path])
        if rc == 0:
            fs_type = None
            for line in out.decode(errors='replace').splitlines():
                if 'File System Type' in line:
                    fs_type = line.split(':', 1)[1].strip()
                    break
            return {'fs_offset': offset, 'fs_type': fs_type}

    # If no FS at common offsets, check partition table for data partitions
    parts = get_partitions(raw_path)
    for p in parts:
        rc, out, _ = run(["fsstat", "-i", "raw", "-o", str(p['start']), raw_path])
        if rc == 0:
            fs_type = None
            for line in out.decode(errors='replace').splitlines():
                if 'File System Type' in line:
                    fs_type = line.split(':', 1)[1].strip()
                    break
            return {'fs_offset': p['start'], 'fs_type': fs_type}

    return None


# ─── LDM VMDB/VBLK Parser ─────────────────────────────────────────────────

def _read_var(buf, pos):
    """Read a length-prefixed field from VBLK body."""
    if pos >= len(buf):
        return b'', pos
    ln = buf[pos]
    end = pos + 1 + ln
    return buf[pos + 1:end], end


def _read_var_num(buf, pos):
    """Read length-prefixed big-endian integer."""
    data, pos = _read_var(buf, pos)
    return int.from_bytes(data, 'big') if data else 0, pos


def _read_var_str(buf, pos):
    """Read length-prefixed ASCII string."""
    data, pos = _read_var(buf, pos)
    return data.decode('ascii', errors='replace').rstrip('\x00'), pos


def parse_ldm_vmdb(raw_path):
    """Parse LDM VMDB/VBLK database from end of disk.

    Returns dict with 'volumes', 'components', 'partitions', 'disks' lists,
    or None if VMDB not found.
    """
    try:
        disk_size = os.path.getsize(raw_path)
        region_size = min(disk_size, 2 * 1024 * 1024)

        with open(raw_path, 'rb') as f:
            f.seek(disk_size - region_size)
            data = f.read(region_size)

        vmdb_off = data.find(b'VMDB')
        if vmdb_off < 0:
            return None

        vblk_size = struct.unpack_from('>I', data, vmdb_off + 8)[0]
        if vblk_size == 0 or vblk_size > 4096:
            vblk_size = 128

        records = {'volumes': [], 'components': [], 'partitions': [], 'disks': []}

        pos = vmdb_off
        while pos + vblk_size <= len(data):
            if data[pos:pos + 4] == b'VBLK':
                _parse_vblk(data, pos, vblk_size, records)
            pos += vblk_size

        return records if any(records.values()) else None
    except OSError:
        return None


def _parse_vblk(data, offset, vblk_size, records):
    """Parse a single VBLK record.

    VBLK type codes (from LDM on-disk format):
      0x32 = Component (CMP3)
      0x33 = Partition (PRT3)
      0x34 = Disk (DISK3/4)
      0x35 = Disk Group (DGRP3)
      0x51 = Volume (VOL5)
    """
    rec = data[offset:offset + vblk_size]
    if len(rec) < 0x18:
        return

    rec_type = rec[0x13]
    body = rec[0x18:]

    try:
        if rec_type == 0x51:    # Volume
            _parse_vblk_volume(body, records)
        elif rec_type == 0x34:  # Disk
            _parse_vblk_disk(body, records)
        elif rec_type == 0x33:  # Partition
            _parse_vblk_partition(body, records)
    except (IndexError, struct.error, ValueError):
        pass


def _parse_vblk_volume(body, records):
    pos = 0
    objid, pos = _read_var_num(body, pos)
    name, pos = _read_var_str(body, pos)
    vol_type, pos = _read_var_str(body, pos)
    records['volumes'].append({'id': objid, 'name': name, 'type': vol_type})


def _parse_vblk_disk(body, records):
    """Parse Disk VBLK (type 0x34).

    Body at offset 0x18:
      [vnum: object_id] [vstr: name e.g. "Disk1"]
      [vstr: per-disk GUID e.g. "fe3079a9-24f6-..."]
    """
    pos = 0
    objid, pos = _read_var_num(body, pos)
    name, pos = _read_var_str(body, pos)
    guid, pos = _read_var_str(body, pos)
    records['disks'].append({
        'id': objid, 'name': name,
        'guid': guid.lower() if guid else '',
    })


def _parse_vblk_partition(body, records):
    """Parse Partition VBLK (type 0x33).

    Extract disk_id, component_id and volume offset by scanning for the
    two trailing vnum fields (component_id, disk_id) near the end of the
    record body.
    """
    pos = 0
    objid, pos = _read_var_num(body, pos)
    name, pos = _read_var_str(body, pos)

    # The rest of the partition body has fixed-length fields we can't easily
    # parse, followed by: [vnum: size] [vnum: component_id] [vnum: disk_id]
    # Scan for this pattern by trying to read vnums from the remaining bytes.
    remaining = body[pos:]

    # Find the last three vnum-like fields before trailing zeros
    # Strategy: find end of meaningful data, then read backwards
    end = len(remaining)
    while end > 0 and remaining[end - 1] == 0:
        end -= 1

    # Try to parse the last vnums from the meaningful region
    # Pattern at end: [vnum: size] [vnum: comp_id] [vnum: disk_id] [0-2 bytes]
    part_info = {'id': objid, 'name': name}
    try:
        # Search backwards for the disk_id vnum (known to be 2-3 bytes + len byte)
        # by trying positions near the end
        for scan_pos in range(max(0, end - 20), end - 2):
            ln = remaining[scan_pos]
            if ln < 1 or ln > 4:
                continue
            if scan_pos + 1 + ln > end:
                continue
            val1 = int.from_bytes(remaining[scan_pos + 1:scan_pos + 1 + ln], 'big')
            next_pos = scan_pos + 1 + ln
            if next_pos >= end:
                continue
            ln2 = remaining[next_pos]
            if ln2 < 1 or ln2 > 4 or next_pos + 1 + ln2 > end:
                continue
            val2 = int.from_bytes(remaining[next_pos + 1:next_pos + 1 + ln2], 'big')
            # Check if these look like valid object IDs (> 1000, < 10000)
            if 1000 < val1 < 10000 and 1000 < val2 < 10000:
                part_info['component_id'] = val1
                part_info['disk_id'] = val2
                # Look for size vnum before these
                for size_pos in range(max(0, scan_pos - 10), scan_pos):
                    sln = remaining[size_pos]
                    if sln < 1 or sln > 5:
                        continue
                    if size_pos + 1 + sln == scan_pos:
                        size_val = int.from_bytes(
                            remaining[size_pos + 1:size_pos + 1 + sln], 'big')
                        part_info['size_sectors'] = size_val
                        break
                # Check for volume offset: stored as BE64 at offset 12 in remaining
                if len(remaining) > 20:
                    vol_offset = struct.unpack_from('>Q', remaining, 12)[0]
                    part_info['volume_offset_sectors'] = vol_offset
                break
    except (IndexError, struct.error):
        pass

    records['partitions'].append(part_info)


# ─── RAID Disk Order Detection ─────────────────────────────────────────────

def _test_raid5_order(ordered_paths, chunk_bytes, data_offset_bytes, n_disks):
    """Reconstruct first ~2 MiB of RAID and check for valid filesystem."""
    n_data = n_disks - 1
    if n_data * chunk_bytes == 0:
        return False
    test_stripes = max(n_disks * 2, 2 * 1024 * 1024 // (n_data * chunk_bytes))

    # Pre-open files to avoid repeated open/close
    fds = {}
    for i, p in enumerate(ordered_paths):
        if p is not None:
            fds[i] = open(p, 'rb')

    tmp_fd, tmp_path = tempfile.mkstemp(suffix='.raw')
    try:
        with os.fdopen(tmp_fd, 'wb') as out:
            for stripe in range(test_stripes):
                pd = (n_disks - 1) - (stripe % n_disks)
                for dd in range(n_data):
                    disk_idx = (pd + 1 + dd) % n_disks
                    disk_off = data_offset_bytes + stripe * chunk_bytes

                    if disk_idx not in fds:
                        # Rebuild from XOR of present disks
                        accum = 0
                        for i, fd in fds.items():
                            fd.seek(disk_off)
                            d = fd.read(chunk_bytes)
                            if len(d) < chunk_bytes:
                                d += b'\x00' * (chunk_bytes - len(d))
                            accum ^= int.from_bytes(d, 'little')
                        out.write(accum.to_bytes(chunk_bytes, 'little'))
                    else:
                        fds[disk_idx].seek(disk_off)
                        chunk = fds[disk_idx].read(chunk_bytes)
                        if len(chunk) < chunk_bytes:
                            chunk += b'\x00' * (chunk_bytes - len(chunk))
                        out.write(chunk)

        rc, _, _ = run(["fsstat", "-i", "raw", "-o", "0", tmp_path])
        return rc == 0
    except OSError:
        return False
    finally:
        for fd in fds.values():
            fd.close()
        try:
            os.unlink(tmp_path)
        except OSError:
            pass


def resolve_ldm_disk_order(vmdb, disks):
    """Determine column order from VMDB Disk records + PRIVHEAD per-disk GUIDs.

    VMDB Disk records have names like "Disk1", "Disk2", "Disk3" with GUIDs
    that match the PRIVHEAD per-disk GUID. The disk number gives the column.
    """
    if not vmdb or not vmdb.get('disks'):
        return None

    # Build map: per-disk GUID -> column index (from Disk record name)
    guid_to_column = {}
    for d in vmdb['disks']:
        name = d.get('name', '')
        guid = d.get('guid', '')
        # Extract number from "Disk1", "Disk2", etc.
        m = re.match(r'Disk(\d+)', name)
        if m and guid:
            col = int(m.group(1)) - 1  # Disk1 -> column 0
            guid_to_column[guid] = col

    if not guid_to_column:
        return None

    n_columns = max(guid_to_column.values()) + 1

    # Match physical disks to columns via per-disk GUID
    ordered = [None] * n_columns
    for d in disks:
        per_guid = d.get('per_disk_guid', '')
        if per_guid in guid_to_column:
            col = guid_to_column[per_guid]
            if col < n_columns:
                ordered[col] = d['raw']

    return ordered, n_columns


def detect_disk_order_bruteforce(raw_paths, chunk_bytes, data_offset_bytes,
                                 n_columns):
    """Try all permutations to find correct RAID disk ordering."""
    n_perm = 1
    for i in range(1, len(raw_paths) + 1):
        n_perm *= i
    print(f"    Brute-force: trying {n_perm} permutations...")
    for perm in itertools.permutations(range(len(raw_paths))):
        ordered = [raw_paths[i] for i in perm]
        if _test_raid5_order(ordered, chunk_bytes, data_offset_bytes, n_columns):
            return ordered
    return None


def detect_degraded_disk_order(present_raw_paths, chunk_bytes, data_offset_bytes,
                               n_columns):
    """For degraded RAID, determine column positions of present disks."""
    n_present = len(present_raw_paths)
    if n_columns - n_present != 1:
        print(f"    [!] Cannot handle {n_columns - n_present} missing disks")
        return None, None

    combos = 0
    for missing_col in range(n_columns):
        remaining_cols = [i for i in range(n_columns) if i != missing_col]
        for perm in itertools.permutations(range(n_present)):
            combos += 1
            ordered = [None] * n_columns
            for i, p_idx in enumerate(perm):
                ordered[remaining_cols[i]] = present_raw_paths[p_idx]
            if _test_raid5_order(ordered, chunk_bytes, data_offset_bytes,
                                 n_columns):
                return ordered, missing_col

    print(f"    [!] No valid ordering found ({combos} combinations tried)")
    return None, None


# Common Windows RAID 5 stripe sizes to try (in bytes)
COMMON_STRIPE_SIZES = [
    64 * 1024,   # 64 KiB (Windows default)
    128 * 1024,
    256 * 1024,
    512 * 1024,
    32 * 1024,
    16 * 1024,
]


def detect_stripe_size(ordered_paths, data_offset_bytes, n_columns):
    """Try common stripe sizes and return the one that produces valid FS."""
    for chunk_bytes in COMMON_STRIPE_SIZES:
        if _test_raid5_order(ordered_paths, chunk_bytes, data_offset_bytes,
                             n_columns):
            return chunk_bytes
    return None


# ─── Group Handlers ────────────────────────────────────────────────────────

def handle_md_group(uuid_str, disks, output_dir, keep_raw):
    """Handle a group of Linux md RAID member disks."""
    d0 = disks[0]
    level = d0['level']
    layout = d0['layout']
    chunk_sectors = d0['chunk_sectors']
    raid_disks = d0['raid_disks']
    data_offset = d0['data_offset_sectors']
    data_size = d0['data_size_sectors']

    label = f"md_{uuid_str[:8]}"
    out = os.path.join(output_dir, label)
    ensure_dir(out)

    layout_name = 'left-symmetric' if layout == 2 else f'layout-{layout}'
    print(f"\n  Array UUID: {uuid_str}")
    print(f"  Level: RAID {level}, Layout: {layout} ({layout_name})")
    print(f"  Chunk: {chunk_sectors * 512 // 1024} KiB, Expected members: {raid_disks}")
    print(f"  Data offset: {data_offset} sectors ({data_offset * 512 // 1048576} MiB)")
    print(f"  Data size/disk: {data_size} sectors "
          f"({data_size * 512 / 1073741824:.1f} GiB)")
    print(f"  Present: {len(disks)} disk(s)")

    if level != 5:
        print(f"  [!] Only RAID 5 supported (got RAID {level})")
        return
    if layout != 2:
        print(f"  [!] Only left-symmetric layout supported (got {layout})")
        return

    # Sort disks by role
    ordered_raw = [None] * raid_disks
    for d in disks:
        role = d['role']
        if role < raid_disks:
            ordered_raw[role] = d['raw']
            print(f"    {d['e01']}: role {role}")

    missing_indices = [i for i, p in enumerate(ordered_raw) if p is None]
    missing_idx = None

    if len(missing_indices) > 1:
        print(f"  [!] Too many missing disks ({len(missing_indices)})")
        return
    elif len(missing_indices) == 1:
        missing_idx = missing_indices[0]
        print(f"    Missing: role {missing_idx} (will rebuild from parity)")

    raid_img = os.path.join(out, "raid5_reconstructed.raw")
    print(f"\n  Reconstructing RAID 5...")
    reconstruct_raid5_left_symmetric(
        disk_files=ordered_raw,
        chunk_bytes=chunk_sectors * 512,
        data_offset_bytes=data_offset * 512,
        data_size_sectors=data_size,
        output_path=raid_img,
        missing_disk_idx=missing_idx,
    )

    fs_type = detect_filesystem(raid_img)
    if fs_type:
        print(f"  [+] Detected {fs_type} filesystem")
    else:
        print(f"  [!] No recognized filesystem signature")

    print(f"  Extracting files...")
    extract_files_from_image(raid_img, 0, os.path.join(out, "files"))

    if not keep_raw and os.path.exists(raid_img):
        os.remove(raid_img)
        print(f"  Removed intermediate image")


def handle_ldm_group(guid, disks, output_dir, keep_raw):
    """Handle a group of Windows LDM Dynamic Disk members."""
    label = f"ldm_{guid[:8]}"
    out = os.path.join(output_dir, label)
    ensure_dir(out)

    print(f"\n  Disk Group GUID: {guid}")
    print(f"  Members: {len(disks)} disk(s)")
    for d in disks:
        print(f"    {d['e01']} (per-disk: {d.get('per_disk_guid', '?')[:13]}...)")

    # Step 1: Check if individual disks have standalone filesystems
    # First check at the LDM partition start (sector 63 typically)
    standalone = []
    for d in disks:
        parts = get_partitions(d['raw'])
        for p in parts:
            rc, fsout, _ = run(["fsstat", "-i", "raw", "-o", str(p['start']),
                                d['raw']])
            if rc == 0:
                fs_type = vol_label = None
                for line in fsout.decode(errors='replace').splitlines():
                    if 'File System Type' in line:
                        fs_type = line.split(':', 1)[1].strip()
                    if 'Volume Name' in line or 'Volume Label' in line:
                        vol_label = line.split(':', 1)[1].strip()
                standalone.append({
                    'disk': d, 'offset': p['start'],
                    'fs_type': fs_type,
                    'label': vol_label or d['e01'].replace('.E01', ''),
                })

    # Also check VMDB for multi-volume disks (multiple volumes on one disk)
    if standalone:
        vmdb = parse_ldm_vmdb(disks[0]['raw'])
        if vmdb and vmdb.get('partitions'):
            # Build disk_id -> physical disk mapping
            guid_to_disk = {d.get('per_disk_guid', ''): d for d in disks}
            vmdb_disk_guid = {rec['id']: rec.get('guid', '')
                              for rec in vmdb.get('disks', [])}

            for prt in vmdb['partitions']:
                vol_off = prt.get('volume_offset_sectors', 0)
                disk_id = prt.get('disk_id')
                if not vol_off or not disk_id:
                    continue  # first volume (offset 0) already found above

                # Find which physical disk this partition lives on
                disk_guid = vmdb_disk_guid.get(disk_id, '')
                phys_disk = guid_to_disk.get(disk_guid)
                if not phys_disk:
                    continue

                # Get the LDM partition start from mmls
                disk_parts = get_partitions(phys_disk['raw'])
                if not disk_parts:
                    continue
                ldm_start = disk_parts[0]['start']

                abs_offset = ldm_start + vol_off
                rc, fsout, _ = run(["fsstat", "-i", "raw", "-o",
                                    str(abs_offset), phys_disk['raw']])
                if rc == 0:
                    fs_type = vol_label = None
                    for line in fsout.decode(errors='replace').splitlines():
                        if 'File System Type' in line:
                            fs_type = line.split(':', 1)[1].strip()
                        if 'Volume Name' in line or 'Volume Label' in line:
                            vol_label = line.split(':', 1)[1].strip()
                    standalone.append({
                        'disk': phys_disk, 'offset': abs_offset,
                        'fs_type': fs_type,
                        'label': vol_label or prt.get('name', 'volume'),
                    })

    if standalone:
        print(f"\n  -> Individual volumes (not RAID): {len(standalone)} found")
        for s in standalone:
            safe_label = re.sub(r'[^\w.-]', '_', s['label']).strip('_') or 'volume'
            vol_out = os.path.join(out, safe_label)
            print(f"\n  [{s['disk']['e01']}] {s['fs_type'] or '?'} "
                  f"volume '{s['label']}' at sector {s['offset']}")
            extract_files_from_image(s['disk']['raw'], s['offset'], vol_out)
        return

    # Step 2: No standalone FS → likely RAID. Parse VMDB for details.
    print(f"\n  -> No standalone filesystems found. Analyzing RAID configuration...")

    vmdb = parse_ldm_vmdb(disks[0]['raw'])

    raid_vol = None
    if vmdb:
        for v in vmdb['volumes']:
            print(f"    VMDB Volume: '{v['name']}' type='{v['type']}'")
            if v['type'] == 'raid5':
                raid_vol = v
        for d_rec in vmdb.get('disks', []):
            print(f"    VMDB Disk: '{d_rec['name']}' guid={d_rec['guid'][:20]}...")

    if not raid_vol:
        print(f"    [!] No RAID 5 volume found in VMDB. Assuming RAID 5.")

    # Get partition offset and size from partition table
    parts = get_partitions(disks[0]['raw'])
    if not parts:
        print(f"  [!] No partition table found on disks")
        return

    part = parts[0]
    part_offset_bytes = part['start'] * 512

    # Step 3: Determine disk order from VMDB Disk records + GUID matching
    ordered = None
    n_columns = len(disks)
    missing_idx = None

    result = resolve_ldm_disk_order(vmdb, disks)
    if result:
        ordered, n_columns = result
        present = sum(1 for p in ordered if p is not None)
        missing_indices = [i for i, p in enumerate(ordered) if p is None]
        print(f"\n  Disk order from VMDB: {n_columns} columns, {present} present")
        if len(missing_indices) == 1:
            missing_idx = missing_indices[0]
        elif len(missing_indices) > 1:
            print(f"  [!] Too many missing disks ({len(missing_indices)})")
            return

    # Step 4: Determine stripe size by trying common values
    chunk_bytes = None
    if ordered:
        chunk_bytes = detect_stripe_size(ordered, part_offset_bytes, n_columns)
        if chunk_bytes:
            print(f"  Detected stripe size: {chunk_bytes // 1024} KiB")

    if not chunk_bytes:
        chunk_bytes = 64 * 1024
        print(f"  Using default stripe size: {chunk_bytes // 1024} KiB")

    # Fallback: if VMDB ordering failed, try brute-force permutations
    if not ordered:
        raw_paths = [d['raw'] for d in disks]
        print(f"\n  VMDB disk order unavailable, trying brute-force...")
        ordered = detect_disk_order_bruteforce(
            raw_paths, chunk_bytes, part_offset_bytes, n_columns)
        if not ordered:
            for try_cols in range(len(disks) + 1, len(disks) + 3):
                print(f"  Trying as degraded {try_cols}-disk array...")
                ordered, missing_idx = detect_degraded_disk_order(
                    raw_paths, chunk_bytes, part_offset_bytes, try_cols)
                if ordered:
                    n_columns = try_cols
                    break
        if not ordered:
            print(f"  [!] Could not determine disk order")
            return

    sectors_per_chunk = chunk_bytes // 512
    data_size_sectors = (part['length'] // sectors_per_chunk) * sectors_per_chunk

    print(f"\n  RAID 5 parameters:")
    print(f"    Chunk size: {chunk_bytes // 1024} KiB")
    print(f"    Columns: {n_columns}")
    print(f"    Partition offset: sector {part['start']}")
    print(f"    Data size/disk: {data_size_sectors} sectors "
          f"({data_size_sectors * 512 / 1073741824:.2f} GiB)")
    print(f"    Layout: left-symmetric")

    for i, path in enumerate(ordered):
        if path:
            e01_name = next((d['e01'] for d in disks if d['raw'] == path), '?')
            print(f"    Column {i}: {e01_name}")
        else:
            print(f"    Column {i}: MISSING (rebuild from parity)")

    raid_img = os.path.join(out, "raid5_reconstructed.raw")
    print(f"\n  Reconstructing RAID 5...")
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
        print(f"  [+] Detected {fs_type} filesystem")
    else:
        print(f"  [!] No recognized filesystem signature")

    print(f"  Extracting files...")
    extract_files_from_image(raid_img, 0, os.path.join(out, "files"))

    if not keep_raw and os.path.exists(raid_img):
        os.remove(raid_img)
        print(f"  Removed intermediate image")


# ─── Main ──────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Auto-detect and extract data from RAID E01 forensic images")
    parser.add_argument("input_dir", nargs='?', default=".",
                        help="Directory containing E01 files (default: current dir)")
    parser.add_argument("-o", "--output", default=None,
                        help="Output directory (default: <input_dir>/auto_extracted)")
    parser.add_argument("--keep-raw", action="store_true",
                        help="Keep intermediate raw RAID images")
    args = parser.parse_args()

    input_dir = os.path.abspath(args.input_dir)
    output_dir = (os.path.abspath(args.output) if args.output
                  else os.path.join(input_dir, "auto_extracted"))

    # Check dependencies
    for tool in ["ewfmount", "fusermount", "fls", "icat", "mmls", "fsstat"]:
        if not shutil.which(tool):
            print(f"[!] Required tool not found: {tool}")
            sys.exit(1)

    # Find E01 files (flat directory first, then subdirectories)
    e01_files = sorted(glob.glob(os.path.join(input_dir, "*.E01")))
    if not e01_files:
        e01_files = sorted(glob.glob(os.path.join(input_dir, "**", "*.E01"),
                                     recursive=True))
    if not e01_files:
        print(f"[!] No E01 files found in {input_dir}")
        sys.exit(1)

    # Deduplicate by basename (same file may appear in multiple case dirs)
    seen = {}
    unique_e01 = []
    for path in e01_files:
        name = os.path.basename(path)
        if name not in seen:
            seen[name] = path
            unique_e01.append(path)
    e01_files = unique_e01

    print(f"[*] Found {len(e01_files)} unique E01 image(s) in {input_dir}")
    ensure_dir(output_dir)

    # ── Phase 1: Mount and classify all disks ──

    print(f"\n{'='*60}")
    print("Phase 1: Mounting and classifying disks")
    print(f"{'='*60}")

    mounts = []
    classified = []

    for e01 in e01_files:
        name = os.path.basename(e01)
        print(f"\n[*] {name}")

        m = EwfMount(e01)
        try:
            raw = m.__enter__()
        except RuntimeError as e:
            print(f"  [!] Mount failed: {e}")
            continue
        mounts.append(m)

        # Probe: md → LDM → standalone
        md = probe_md(raw)
        if md:
            print(f"  -> Linux md RAID {md['level']} "
                  f"(UUID {md['uuid'][:13]}..., role {md['role']})")
            classified.append({'class': 'md', 'e01': name, 'raw': raw, **md})
            continue

        ldm = probe_ldm(raw)
        if ldm:
            print(f"  -> Windows LDM (group {ldm['disk_group_guid'][:13]}...)")
            classified.append({'class': 'ldm', 'e01': name, 'raw': raw, **ldm})
            continue

        standalone = probe_standalone(raw)
        if standalone:
            print(f"  -> Standalone {standalone['fs_type']} "
                  f"at sector {standalone['fs_offset']}")
            classified.append({'class': 'standalone', 'e01': name, 'raw': raw,
                               **standalone})
            continue

        print(f"  -> Unknown disk type")
        classified.append({'class': 'unknown', 'e01': name, 'raw': raw})

    if not classified:
        print("\n[!] No disks could be mounted/classified")
        _cleanup(mounts)
        sys.exit(1)

    # ── Phase 2: Group disks ──

    groups = {}
    for d in classified:
        if d['class'] == 'md':
            key = ('md', d['uuid'])
        elif d['class'] == 'ldm':
            key = ('ldm', d['disk_group_guid'])
        elif d['class'] == 'standalone':
            key = ('standalone', d['e01'])
        else:
            key = ('unknown', d['e01'])
        groups.setdefault(key, []).append(d)

    print(f"\n{'='*60}")
    print(f"Phase 2: Identified {len(groups)} disk group(s)")
    print(f"{'='*60}")

    for (gtype, gid), gdisks in groups.items():
        names = ', '.join(d['e01'] for d in gdisks)
        print(f"  [{gtype}] {gid[:20]}... -> {len(gdisks)} disk(s): {names}")

    # ── Phase 3: Reconstruct and extract ──

    print(f"\n{'='*60}")
    print("Phase 3: Reconstruction and extraction")
    print(f"{'='*60}")

    for (gtype, gid), gdisks in groups.items():
        print(f"\n{'='*60}")
        if gtype == 'md':
            print(f"GROUP: Linux md RAID ({len(gdisks)} disk(s))")
            print(f"{'='*60}")
            handle_md_group(gid, gdisks, output_dir, args.keep_raw)

        elif gtype == 'ldm':
            print(f"GROUP: Windows LDM Dynamic Disks ({len(gdisks)} disk(s))")
            print(f"{'='*60}")
            handle_ldm_group(gid, gdisks, output_dir, args.keep_raw)

        elif gtype == 'standalone':
            d = gdisks[0]
            print(f"GROUP: Standalone volume ({d['e01']})")
            print(f"{'='*60}")
            vol_out = os.path.join(output_dir, d['e01'].replace('.E01', ''))
            extract_files_from_image(d['raw'], d['fs_offset'], vol_out)

        else:
            print(f"GROUP: Unknown ({gdisks[0]['e01']})")
            print(f"{'='*60}")
            print(f"  [!] Skipped -- could not determine disk type")

    # ── Cleanup ──

    _cleanup(mounts)

    print(f"\n{'='*60}")
    print(f"Done! Extracted files are in: {output_dir}")
    print(f"{'='*60}")


def _cleanup(mounts):
    for m in reversed(mounts):
        m.__exit__(None, None, None)


if __name__ == "__main__":
    main()
