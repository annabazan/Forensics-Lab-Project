#!/usr/bin/env python3
"""
Auto-detecting RAID Forensic Data Extraction
=============================================
Scans a directory of E01 forensic disk images, auto-detects RAID configurations
(Linux md, Windows LDM/Dynamic Disk, hardware RAID), groups related disks,
reconstructs arrays, and extracts user data.

Supports RAID 0, 1, and 5. Hardware RAID arrays (no on-disk metadata) are
detected by clustering disks of identical size and brute-forcing permutations,
stripe sizes, and data offsets until a valid filesystem is found.

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


def reconstruct_raid0(disk_files, chunk_bytes, data_offset_bytes,
                      data_size_sectors, output_path):
    """Reconstruct a RAID 0 array by interleaving chunks across disks."""
    n_disks = len(disk_files)
    total_data_bytes = data_size_sectors * 512 * n_disks

    print(f"    RAID-0: {n_disks} disks, {chunk_bytes // 1024} KiB chunk, "
          f"data offset {data_offset_bytes} bytes")
    print(f"    Total RAID volume size: {total_data_bytes / 1024 / 1024 / 1024:.2f} GiB")

    fds = [open(path, "rb") for path in disk_files]

    sectors_per_chunk = chunk_bytes // 512
    num_stripes = data_size_sectors // sectors_per_chunk
    report_interval = max(1, num_stripes // 20)

    with open(output_path, "wb") as out:
        bytes_written = 0
        for stripe in range(num_stripes):
            for disk_idx in range(n_disks):
                disk_off = data_offset_bytes + stripe * chunk_bytes
                fds[disk_idx].seek(disk_off)
                chunk = fds[disk_idx].read(chunk_bytes)
                if len(chunk) < chunk_bytes:
                    chunk += b'\x00' * (chunk_bytes - len(chunk))
                out.write(chunk)
                bytes_written += chunk_bytes

            if stripe % report_interval == 0 and stripe > 0:
                pct = stripe / num_stripes * 100
                print(f"    Progress: {pct:.0f}%", end="\r", flush=True)

    print(f"    Wrote {bytes_written / 1024 / 1024:.1f} MiB to "
          f"{os.path.basename(output_path)}")

    for fd in fds:
        fd.close()


# ─── Partition table parsing ───────────────────────────────────────────────

def get_partitions(raw_path):
    """Parse partition table via mmls, with pure-Python GPT fallback."""
    parts = _get_partitions_mmls(raw_path)
    if parts:
        return parts
    return _get_partitions_gpt(raw_path)


def _get_partitions_mmls(raw_path):
    rc, out, _ = run(["mmls", "-i", "raw", raw_path])
    if rc != 0:
        return []
    parts = []
    for line in out.decode(errors='replace').splitlines():
        line = line.strip()
        if not line or 'Unallocated' in line or 'Meta' in line:
            continue
        m = re.match(r'\d+:\s+\S+\s+(\d+)\s+(\d+)\s+(\d+)\s+(.*)', line)
        if m:
            parts.append({
                'start':  int(m.group(1)),
                'end':    int(m.group(2)),
                'length': int(m.group(3)),
                'desc':   m.group(4).strip(),
            })
    return parts


def _get_partitions_gpt(raw_path):
    """GPT parser — no external tools needed.

    GPT layout:
      LBA 0  = Protective MBR
      LBA 1  = GPT Header
        +0:  signature "EFI PART" (8 bytes)
        +72: partition entry start LBA (LE64)
        +80: number of partition entries (LE32)
        +84: size of each entry (LE32)
      LBA 2+ = Partition entries (128 bytes each by default)
        +0:  type GUID (16 bytes) — all zeros = unused
        +32: start LBA (LE64)
        +40: end LBA (LE64)
        +56: name (72 bytes UTF-16LE)
    """
    try:
        with open(raw_path, 'rb') as f:
            # GPT header at LBA 1
            f.seek(512)
            header = f.read(512)

        if header[:8] != b'EFI PART':
            return []

        num_entries  = struct.unpack_from('<I', header, 80)[0]
        entry_size   = struct.unpack_from('<I', header, 84)[0]
        entries_lba  = struct.unpack_from('<Q', header, 72)[0]

        if entry_size == 0 or num_entries > 128:
            return []

        with open(raw_path, 'rb') as f:
            f.seek(entries_lba * 512)
            entries_data = f.read(num_entries * entry_size)

        parts = []
        for i in range(num_entries):
            entry = entries_data[i * entry_size:(i + 1) * entry_size]
            if len(entry) < 56:
                continue

            type_guid = entry[0:16]
            if type_guid == b'\x00' * 16:
                continue  # unused entry

            start_lba = struct.unpack_from('<Q', entry, 32)[0]
            end_lba   = struct.unpack_from('<Q', entry, 40)[0]
            length    = end_lba - start_lba + 1

            try:
                name = entry[56:128].decode('utf-16-le').rstrip('\x00')
            except UnicodeDecodeError:
                name = ''

            parts.append({
                'start':  start_lba,
                'end':    end_lba,
                'length': length,
                'desc':   name,
            })

        return parts

    except (OSError, struct.error):
        return []


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
    """Check for Linux md superblock v1.x at multiple possible offsets."""

    result = _read_md_superblock(raw_path, byte_offset=4096)
    if result:
        return result

    parts = get_partitions(raw_path)
    for p in parts:
        part_byte_offset = p['start'] * 512 + 4096
        result = _read_md_superblock(raw_path, byte_offset=part_byte_offset)
        if result:
            result['partition_byte_offset'] = p['start'] * 512
            return result

    try:
        file_size = os.path.getsize(raw_path)
    except OSError:
        return None

    scan_limit = min(32 * 1024 * 1024, file_size)
    step = 512 * 512  # 256 KiB

    for offset in range(step, scan_limit, step):
        result = _read_md_superblock(raw_path, byte_offset=offset + 4096)
        if result:
            result['partition_byte_offset'] = offset
            return result

    return None


def _read_md_superblock(raw_path, byte_offset):
    """Read and parse md superblock v1.2 at given byte offset."""
    try:
        with open(raw_path, 'rb') as f:
            f.seek(byte_offset)
            sb = f.read(512)

        if len(sb) < 512:
            return None

        magic = struct.unpack_from('<I', sb, 0)[0]
        if magic != 0xa92b4efc:
            return None

        set_uuid     = sb[16:32]
        level        = struct.unpack_from('<I', sb, 72)[0]
        layout       = struct.unpack_from('<I', sb, 76)[0]
        chunk_sectors = struct.unpack_from('<I', sb, 88)[0]
        raid_disks   = struct.unpack_from('<I', sb, 92)[0]
        data_offset  = struct.unpack_from('<Q', sb, 128)[0]
        data_size    = struct.unpack_from('<Q', sb, 136)[0]
        dev_number   = struct.unpack_from('<I', sb, 160)[0]
        max_dev      = struct.unpack_from('<I', sb, 220)[0]

        with open(raw_path, 'rb') as f:
            f.seek(byte_offset + 256)
            roles_raw = f.read(max_dev * 2)
        roles = [struct.unpack_from('<H', roles_raw, i * 2)[0]
                 for i in range(max_dev)]
        role = roles[dev_number] if dev_number < len(roles) else 0xFFFF

        uuid_hex = set_uuid.hex()
        uuid_str = (f"{uuid_hex[:8]}-{uuid_hex[8:12]}-{uuid_hex[12:16]}"
                    f"-{uuid_hex[16:20]}-{uuid_hex[20:]}")

        return {
            'uuid':                uuid_str,
            'level':               level,
            'layout':              layout,
            'chunk_sectors':       chunk_sectors,
            'raid_disks':          raid_disks,
            'data_offset_sectors': data_offset,
            'data_size_sectors':   data_size,
            'dev_number':          dev_number,
            'role':                role,
            'sb_byte_offset':      byte_offset,
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


def _probe_fs_at_offset(raw_path, offset):
    """Probe for a valid filesystem at the given sector offset.

    Runs fsstat to check for a superblock, then fls to verify the
    filesystem is actually readable (not just a superblock fragment
    from a RAID 0 member disk).
    """
    rc, out, _ = run(["fsstat", "-i", "raw", "-o", str(offset), raw_path])
    if rc != 0:
        return None
    fs_type = None
    for line in out.decode(errors='replace').splitlines():
        if 'File System Type' in line:
            fs_type = line.split(':', 1)[1].strip()
            break
    rc2, out2, _ = run(["fls", "-i", "raw", "-o", str(offset), raw_path])
    if rc2 != 0 or not out2.strip():
        return None
    return {'fs_offset': offset, 'fs_type': fs_type}


def probe_standalone(raw_path):
    """Try to identify a standalone filesystem at common offsets.

    Also checks partition table for non-LDM partitions (e.g. extended
    partitions with NTFS/FAT inside).
    """
    # First try common fixed offsets
    for offset in (63, 0, 2048):
        result = _probe_fs_at_offset(raw_path, offset)
        if result:
            return result

    # If no FS at common offsets, check partition table for data partitions
    parts = get_partitions(raw_path)
    for p in parts:
        result = _probe_fs_at_offset(raw_path, p['start'])
        if result:
            return result

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
    """Reconstruct first ~16 MiB of RAID and check for valid filesystem."""
    n_data = n_disks - 1
    if n_data * chunk_bytes == 0:
        return False
    test_stripes = max(n_disks * 2, 16 * 1024 * 1024 // (n_data * chunk_bytes))

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
        if rc != 0:
            return False
        rc2, fls_out, _ = run(["fls", "-i", "raw", "-o", "0", tmp_path])
        return rc2 == 0 and len(fls_out) > 0
    except OSError:
        return False
    finally:
        for fd in fds.values():
            fd.close()
        try:
            os.unlink(tmp_path)
        except OSError:
            pass


def _test_raid0_order(ordered_paths, chunk_bytes, data_offset_bytes, n_disks):
    """Reconstruct first ~16 MiB of RAID 0 and check for valid filesystem."""
    if n_disks * chunk_bytes == 0:
        return False
    test_stripes = max(n_disks * 2, 16 * 1024 * 1024 // (n_disks * chunk_bytes))

    fds = {}
    for i, p in enumerate(ordered_paths):
        if p is not None:
            fds[i] = open(p, 'rb')

    tmp_fd, tmp_path = tempfile.mkstemp(suffix='.raw')
    try:
        with os.fdopen(tmp_fd, 'wb') as out:
            for stripe in range(test_stripes):
                for disk_idx in range(n_disks):
                    disk_off = data_offset_bytes + stripe * chunk_bytes
                    if disk_idx not in fds:
                        out.write(b'\x00' * chunk_bytes)
                    else:
                        fds[disk_idx].seek(disk_off)
                        chunk = fds[disk_idx].read(chunk_bytes)
                        if len(chunk) < chunk_bytes:
                            chunk += b'\x00' * (chunk_bytes - len(chunk))
                        out.write(chunk)

        rc, _, _ = run(["fsstat", "-i", "raw", "-o", "0", tmp_path])
        if rc != 0:
            return False
        rc2, fls_out, _ = run(["fls", "-i", "raw", "-o", "0", tmp_path])
        return rc2 == 0 and len(fls_out) > 0
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

COMMON_DATA_OFFSETS = [
    0,
    63 * 512,      # 32256 bytes — old CHS alignment
    2048 * 512,    # 1 MiB — modern alignment / md 1.2 default
    4096 * 512,    # 2 MiB — md 1.2 on small disks
]


def detect_stripe_size(ordered_paths, data_offset_bytes, n_columns):
    """Try common stripe sizes and return the one that produces valid FS."""
    for chunk_bytes in COMMON_STRIPE_SIZES:
        if _test_raid5_order(ordered_paths, chunk_bytes, data_offset_bytes,
                             n_columns):
            return chunk_bytes
    return None


# ─── Hardware RAID Detection ─────────────────────────────────────────────


def _detect_standalone_mirrors(groups):
    """Detect RAID 1 mirrors among standalone-classified disks.

    Standalone disks with identical raw file sizes and matching content
    samples (first + last 1 MiB) are reclassified as hardware RAID groups.
    """
    standalone_keys = [k for k in groups if k[0] == 'standalone']
    if len(standalone_keys) < 2:
        return groups

    size_buckets = {}
    for key in standalone_keys:
        d = groups[key][0]
        try:
            size = os.path.getsize(d['raw'])
        except OSError:
            continue
        size_buckets.setdefault(size, []).append(key)

    SAMPLE = 1024 * 1024  # 1 MiB

    hw_idx = max(
        (int(k[1].split('_')[1]) for k in groups if k[0] == 'hardware'),
        default=-1,
    ) + 1

    for size, keys in size_buckets.items():
        if len(keys) < 2:
            continue

        samples = {}
        for key in keys:
            raw = groups[key][0]['raw']
            try:
                with open(raw, 'rb') as f:
                    head = f.read(SAMPLE)
                    f.seek(max(0, size - SAMPLE))
                    tail = f.read(SAMPLE)
                samples[key] = head + tail
            except OSError:
                continue

        if len(samples) < 2:
            continue

        vals = list(samples.values())
        if all(v == vals[0] for v in vals[1:]):
            mirror_disks = []
            for key in samples:
                mirror_disks.extend(groups.pop(key))
            groups[('hardware', f'group_{hw_idx}')] = mirror_disks
            hw_idx += 1

    return groups


def detect_hardware_raid_groups(classified):
    """Cluster unknown disks by file size into candidate hardware RAID groups."""
    unknowns = [d for d in classified if d['class'] == 'unknown']
    if not unknowns:
        return []

    size_groups = {}
    for d in unknowns:
        try:
            size = os.path.getsize(d['raw'])
        except OSError:
            continue
        size_groups.setdefault(size, []).append(d)

    groups = []
    for size, disks in size_groups.items():
        if len(disks) >= 2:
            groups.append(disks)
    return groups


def _try_hardware_raid1(disks):
    """Check if any disk in the group has a standalone filesystem."""
    for d in disks:
        for offset_bytes in COMMON_DATA_OFFSETS:
            offset_sectors = offset_bytes // 512
            rc, out, _ = run(["fsstat", "-i", "raw", "-o",
                              str(offset_sectors), d['raw']])
            if rc == 0:
                fs_type = None
                for line in out.decode(errors='replace').splitlines():
                    if 'File System Type' in line:
                        fs_type = line.split(':', 1)[1].strip()
                        break
                return {'level': 1, 'disk': d, 'fs_offset': offset_sectors,
                        'fs_type': fs_type}

        parts = get_partitions(d['raw'])
        for p in parts:
            rc, out, _ = run(["fsstat", "-i", "raw", "-o",
                              str(p['start']), d['raw']])
            if rc == 0:
                fs_type = None
                for line in out.decode(errors='replace').splitlines():
                    if 'File System Type' in line:
                        fs_type = line.split(':', 1)[1].strip()
                        break
                return {'level': 1, 'disk': d, 'fs_offset': p['start'],
                        'fs_type': fs_type}
    return None


def _try_hardware_raid0(disks):
    """Try all RAID 0 configurations and return first valid one."""
    raw_paths = [d['raw'] for d in disks]
    n_disks = len(disks)

    for offset_bytes in COMMON_DATA_OFFSETS:
        for chunk_bytes in COMMON_STRIPE_SIZES:
            for perm in itertools.permutations(range(n_disks)):
                ordered = [raw_paths[i] for i in perm]
                if _test_raid0_order(ordered, chunk_bytes, offset_bytes,
                                     n_disks):
                    return {
                        'level': 0,
                        'ordered': ordered,
                        'chunk_bytes': chunk_bytes,
                        'data_offset_bytes': offset_bytes,
                    }
    return None


def _try_hardware_raid5(disks, *, try_degraded=True):
    """Try all RAID 5 configurations and return first valid one."""
    raw_paths = [d['raw'] for d in disks]
    n_disks = len(disks)

    if n_disks < 3:
        return None

    for offset_bytes in COMMON_DATA_OFFSETS:
        for chunk_bytes in COMMON_STRIPE_SIZES:
            for perm in itertools.permutations(range(n_disks)):
                ordered = [raw_paths[i] for i in perm]
                if _test_raid5_order(ordered, chunk_bytes, offset_bytes,
                                     n_disks):
                    return {
                        'level': 5,
                        'ordered': ordered,
                        'chunk_bytes': chunk_bytes,
                        'data_offset_bytes': offset_bytes,
                        'n_columns': n_disks,
                        'missing_idx': None,
                    }

    if not try_degraded:
        return None

    # Try degraded (one missing disk)
    for n_cols in range(n_disks + 1, n_disks + 3):
        for offset_bytes in COMMON_DATA_OFFSETS:
            for chunk_bytes in COMMON_STRIPE_SIZES:
                for missing_col in range(n_cols):
                    remaining_cols = [c for c in range(n_cols)
                                      if c != missing_col]
                    for perm in itertools.permutations(range(n_disks)):
                        ordered = [None] * n_cols
                        for i, p_idx in enumerate(perm):
                            ordered[remaining_cols[i]] = raw_paths[p_idx]
                        if _test_raid5_order(ordered, chunk_bytes,
                                             offset_bytes, n_cols):
                            return {
                                'level': 5,
                                'ordered': ordered,
                                'chunk_bytes': chunk_bytes,
                                'data_offset_bytes': offset_bytes,
                                'n_columns': n_cols,
                                'missing_idx': missing_col,
                            }
    return None


def _report_hw_failure(disks):
    """Report failure to detect hardware RAID configuration."""
    print(f"\n  [!] Could not detect hardware RAID configuration")
    print(f"  Tried:")
    levels = "0, 5" if len(disks) >= 3 else "1, 0"
    print(f"    RAID levels: {levels}")
    print(f"    Stripe sizes: "
          f"{', '.join(str(s // 1024) + 'K' for s in COMMON_STRIPE_SIZES)}")
    print(f"    Data offsets (sectors): "
          f"{', '.join(str(o // 512) for o in COMMON_DATA_OFFSETS)}")
    n_perm = 1
    for i in range(1, len(disks) + 1):
        n_perm *= i
    total = n_perm * len(COMMON_STRIPE_SIZES) * len(COMMON_DATA_OFFSETS)
    print(f"    Permutations per config: {n_perm} "
          f"({total} total trials per RAID level)")
    print(f"\n  Retry with manual parameters:")
    print(f"    --hw-raid-level {{0,1,5}}")
    print(f"    --hw-stripe SIZE_KIB")
    print(f"    --hw-order disk_A.E01,disk_B.E01,...")
    print(f"    --hw-offset SECTORS")


def _apply_hw_overrides(disks, overrides):
    """Apply user-specified hardware RAID parameters."""
    level = overrides['level']

    chunk_bytes = (overrides['stripe'] or 64) * 1024
    data_offset_bytes = (overrides['offset'] or 0) * 512

    if overrides.get('order'):
        name_to_disk = {d['e01']: d for d in disks}
        ordered = []
        for name in overrides['order']:
            key = name if name in name_to_disk else name + '.E01'
            if key not in name_to_disk:
                print(f"  [!] Unknown disk in --hw-order: {name}")
                return None
            ordered.append(name_to_disk[key]['raw'])
    else:
        ordered = [d['raw'] for d in disks]

    return {
        'level': level,
        'ordered': ordered,
        'chunk_bytes': chunk_bytes,
        'data_offset_bytes': data_offset_bytes,
        'n_columns': len(ordered),
        'missing_idx': None,
    }


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
    partition_base    = d0.get('partition_byte_offset', 0)
    data_offset_bytes = partition_base + data_offset * 512

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
        data_offset_bytes=data_offset_bytes,
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


def handle_hardware_raid_group(disks, output_dir, keep_raw, overrides=None):
    """Handle a group of unknown disks as hardware RAID."""
    group_id = '_'.join(sorted(d['e01'].replace('.E01', '') for d in disks))
    label = f"hw_{group_id}"
    out = os.path.join(output_dir, label)
    ensure_dir(out)

    names = ', '.join(d['e01'] for d in disks)
    disk_size = os.path.getsize(disks[0]['raw'])
    print(f"\n  Hardware RAID candidate: {len(disks)} disks, "
          f"{disk_size / 1073741824:.2f} GiB each")
    print(f"  Members: {names}")

    if len(disks) >= 5:
        print(f"  [!] Warning: {len(disks)} disks = many permutations. "
              f"Consider --hw-* flags for faster detection.")

    if overrides and overrides.get('level') is not None:
        result = _apply_hw_overrides(disks, overrides)
    else:
        result = None

        # RAID 1 only for 2-disk groups (3+ disks false-positive on
        # RAID 5 members where the FS superblock lands in one stripe)
        if len(disks) == 2:
            print(f"\n  Trying RAID 1 (mirror)...")
            r1 = _try_hardware_raid1(disks)
            if r1:
                print(f"  [+] RAID 1 detected: {r1['disk']['e01']} has "
                      f"{r1['fs_type']} at sector {r1['fs_offset']}")
                print(f"  Extracting files...")
                extract_files_from_image(r1['disk']['raw'], r1['fs_offset'],
                                         os.path.join(out, "files"))
                return

        # Full RAID 5 first (all disks present), then RAID 0, then
        # degraded RAID 5 last (prone to false positives on RAID 0 data)
        if len(disks) >= 3:
            print(f"\n  Trying RAID 5 (stripe + parity)...")
            result = _try_hardware_raid5(disks, try_degraded=False)

        if not result:
            print(f"  Trying RAID 0 (stripe)...")
            result = _try_hardware_raid0(disks)

        if not result and len(disks) >= 3:
            print(f"  Trying degraded RAID 5...")
            result = _try_hardware_raid5(disks, try_degraded=True)

    if not result:
        _report_hw_failure(disks)
        return

    level = result['level']
    ordered = result['ordered']
    chunk_bytes = result['chunk_bytes']
    data_offset_bytes = result['data_offset_bytes']

    # RAID 1 via override — extract directly from member disk
    if level == 1:
        disk_path = ordered[0]
        fs_offset = data_offset_bytes // 512
        if not fs_offset:
            for try_bytes in COMMON_DATA_OFFSETS:
                try_sectors = try_bytes // 512
                rc, _, _ = run(["fsstat", "-i", "raw", "-o",
                                str(try_sectors), disk_path])
                if rc == 0:
                    fs_offset = try_sectors
                    break
            if not fs_offset:
                parts = get_partitions(disk_path)
                for p in parts:
                    rc, _, _ = run(["fsstat", "-i", "raw", "-o",
                                    str(p['start']), disk_path])
                    if rc == 0:
                        fs_offset = p['start']
                        break
        if fs_offset is not None:
            e01_name = next((d['e01'] for d in disks
                             if d['raw'] == disk_path), '?')
            print(f"\n  RAID 1: extracting from {e01_name} "
                  f"at sector {fs_offset}")
            extract_files_from_image(disk_path, fs_offset,
                                     os.path.join(out, "files"))
        else:
            print(f"  [!] No filesystem found on RAID 1 member disk")
        return

    # RAID 0 / RAID 5 — compute data size and reconstruct
    disk_size = os.path.getsize(disks[0]['raw'])
    sectors_per_chunk = chunk_bytes // 512
    avail_sectors = (disk_size - data_offset_bytes) // 512
    data_size_sectors = (avail_sectors // sectors_per_chunk) * sectors_per_chunk

    print(f"\n  Detected RAID {level} parameters:")
    print(f"    Chunk size: {chunk_bytes // 1024} KiB")
    print(f"    Data offset: {data_offset_bytes} bytes "
          f"(sector {data_offset_bytes // 512})")
    print(f"    Data size/disk: {data_size_sectors} sectors "
          f"({data_size_sectors * 512 / 1073741824:.2f} GiB)")

    for i, path in enumerate(ordered):
        if path:
            e01_name = next((d['e01'] for d in disks if d['raw'] == path),
                            '?')
            print(f"    Column {i}: {e01_name}")
        else:
            print(f"    Column {i}: MISSING (rebuild from parity)")

    if level == 0:
        raid_img = os.path.join(out, "raid0_reconstructed.raw")
        print(f"\n  Reconstructing RAID 0...")
        reconstruct_raid0(
            disk_files=ordered,
            chunk_bytes=chunk_bytes,
            data_offset_bytes=data_offset_bytes,
            data_size_sectors=data_size_sectors,
            output_path=raid_img,
        )
    elif level == 5:
        raid_img = os.path.join(out, "raid5_reconstructed.raw")
        missing_idx = result.get('missing_idx')
        print(f"\n  Reconstructing RAID 5...")
        reconstruct_raid5_left_symmetric(
            disk_files=ordered,
            chunk_bytes=chunk_bytes,
            data_offset_bytes=data_offset_bytes,
            data_size_sectors=data_size_sectors,
            output_path=raid_img,
            missing_disk_idx=missing_idx,
        )
    else:
        return

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
    parser.add_argument("--hw-raid-level", type=int, choices=[0, 1, 5],
                        help="Force RAID level for unknown disks")
    parser.add_argument("--hw-stripe", type=int,
                        help="Force stripe size in KiB for unknown disks")
    parser.add_argument("--hw-order",
                        help="Force disk order (comma-separated E01 filenames)")
    parser.add_argument("--hw-offset", type=int,
                        help="Force data offset in sectors for unknown disks")
    args = parser.parse_args()

    input_dir = os.path.abspath(args.input_dir)
    output_dir = (os.path.abspath(args.output) if args.output
                  else os.path.join(input_dir, "auto_extracted"))

    hw_overrides = None
    if (args.hw_raid_level is not None or args.hw_stripe
            or args.hw_order or args.hw_offset is not None):
        hw_overrides = {
            'level': args.hw_raid_level,
            'stripe': args.hw_stripe,
            'offset': args.hw_offset,
            'order': args.hw_order.split(',') if args.hw_order else None,
        }

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

    # Detect hardware RAID groups from unknowns
    hw_groups = detect_hardware_raid_groups(classified)
    if hw_groups:
        hw_disk_e01s = set()
        for hg in hw_groups:
            for d in hg:
                hw_disk_e01s.add(d['e01'])
        groups = {k: v for k, v in groups.items()
                  if k[0] != 'unknown' or k[1] not in hw_disk_e01s}
        for i, hg in enumerate(hw_groups):
            groups[('hardware', f'group_{i}')] = hg

    # Detect RAID 1 mirrors among standalone disks
    groups = _detect_standalone_mirrors(groups)

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

        elif gtype == 'hardware':
            print(f"GROUP: Hardware RAID candidate ({len(gdisks)} disk(s))")
            print(f"{'='*60}")
            handle_hardware_raid_group(gdisks, output_dir, args.keep_raw,
                                       hw_overrides)

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
