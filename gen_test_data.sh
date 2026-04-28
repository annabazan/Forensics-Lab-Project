#!/usr/bin/env bash
# Generate E01 test image sets for detect_and_extract_raids.py
#
# Test cases:
#   md_raid5_3disk        — 3-disk md RAID 5, 512K chunk, ext4
#   md_raid5_4disk_64k    — 4-disk md RAID 5, 64K chunk, ext4
#   md_raid5_degraded     — 3-disk md RAID 5, only 2 disks exported
#   standalone_ext4       — single disk, MBR partition table, ext4
#   standalone_fat32      — single disk, whole-device FAT32
#   hardware_raid5        — 3-disk RAID 5 with superblock wiped (no metadata)
#   mixed                 — RAID + standalone E01s in one directory
#
# Usage: sudo ./gen_test_data.sh [output_dir]
# Dependencies: mdadm, ewfacquire (libewf), mkfs.ext4, mkfs.fat, sfdisk

set -euo pipefail

OUT="${1:-./test_data}"
WORK="$(mktemp -d)"
DISK_MB=100

LOOPS=()
MDS=()
MNTS=()

die() { echo "[!] $*" >&2; exit 1; }

cleanup() {
    set +e
    for m in "${MNTS[@]}"; do sudo umount "$m" 2>/dev/null; done
    for md in "${MDS[@]}"; do sudo mdadm --stop "$md" 2>/dev/null; done
    for l in "${LOOPS[@]}"; do sudo losetup -d "$l" 2>/dev/null; done
    rm -rf "$WORK"
}
trap cleanup EXIT

require() {
    for cmd in "$@"; do
        command -v "$cmd" >/dev/null || die "Missing: $cmd"
    done
}

lo_attach() {
    local dev
    dev=$(losetup --find --show "$1")
    LOOPS+=("$dev")
    echo "$dev"
}

lo_detach() {
    losetup -d "$1" 2>/dev/null || true
    local new=()
    for l in "${LOOPS[@]}"; do [ "$l" != "$1" ] && new+=("$l"); done
    LOOPS=("${new[@]+"${new[@]}"}")
}

md_create() {
    local md_dev="$1"; shift
    mdadm --create "$md_dev" --metadata=1.2 --run "$@" <<< 'y'
    MDS+=("$md_dev")
}

md_stop() {
    mdadm --stop "$1" 2>/dev/null || true
    local new=()
    for m in "${MDS[@]}"; do [ "$m" != "$1" ] && new+=("$m"); done
    MDS=("${new[@]+"${new[@]}"}")
}

next_md() {
    for i in $(seq 100 120); do
        [ ! -e "/dev/md$i" ] && echo "/dev/md$i" && return
    done
    die "No free md device (md100-md120)"
}

mount_fs() {
    mkdir -p "$2"
    mount "$1" "$2"
    MNTS+=("$2")
}

umount_fs() {
    umount "$1" 2>/dev/null || true
    local new=()
    for m in "${MNTS[@]}"; do [ "$m" != "$1" ] && new+=("$m"); done
    MNTS=("${new[@]+"${new[@]}"}")
}

populate() {
    local mp="$1"
    mkdir -p "$mp/documents" "$mp/images"
    echo 'Confidential forensic evidence — Case #2025-0042' > "$mp/documents/case_report.txt"
    echo '<html><body><h1>Evidence Index</h1><p>14 items catalogued</p></body></html>' > "$mp/documents/index.html"
    echo 'Transaction log — 2025-03-15 — wire transfer EUR 50,000' > "$mp/documents/transactions.log"
    dd if=/dev/urandom of="$mp/images/photo_001.jpg" bs=1K count=128 status=none
    dd if=/dev/urandom of="$mp/images/scan_002.png" bs=1K count=64 status=none
    echo 'Notes: suspect accessed system at 03:14 UTC' > "$mp/notes.txt"
}

to_e01() {
    local raw="$1" prefix="$2"
    ewfacquire -u -t "$prefix" -f encase6 -c fast "$raw"
}

banner() {
    echo
    echo "═══════════════════════════════════════"
    echo " $1"
    echo "═══════════════════════════════════════"
}

# ─── Test cases ───────────────────────────────────────────────────────────

gen_md_raid5() {
    local name="$1" n_disks="$2" chunk_k="${3:-512}"
    local case_dir="$OUT/$name"
    local md_dev mnt="$WORK/mnt_${name}"
    md_dev=$(next_md)

    banner "$name — ${n_disks}-disk md RAID 5, ${chunk_k}K chunk"

    local devs=() raws=() letters=(A B C D E F G H)
    for i in $(seq 0 $((n_disks - 1))); do
        local raw="$WORK/${name}_${letters[$i]}.raw"
        truncate -s "${DISK_MB}M" "$raw"
        raws+=("$raw")
        devs+=("$(lo_attach "$raw")")
    done

    md_create "$md_dev" --level=5 --raid-devices="$n_disks" \
        --chunk="$chunk_k" "${devs[@]}"
    # wait for initial sync on small arrays
    mdadm --wait "$md_dev" 2>/dev/null || true

    mkfs.ext4 -q "$md_dev"
    mount_fs "$md_dev" "$mnt"
    populate "$mnt"
    umount_fs "$mnt"
    md_stop "$md_dev"

    for i in $(seq 0 $((n_disks - 1))); do
        lo_detach "${devs[$i]}"
    done

    mkdir -p "$case_dir"
    for i in $(seq 0 $((n_disks - 1))); do
        to_e01 "${raws[$i]}" "$case_dir/disk_${letters[$i]}"
    done

    echo "[+] $name: $n_disks E01 files → $case_dir"
}

gen_md_raid5_degraded() {
    local name="md_raid5_degraded"
    local case_dir="$OUT/$name"
    local md_dev mnt="$WORK/mnt_${name}"
    md_dev=$(next_md)

    banner "$name — 3-disk md RAID 5, 1 disk excluded"

    local devs=() raws=() letters=(A B C)
    for i in 0 1 2; do
        local raw="$WORK/${name}_${letters[$i]}.raw"
        truncate -s "${DISK_MB}M" "$raw"
        raws+=("$raw")
        devs+=("$(lo_attach "$raw")")
    done

    md_create "$md_dev" --level=5 --raid-devices=3 --chunk=512 "${devs[@]}"
    mdadm --wait "$md_dev" 2>/dev/null || true

    mkfs.ext4 -q "$md_dev"
    mount_fs "$md_dev" "$mnt"
    populate "$mnt"
    umount_fs "$mnt"
    md_stop "$md_dev"

    for i in 0 1 2; do lo_detach "${devs[$i]}"; done

    # Export only 2 of 3 disks — tool must rebuild via XOR
    mkdir -p "$case_dir"
    to_e01 "${raws[0]}" "$case_dir/disk_A"
    to_e01 "${raws[1]}" "$case_dir/disk_B"

    echo "[+] $name: 2 E01 files (disk C excluded) → $case_dir"
}

gen_standalone_ext4() {
    local name="standalone_ext4"
    local case_dir="$OUT/$name"
    local raw="$WORK/${name}.raw"
    local mnt="$WORK/mnt_${name}"

    banner "$name — MBR + ext4 partition"

    truncate -s "${DISK_MB}M" "$raw"

    # MBR with one Linux partition starting at sector 2048
    echo '2048,,L' | sfdisk -q "$raw"

    local dev
    dev=$(lo_attach "$raw")
    partprobe "$dev"
    sleep 0.5

    # Partition device: e.g. /dev/loop101p1
    local part="${dev}p1"
    for _ in $(seq 1 20); do [ -b "$part" ] && break; sleep 0.3; done
    [ -b "$part" ] || die "Partition $part not found"

    mkfs.ext4 -q "$part"
    mount_fs "$part" "$mnt"
    populate "$mnt"
    umount_fs "$mnt"
    lo_detach "$dev"

    mkdir -p "$case_dir"
    to_e01 "$raw" "$case_dir/disk"

    echo "[+] $name: 1 E01 file → $case_dir"
}

gen_standalone_fat32() {
    local name="standalone_fat32"
    local case_dir="$OUT/$name"
    local raw="$WORK/${name}.raw"
    local mnt="$WORK/mnt_${name}"

    banner "$name — whole-disk FAT32"

    truncate -s "${DISK_MB}M" "$raw"
    mkfs.fat -F 32 "$raw" >/dev/null

    local dev
    dev=$(lo_attach "$raw")
    mount_fs "$dev" "$mnt"
    populate "$mnt"
    umount_fs "$mnt"
    lo_detach "$dev"

    mkdir -p "$case_dir"
    to_e01 "$raw" "$case_dir/disk"

    echo "[+] $name: 1 E01 file → $case_dir"
}

gen_hardware_raid5() {
    local name="hardware_raid5"
    local case_dir="$OUT/$name"
    local md_dev mnt="$WORK/mnt_${name}"
    md_dev=$(next_md)

    banner "$name — 3-disk RAID 5, superblock wiped (no metadata)"

    local devs=() raws=() letters=(A B C)
    for i in 0 1 2; do
        local raw="$WORK/${name}_${letters[$i]}.raw"
        truncate -s "${DISK_MB}M" "$raw"
        raws+=("$raw")
        devs+=("$(lo_attach "$raw")")
    done

    md_create "$md_dev" --level=5 --raid-devices=3 --chunk=512 "${devs[@]}"
    mdadm --wait "$md_dev" 2>/dev/null || true

    mkfs.ext4 -q "$md_dev"
    mount_fs "$md_dev" "$mnt"
    populate "$mnt"
    umount_fs "$mnt"
    md_stop "$md_dev"

    # Wipe md superblocks — simulates hardware RAID controller images
    for dev in "${devs[@]}"; do
        mdadm --zero-superblock "$dev" 2>/dev/null || true
    done

    for i in 0 1 2; do lo_detach "${devs[$i]}"; done

    mkdir -p "$case_dir"
    for i in 0 1 2; do
        to_e01 "${raws[$i]}" "$case_dir/disk_${letters[$i]}"
    done

    echo "[+] $name: 3 E01 files (no RAID metadata) → $case_dir"
    echo "    Tool will classify as 'unknown' — needs manual RAID params"
}

gen_mixed() {
    local name="mixed"
    local case_dir="$OUT/$name"

    banner "$name — RAID + standalone in one directory"

    mkdir -p "$case_dir"

    local src count=0
    # Copy md RAID 5 disks (prefixed to avoid name collision)
    src="$OUT/md_raid5_3disk"
    if [ -d "$src" ]; then
        for f in "$src"/*.E01; do
            [ -f "$f" ] || continue
            cp "$f" "$case_dir/raid_$(basename "$f")"
            ((++count))
        done
    fi

    # Copy standalone ext4
    src="$OUT/standalone_ext4"
    if [ -d "$src" ]; then
        for f in "$src"/*.E01; do
            [ -f "$f" ] || continue
            cp "$f" "$case_dir/solo_$(basename "$f")"
            ((++count))
        done
    fi

    echo "[+] $name: $count E01 files (mixed types) → $case_dir"
}

# ─── Main ─────────────────────────────────────────────────────────────────

main() {
    [ "$(id -u)" -eq 0 ] || die "Must run as root (sudo ./gen_test_data.sh)"
    require mdadm ewfacquire mkfs.ext4 mkfs.fat sfdisk losetup partprobe

    echo "[*] Generating test data for detect_and_extract_raids"
    echo "[*] Output: $OUT"
    echo "[*] Temp:   $WORK"

    mkdir -p "$OUT"

    gen_md_raid5 "md_raid5_3disk" 3 512
    gen_md_raid5 "md_raid5_4disk_64k" 4 64
    gen_md_raid5_degraded
    gen_standalone_ext4
    gen_standalone_fat32
    gen_hardware_raid5
    gen_mixed

    # chown output to the invoking user (not root)
    if [ -n "${SUDO_USER:-}" ]; then
        chown -R "$SUDO_USER:$SUDO_USER" "$OUT"
    fi

    echo
    echo "═══════════════════════════════════════"
    echo " All test sets generated:"
    echo "═══════════════════════════════════════"
    for d in "$OUT"/*/; do
        [ -d "$d" ] || continue
        local count
        count=$(find "$d" -maxdepth 1 -name "*.E01" | wc -l)
        printf "  %-28s %d E01 file(s)\n" "$(basename "$d")/" "$count"
    done
    echo
    echo "Run: python detect_and_extract_raids.py $OUT/<test_case>/"
}

main
