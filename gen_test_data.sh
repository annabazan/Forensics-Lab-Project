#!/usr/bin/env bash
# Generate E01 test image sets for detect_and_extract_raids.py
#
# All E01 files land in a single flat directory ($OUT) with unique prefixed
# names.  Run the tool once against that directory to exercise the full
# auto-detection pipeline.
#
# Test cases (prefix → description):
#   md5_3d_       — 3-disk md RAID 5, 512K chunk, ext4
#   md5_4d_       — 4-disk md RAID 5, 64K chunk, ext4
#   md5_deg_      — 3-disk md RAID 5, only 2 disks exported (degraded)
#   md5_gpt_      — 3-disk md RAID 5 on GPT partitions
#   ext4_         — single disk, MBR partition table, ext4
#   fat32_        — single disk, whole-device FAT32
#   hw5_          — 3-disk hardware RAID 5, superblock wiped (110 MiB disks)
#   hw0_          — 3-disk hardware RAID 0, superblock wiped (120 MiB disks)
#   hw1_          — 2-disk hardware RAID 1, superblock wiped (105 MiB disks)
#
# Hardware RAID test cases use different disk sizes so size-based clustering
# groups them correctly when all files share one directory.
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
    local prefix="$1" n_disks="$2" chunk_k="${3:-512}" disk_mb="${4:-$DISK_MB}"
    local md_dev mnt="$WORK/mnt_${prefix}"
    md_dev=$(next_md)

    banner "$prefix — ${n_disks}-disk md RAID 5, ${chunk_k}K chunk"

    local devs=() raws=() letters=(A B C D E F G H)
    for i in $(seq 0 $((n_disks - 1))); do
        local raw="$WORK/${prefix}_${letters[$i]}.raw"
        truncate -s "${disk_mb}M" "$raw"
        raws+=("$raw")
        devs+=("$(lo_attach "$raw")")
    done

    md_create "$md_dev" --level=5 --raid-devices="$n_disks" \
        --chunk="$chunk_k" "${devs[@]}"
    mdadm --wait "$md_dev" 2>/dev/null || true

    mkfs.ext4 -q "$md_dev"
    mount_fs "$md_dev" "$mnt"
    populate "$mnt"
    umount_fs "$mnt"
    md_stop "$md_dev"

    for i in $(seq 0 $((n_disks - 1))); do
        lo_detach "${devs[$i]}"
    done

    for i in $(seq 0 $((n_disks - 1))); do
        to_e01 "${raws[$i]}" "$OUT/${prefix}_${letters[$i]}"
    done

    echo "[+] $prefix: $n_disks E01 files → $OUT"
}

gen_md_raid5_degraded() {
    local prefix="md5_deg"
    local md_dev mnt="$WORK/mnt_${prefix}"
    md_dev=$(next_md)

    banner "$prefix — 3-disk md RAID 5, 1 disk excluded"

    local devs=() raws=() letters=(A B C)
    for i in 0 1 2; do
        local raw="$WORK/${prefix}_${letters[$i]}.raw"
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
    to_e01 "${raws[0]}" "$OUT/${prefix}_A"
    to_e01 "${raws[1]}" "$OUT/${prefix}_B"

    echo "[+] $prefix: 2 E01 files (disk C excluded) → $OUT"
}

gen_standalone_ext4() {
    local prefix="ext4"
    local raw="$WORK/${prefix}.raw"
    local mnt="$WORK/mnt_${prefix}"

    banner "$prefix — MBR + ext4 partition"

    truncate -s "${DISK_MB}M" "$raw"

    # MBR with one Linux partition starting at sector 2048
    echo '2048,,L' | sfdisk -q "$raw"

    local dev
    dev=$(lo_attach "$raw")
    partprobe "$dev"
    sleep 0.5

    local part="${dev}p1"
    for _ in $(seq 1 20); do [ -b "$part" ] && break; sleep 0.3; done
    [ -b "$part" ] || die "Partition $part not found"

    mkfs.ext4 -q "$part"
    mount_fs "$part" "$mnt"
    populate "$mnt"
    umount_fs "$mnt"
    lo_detach "$dev"

    to_e01 "$raw" "$OUT/${prefix}_disk"

    echo "[+] $prefix: 1 E01 file → $OUT"
}

gen_standalone_fat32() {
    local prefix="fat32"
    local raw="$WORK/${prefix}.raw"
    local mnt="$WORK/mnt_${prefix}"

    banner "$prefix — whole-disk FAT32"

    truncate -s "${DISK_MB}M" "$raw"
    mkfs.fat -F 32 "$raw" >/dev/null

    local dev
    dev=$(lo_attach "$raw")
    mount_fs "$dev" "$mnt"
    populate "$mnt"
    umount_fs "$mnt"
    lo_detach "$dev"

    to_e01 "$raw" "$OUT/${prefix}_disk"

    echo "[+] $prefix: 1 E01 file → $OUT"
}

gen_hardware_raid5() {
    local prefix="hw5"
    local disk_mb=110
    local md_dev mnt="$WORK/mnt_${prefix}"
    md_dev=$(next_md)

    banner "$prefix — 3-disk RAID 5, superblock wiped (${disk_mb} MiB disks)"

    local devs=() raws=() letters=(A B C)
    for i in 0 1 2; do
        local raw="$WORK/${prefix}_${letters[$i]}.raw"
        truncate -s "${disk_mb}M" "$raw"
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

    for dev in "${devs[@]}"; do
        mdadm --zero-superblock "$dev" 2>/dev/null || true
    done

    for i in 0 1 2; do lo_detach "${devs[$i]}"; done

    for i in 0 1 2; do
        to_e01 "${raws[$i]}" "$OUT/${prefix}_${letters[$i]}"
    done

    echo "[+] $prefix: 3 E01 files (no RAID metadata, ${disk_mb} MiB) → $OUT"
}

gen_hardware_raid0() {
    local prefix="hw0"
    local disk_mb=120
    local md_dev mnt="$WORK/mnt_${prefix}"
    md_dev=$(next_md)

    banner "$prefix — 3-disk RAID 0, superblock wiped (${disk_mb} MiB disks)"

    local devs=() raws=() letters=(A B C)
    for i in 0 1 2; do
        local raw="$WORK/${prefix}_${letters[$i]}.raw"
        truncate -s "${disk_mb}M" "$raw"
        raws+=("$raw")
        devs+=("$(lo_attach "$raw")")
    done

    md_create "$md_dev" --level=0 --raid-devices=3 --chunk=64 "${devs[@]}"

    mkfs.ext4 -q "$md_dev"
    mount_fs "$md_dev" "$mnt"
    populate "$mnt"
    umount_fs "$mnt"
    md_stop "$md_dev"

    for dev in "${devs[@]}"; do
        mdadm --zero-superblock "$dev" 2>/dev/null || true
    done

    for i in 0 1 2; do lo_detach "${devs[$i]}"; done

    for i in 0 1 2; do
        to_e01 "${raws[$i]}" "$OUT/${prefix}_${letters[$i]}"
    done

    echo "[+] $prefix: 3 E01 files (no RAID metadata, ${disk_mb} MiB) → $OUT"
}

gen_hardware_raid1() {
    local prefix="hw1"
    local disk_mb=105
    local md_dev mnt="$WORK/mnt_${prefix}"
    md_dev=$(next_md)

    banner "$prefix — 2-disk RAID 1, superblock wiped (${disk_mb} MiB disks)"

    local devs=() raws=() letters=(A B)
    for i in 0 1; do
        local raw="$WORK/${prefix}_${letters[$i]}.raw"
        truncate -s "${disk_mb}M" "$raw"
        raws+=("$raw")
        devs+=("$(lo_attach "$raw")")
    done

    md_create "$md_dev" --level=1 --raid-devices=2 "${devs[@]}"
    mdadm --wait "$md_dev" 2>/dev/null || true

    mkfs.ext4 -q "$md_dev"
    mount_fs "$md_dev" "$mnt"
    populate "$mnt"
    umount_fs "$mnt"
    md_stop "$md_dev"

    for dev in "${devs[@]}"; do
        mdadm --zero-superblock "$dev" 2>/dev/null || true
    done

    for i in 0 1; do lo_detach "${devs[$i]}"; done

    for i in 0 1; do
        to_e01 "${raws[$i]}" "$OUT/${prefix}_${letters[$i]}"
    done

    echo "[+] $prefix: 2 E01 files (no RAID metadata, ${disk_mb} MiB) → $OUT"
}

gen_md_raid5_gpt() {
    local prefix="md5_gpt"
    local md_dev mnt="$WORK/mnt_${prefix}"
    md_dev=$(next_md)

    banner "$prefix — GPT on disks + RAID5 on partitions"

    local devs=() raws=() letters=(A B C)

    for i in 0 1 2; do
        local raw="$WORK/${prefix}_${letters[$i]}.raw"
        truncate -s "${DISK_MB}M" "$raw"
        raws+=("$raw")
        devs+=("$(lo_attach "$raw")")
    done

    local parts=()
    for dev in "${devs[@]}"; do
        sgdisk -Z "$dev"
        sgdisk -o "$dev"
        sgdisk -n 1:2048:0 -t 1:fd00 "$dev"

        partprobe "$dev"

        local part="${dev}p1"
        for _ in $(seq 1 20); do
            [ -b "$part" ] && break
            sleep 0.3
        done

        [ -b "$part" ] || die "Partition not found on $dev"
        parts+=("$part")
    done

    md_create "$md_dev" --level=5 --raid-devices=3 --chunk=512 "${parts[@]}"
    mdadm --wait "$md_dev" 2>/dev/null || true

    mkfs.ext4 -q "$md_dev"
    mount_fs "$md_dev" "$mnt"
    populate "$mnt"
    umount_fs "$mnt"

    md_stop "$md_dev"

    for d in "${devs[@]}"; do
        lo_detach "$d"
    done

    for i in 0 1 2; do
        to_e01 "${raws[$i]}" "$OUT/${prefix}_${letters[$i]}"
    done

    echo "[+] $prefix: 3 E01 files (GPT + RAID) → $OUT"
}

# ─── Main ─────────────────────────────────────────────────────────────────

main() {
    [ "$(id -u)" -eq 0 ] || die "Must run as root (sudo ./gen_test_data.sh)"
    require mdadm ewfacquire mkfs.ext4 mkfs.fat sfdisk sgdisk losetup partprobe

    echo "[*] Generating test data for detect_and_extract_raids"
    echo "[*] Output: $OUT"
    echo "[*] Temp:   $WORK"

    rm -rf "$OUT"
    mkdir -p "$OUT"

    gen_md_raid5 "md5_3d" 3 512
    gen_md_raid5 "md5_4d" 4 64
    gen_md_raid5_degraded
    gen_md_raid5_gpt
    gen_standalone_ext4
    gen_standalone_fat32
    gen_hardware_raid5
    gen_hardware_raid0
    gen_hardware_raid1

    # chown output to the invoking user (not root)
    if [ -n "${SUDO_USER:-}" ]; then
        chown -R "$SUDO_USER:$SUDO_USER" "$OUT"
    fi

    echo
    echo "═══════════════════════════════════════"
    echo " All test data generated in $OUT:"
    echo "═══════════════════════════════════════"
    local count
    count=$(find "$OUT" -maxdepth 1 -name "*.E01" | wc -l)
    echo "  $count E01 file(s) total"
    echo
    ls -1 "$OUT"/*.E01 2>/dev/null | while read -r f; do
        printf "  %s (%s)\n" "$(basename "$f")" "$(du -h "$f" | cut -f1)"
    done
    echo
    echo "Run: python detect_and_extract_raids.py $OUT/"
}

main
