#!/usr/bin/env bash

# ============================================================
# Rolling PCAP Capture Script
#
# Captures traffic on all or specified interfaces into
# daily, timestamped PCAP files with configurable max size.
# Each interface writes to a separate PCAP.
#
# Disk space monitored; stops capture if disk < 5% free.
# Rotates files at max size or at date boundary.
#
# Optional auto-purge of old PCAPs is available but disabled
# by default. Purge can be enabled via PURGE_ENABLED=1
##
# © 2026 Blue Bridge Software Ltd. All Rights Reserved.
#
# This software and its associated documentation are proprietary
# and confidential. Any unauthorized use, copying, modification,
# or distribution of this software, in whole or in part, is
# strictly prohibited without the prior written consent of
# Blue Bridge Software Ltd.
#
# For licensing inquiries, contact: legal@bluebridgesoftware.com
# ============================================================

set -euo pipefail

# ---------------- CONFIGURATION ----------------
CAPTURE_DIR="/var/log/pcap"
ARCHIVE_DIR="/var/log/pcap/archive"
MAX_FILE_SIZE_MB=50
INTERFACES=()                # Empty = all interfaces
HOSTNAME=$(hostname)
PURGE_ENABLED=0              # 0=off, 1=on
PURGE_DAYS=30                # Only used if PURGE_ENABLED=1
MIN_DISK_FREE_PCT=5          # Stop capture if free space below this %

mkdir -p "$CAPTURE_DIR"
mkdir -p "$ARCHIVE_DIR"

# ---------------- FUNCTIONS ----------------
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $*"
}

check_disk_space() {
    local avail
    avail=$(df --output=pcent "$CAPTURE_DIR" | tail -n 1 | tr -d ' %')
    if (( avail > (100 - MIN_DISK_FREE_PCT) )); then
        log "Disk usage above $((100 - MIN_DISK_FREE_PCT))%, stopping capture."
        kill "${CAPTURE_PIDS[@]:-}" || true
        exit 1
    fi
}

generate_pcap_name() {
    local iface="$1"
    printf "%s/%s_%s_%s.pcap" "$CAPTURE_DIR" "$HOSTNAME" "$iface" "$(date '+%Y%m%d_%H%M%S')"
}

archive_daily_pcaps() {
    local today=$(date '+%Y%m%d')
    local archive_file="$ARCHIVE_DIR/${HOSTNAME}_${today}.tar.gz"
    local files_to_archive=($(find "$CAPTURE_DIR" -maxdepth 1 -type f -name "${HOSTNAME}_*.pcap" -daystart -mtime 0))
    if (( ${#files_to_archive[@]} > 0 )); then
        log "Archiving ${#files_to_archive[@]} files into $archive_file"
        tar -czf "$archive_file" -C "$CAPTURE_DIR" "${files_to_archive[@]##*/}"
        rm -f "${files_to_archive[@]}"
    fi
}

auto_purge_old_pcaps() {
    if [[ "$PURGE_ENABLED" -eq 1 ]]; then
        log "Auto purge enabled: deleting PCAPs older than $PURGE_DAYS days"
        find "$CAPTURE_DIR" -type f -name "${HOSTNAME}_*.pcap" -mtime +"$PURGE_DAYS" -print -exec rm -f {} \;
    else
        log "Auto purge disabled. Set PURGE_ENABLED=1 to enable."
    fi
}

# ---------------- MAIN CAPTURE ----------------
# Determine interfaces to capture
if (( ${#INTERFACES[@]} == 0 )); then
    INTERFACES=($(ls /sys/class/net | grep -v lo))
fi

CAPTURE_PIDS=()

for iface in "${INTERFACES[@]}"; do
    pcap_file=$(generate_pcap_name "$iface")
    log "Starting capture on $iface -> $pcap_file"

    dumpcap -i "$iface" \
             -b filesize:$((MAX_FILE_SIZE_MB * 1024)) \
             -b files:1000 \
             -w "$pcap_file" \
             -q &
    CAPTURE_PIDS+=($!)
done

# Clean up on exit
trap 'log "Stopping captures..."; kill "${CAPTURE_PIDS[@]:-}" || true' SIGINT SIGTERM

# ---------------- LOOP: daily rollover, disk check ----------------
while true; do
    sleep 60

    check_disk_space

    # Archive previous day PCAPs at midnight
    current_date=$(date '+%Y%m%d')
    if [[ "$current_date" != "$LAST_ARCHIVE_DATE" ]]; then
        archive_daily_pcaps
        auto_purge_old_pcaps
        LAST_ARCHIVE_DATE="$current_date"
    fi
done

