#!/usr/bin/env bash

# ============================================================
# Rolling PCAP Capture Script to manage and capture interface
# traffic for platform management and diagnostics
#
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

################ CONFIG ################

CAPTURE_DIR="/var/log/pcap"
MAX_SIZE_MB=50
MIN_FREE_PERCENT=10          # Stop capture if disk free < 10%
CHECK_INTERVAL=30            # Disk check interval (seconds)
DUMPCAP_BIN="/usr/bin/dumpcap"
CAPTURE_USER="pcap"
EXCLUDE_INTERFACES="lo"

########################################

HOSTNAME=$(hostname -s)

mkdir -p "$CAPTURE_DIR"
chown -R "$CAPTURE_USER":"$CAPTURE_USER" "$CAPTURE_DIR"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

get_free_percent() {
    df -P "$CAPTURE_DIR" | awk 'NR==2 {print 100 - $5}' | tr -d '%'
}

get_interfaces() {
    ip -o link show | awk -F': ' '{print $2}' | \
        grep -vE "$EXCLUDE_INTERFACES"
}

stop_all_captures() {
    log "Stopping all dumpcap processes due to low disk space"
    pkill -u "$CAPTURE_USER" dumpcap || true
}

start_capture_for_interface() {
    local IFACE=$1

    TODAY=$(date +%Y-%m-%d)
    START_TIME=$(date +%H%M%S)
    NOW=$(date +%s)
    END_OF_DAY=$(date -d "today 23:59:59" +%s)
    SECONDS_LEFT=$(( END_OF_DAY - NOW ))

    FILE_PREFIX="${CAPTURE_DIR}/${HOSTNAME}_${TODAY}_${IFACE}_${START_TIME}"

    log "Starting capture on interface ${IFACE}"

    "$DUMPCAP_BIN" \
        -i "$IFACE" \
        -s 0 \
        -b filesize:$((MAX_SIZE_MB * 1000)) \
        -b files:1000000 \
        -a duration:${SECONDS_LEFT} \
        -w "${FILE_PREFIX}.pcap" \
        >> "${CAPTURE_DIR}/capture_${IFACE}.log" 2>&1 &
}

########################################
# Main Loop
########################################

while true; do

    TODAY=$(date +%Y-%m-%d)
    log "Starting new daily capture cycle for $TODAY"

    # Start per-interface capture
    for IFACE in $(get_interfaces); do
        start_capture_for_interface "$IFACE"
    done

    # Disk monitoring loop
    while true; do

        sleep "$CHECK_INTERVAL"

        FREE_PERCENT=$(get_free_percent)

        if (( FREE_PERCENT < MIN_FREE_PERCENT )); then
            log "Disk free space below ${MIN_FREE_PERCENT}% (currently ${FREE_PERCENT}%)."
            stop_all_captures
            exit 1
        fi

        NOW=$(date +%s)
        END_OF_DAY=$(date -d "today 23:59:59" +%s)

        if (( NOW > END_OF_DAY )); then
            log "Midnight boundary reached. Restarting captures."
            stop_all_captures
            break
        fi

    done

done

