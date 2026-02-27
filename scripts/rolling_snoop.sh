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
MAX_SIZE_MB=50                 # Rotate at 50MB
USER_TO_DROP="tcpdump"         # Optional: run as unprivileged user
TCPDUMP_BIN="/usr/sbin/tcpdump"

########################################

HOSTNAME=$(hostname -s)
DATE=$(date +%Y-%m-%d)
START_OF_DAY=$(date -d "today 00:00:00" +%s)
END_OF_DAY=$(date -d "today 23:59:59" +%s)

mkdir -p "$CAPTURE_DIR"

echo "Starting rolling capture for $HOSTNAME on $DATE"

while true; do
    NOW=$(date +%s)

    # If we've crossed midnight, restart loop so new DATE applies
    if [[ "$NOW" -gt "$END_OF_DAY" ]]; then
        echo "Date boundary reached. Restarting capture for new day."
        exec "$0"
    fi

    DATE=$(date +%Y-%m-%d)

    FILE_PREFIX="${CAPTURE_DIR}/${HOSTNAME}_${DATE}_$(date +%H%M%S)"

    # Calculate seconds remaining until midnight
    SECONDS_LEFT=$(( END_OF_DAY - NOW ))

    echo "Capturing to ${FILE_PREFIX}_*.pcap (max ${MAX_SIZE_MB}MB per file)"

    # -i any            = all interfaces
    # -C size           = rotate every N MB
    # -W 1000000        = effectively unlimited rotations
    # -G seconds        = stop at date boundary
    # -w prefix         = file prefix
    # -Z user           = drop privileges
    #
    # We use timeout logic via -G to ensure we do not cross midnight.

    "$TCPDUMP_BIN" \
        -i any \
        -nn \
        -s 0 \
        -C "$MAX_SIZE_MB" \
        -G "$SECONDS_LEFT" \
        -w "${FILE_PREFIX}.pcap" \
        ${USER_TO_DROP:+-Z $USER_TO_DROP} \
        2>>"${CAPTURE_DIR}/capture_errors.log" || true

done
