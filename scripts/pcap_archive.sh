#!/usr/bin/env bash

# ==============================
# PCAP Daily Archive Script
# ==============================

# ============================================================
# PCAP Archive Script to manage and PCAP files for traffic
# and platform management, and diagnostics
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
ARCHIVE_DIR="/var/log/pcap/archive"

########################################

HOSTNAME=$(hostname -s)
YESTERDAY=$(date -d "yesterday" +%Y-%m-%d)

mkdir -p "$ARCHIVE_DIR"

cd "$CAPTURE_DIR"

FILES=$(ls ${HOSTNAME}_${YESTERDAY}_*.pcap* 2>/dev/null || true)

if [[ -z "$FILES" ]]; then
    echo "No PCAP files found for $YESTERDAY"
    exit 0
fi

ARCHIVE_FILE="${HOSTNAME}_${YESTERDAY}.tar.gz"

echo "Archiving PCAP files for $YESTERDAY"

tar -czf "$ARCHIVE_FILE" ${HOSTNAME}_${YESTERDAY}_*.pcap*

mv "$ARCHIVE_FILE" "$ARCHIVE_DIR/"

# Remove original PCAP files
rm -f ${HOSTNAME}_${YESTERDAY}_*.pcap*

echo "Archive created: ${ARCHIVE_DIR}/${ARCHIVE_FILE}"
