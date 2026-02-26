#!/bin/bash

# Input file (plain text, no MIME parsing)
INPUT_FILE="$1"

# YARA rules file
YARA_RULES="/home/tpb6/Desktop/custom.yar"

# Optional: Log file (uncomment if you want logging)
# LOG_FILE="/var/log/yara-scan.log"
# exec >> "$LOG_FILE" 2>&1

# Basic validation
if [[ ! -f "$INPUT_FILE" ]]; then
    echo "Error: Input file not found: $INPUT_FILE" >&2
    exit 2
fi

if [[ ! -f "$YARA_RULES" ]]; then
    echo "Error: YARA rules file not found: $YARA_RULES" >&2
    exit 2
fi

# Scan the file directly with YARA
SCAN_RESULT=$(yara "$YARA_RULES" "$INPUT_FILE" 2>/dev/null)

if [[ -n "$SCAN_RESULT" ]]; then
    echo "Blocked by YARA: $SCAN_RESULT"
    exit 1
fi

exit 0
