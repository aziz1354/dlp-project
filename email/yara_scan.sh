#!/bin/bash

# Input: File to scan (passed by Amavis)
INPUT_FILE="$1"

# Directory containing YARA rules
YARA_RULES_DIR="/home/tpb6/Desktop/custom.yar"

# Run YARA scan
yara -r "$YARA_RULES_DIR" "$INPUT_FILE" 2>/dev/null

# Check if YARA found any matches
if [ $? -eq 0 ]; then
    echo "YARA detected a match in the file: $INPUT_FILE"
    exit 1  # Signal Amavis to block/quarantine the email
else
    exit 0  # No matches, allow the email
fi
