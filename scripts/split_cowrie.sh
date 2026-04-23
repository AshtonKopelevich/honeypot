#!/bin/bash
# split_cowrie.sh
# Rebuild the analysis database from Cowrie's live JSONL log.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

/usr/bin/python3 "$PROJECT_DIR/dashboard/session_parser.py" \
    --log    "$PROJECT_DIR/logs/raw-logs/cowrie.json" \
    --output "$PROJECT_DIR/logs/analysis" \
    --format both
