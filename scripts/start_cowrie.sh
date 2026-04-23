#!/bin/bash
# start_cowrie.sh
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
COWRIE_DIR="$(cd "$PROJECT_DIR/.." && pwd)/cowrie"

set -e

cd "$COWRIE_DIR"
source cowrie-env/bin/activate

echo "[1/3] Generating fake filesystem..."
python3 "$PROJECT_DIR/dashboard/generate_fs.py" --cowrie-dir "$COWRIE_DIR"

echo "[2/3] Building pickle..."
mkdir -p "$COWRIE_DIR/share/cowrie/"
rm -f "$COWRIE_DIR/share/cowrie/custom.pickle"
createfs -l /tmp/cowrie-src -d 5 -o "$COWRIE_DIR/share/cowrie/custom.pickle"

echo "[3/3] Starting Cowrie..."
cowrie start
echo "Done."
