#!/bin/bash
# stop_cowrie.sh
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COWRIE_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)/cowrie"

cd "$COWRIE_DIR"
source cowrie-env/bin/activate
cowrie stop
