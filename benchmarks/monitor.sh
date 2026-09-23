#!/usr/bin/env bash
# Watches CPU and RSS of the running honeypot and classifier processes.
# Run this in one terminal while benchmarks/flood_test.py runs in another.
#
# Usage (with Echidra already started via 'echidra start'):
#   ./benchmarks/monitor.sh
#
# Requires GNU 'watch'. On macOS: brew install watch

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PID_FILE="$REPO_ROOT/logs/echidra.pid"

if [ ! -f "$PID_FILE" ]; then
    echo "No $PID_FILE found. Start Echidra first with 'echidra start', then re-run this script." >&2
    exit 1
fi

PIDS="$(paste -sd, "$PID_FILE")"

watch -n 1 "ps -p $PIDS -o pid,%cpu,rss,comm; echo '-----------------------------'; ps -p $PIDS -o rss= | awk '{sum+=\$1} END {printf \"Total RSS: %.1f MB\n\", sum/1024}'"
