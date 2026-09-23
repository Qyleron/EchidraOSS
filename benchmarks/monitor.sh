#!/usr/bin/env bash
# Watches CPU and RSS of the running honeypot and classifier processes.
# Run this in one terminal while benchmarks/flood_test.py runs in another.
#
# Usage:
#   ./benchmarks/monitor.sh              # reads PIDs from logs/echidra.pid
#                                         # (written by 'echidra start')
#   ./benchmarks/monitor.sh 758,894      # or pass PIDs directly, e.g. when
#                                         # Echidra runs under systemd/Docker
#
# Requires GNU 'watch'. On macOS: brew install watch

set -euo pipefail

if [ "${1:-}" != "" ]; then
    PIDS="$1"
else
    REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
    PID_FILE="$REPO_ROOT/logs/echidra.pid"

    if [ ! -f "$PID_FILE" ]; then
        echo "No $PID_FILE found. Either start Echidra with 'echidra start', or pass PIDs" >&2
        echo "directly if it's already running under systemd/Docker, e.g.:" >&2
        echo "  ./benchmarks/monitor.sh 758,894" >&2
        exit 1
    fi

    PIDS="$(paste -sd, "$PID_FILE")"
fi

watch -n 1 "ps -p $PIDS -o pid,%cpu,rss,comm; echo '-----------------------------'; ps -p $PIDS -o rss= | awk '{sum+=\$1} END {printf \"Total RSS: %.1f MB\n\", sum/1024}'"
