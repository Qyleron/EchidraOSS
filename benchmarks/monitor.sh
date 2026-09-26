#!/usr/bin/env bash
# Watches CPU and RSS of the running honeypot and classifier processes.
# Run this in one terminal while benchmarks/flood_test.py runs in another.
# CPU is instantaneous (top's second sample), not a lifetime average.
#
# Usage:
#   ./benchmarks/monitor.sh              # reads PIDs from logs/echidra.pid
#                                         # (written by 'echidra start')
#   ./benchmarks/monitor.sh 758,894      # or pass PIDs directly, e.g. when
#                                         # Echidra runs under systemd/Docker
#
# Requires Linux (procps 'top' and 'ps').

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

while true; do
    out="$(top -b -n 2 -d 1 -p "$PIDS" | awk '/^top -/{n++} n==2')"
    clear
    date
    echo "$out" | awk '/^ *PID/{print "  PID  %CPU  RSS_KB COMMAND"; next} /^ *[0-9]/{printf "%5s %5s %7s %s\n", $1, $9, $6, $12}'
    echo "-----------------------------"
    ps -p "$PIDS" -o rss= | awk '{sum+=$1} END {printf "Total RSS: %.1f MB\n", sum/1024}'
done
