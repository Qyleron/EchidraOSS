#!/bin/bash
echo "[*] Starting Capture Layer"
python3 /capture_layer/main.py &

echo "[*] Starting Dashboard"
node ./dashboard/server.js
