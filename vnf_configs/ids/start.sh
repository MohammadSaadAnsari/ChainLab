#!/bin/sh
set -eu
touch /run/sfc-active
echo "[IDS] Watching eth1 for GET /attack or X-SFC-Attack: 1" >&2
exec python3 -u /app/ids.py
