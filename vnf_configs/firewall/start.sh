#!/bin/sh
set -eu
nft -f /app/rules.nft
touch /run/sfc-active
echo "[FIREWALL] Bridge rule active: TCP/23 is dropped; HTTP is counted" >&2
exec python3 -u /app/observe.py
