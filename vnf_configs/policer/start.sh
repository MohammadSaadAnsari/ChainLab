#!/bin/sh
set -eu

# Every packet reaching eth2 has already passed the firewall and IDS.
tc qdisc replace dev eth2 root tbf rate 1mbit burst 32kbit latency 400ms
touch /run/sfc-active
echo "[POLICER] eth2 shaped to 1 Mbit/s (inspect: tc -s qdisc show dev eth2)" >&2
exec sleep infinity
