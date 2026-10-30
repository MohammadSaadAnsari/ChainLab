#!/bin/sh
set -eu

# The topology adds eth1/eth2 and br0 after Docker starts this process.
while [ ! -e /run/sfc-ready ]; do
    sleep 0.1
done
exec /app/start.sh
