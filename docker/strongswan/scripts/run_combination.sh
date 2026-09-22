#!/bin/bash
# Run ONE VPN configuration through the testbed (all 5 traffic classes + the IKE handshake).
# The old version of this script started tcpdump only AFTER the tunnel was up and stopped
# it with pkill, so it never saw the IKE negotiation. The capture logic now lives in
# traffic-engineer/scripts/orchestrate.py (starts tcpdump first, stops by time).
#
# Usage (from the repo root, with `docker compose up -d` already running in docker/strongswan):
#   ./docker/strongswan/scripts/run_combination.sh aes128-dh14-tunnel-pfs-on
set -e
COMBO=$1
if [ -z "$COMBO" ]; then
  echo "Usage: $0 <combination-name>   (see: python traffic-engineer/scripts/orchestrate.py --list)"
  exit 1
fi
cd "$(dirname "$0")/../../.."
python traffic-engineer/scripts/orchestrate.py --combo "$COMBO"
