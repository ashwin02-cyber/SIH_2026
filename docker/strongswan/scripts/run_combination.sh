#!/bin/bash
set -e

COMBO=$1
if [ -z "$COMBO" ]; then
  echo "Usage: $0 <combination-name>"
  ls scripts/generated_configs/
  exit 1
fi

CONF_FILE="scripts/generated_configs/${COMBO}.conf"
if [ ! -f "$CONF_FILE" ]; then
  echo "Config not found: $CONF_FILE"
  exit 1
fi

echo "=== Swapping in config: $COMBO ==="
cp "$CONF_FILE" configs/peer-a/ipsec.conf
cp "$CONF_FILE" configs/peer-b/ipsec.conf
sed -i 's/left=10.10.0.10/left=10.10.0.20/; s/right=10.10.0.20/right=10.10.0.10/' configs/peer-b/ipsec.conf

echo "=== Recreating containers ==="
docker compose down
docker compose up -d

echo "=== Waiting for tunnel to establish ==="
sleep 8

echo "=== Status ==="
docker exec peer-a ipsec status

echo "=== Starting capture ==="
docker exec -d peer-a tcpdump -i eth0 -w /tmp/capture.pcap -U
sleep 2

echo "=== Generating traffic ==="
docker exec peer-a ping -c 10 10.10.0.20

echo "=== Stopping capture ==="
docker exec peer-a pkill tcpdump || true
sleep 2

echo "=== Copying capture out ==="
docker cp peer-a:/tmp/capture.pcap "./captures/${COMBO}.pcap"

echo "=== Done: captures/${COMBO}.pcap ==="
