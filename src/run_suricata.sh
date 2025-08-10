#!/usr/bin/env bash
set -euo pipefail
PCAP_DIR=${1:-pcaps}
OUT_DIR=${2:-out}
mkdir -p "$OUT_DIR"
echo "[*] Running Suricata on PCAPs in $PCAP_DIR -> $OUT_DIR"
for p in "$PCAP_DIR"/*.pcap*; do
  [ -e "$p" ] || { echo "No PCAPs in $PCAP_DIR"; exit 1; }
  suricata -r "$p" -l "$OUT_DIR" --set outputs.eve.enabled=yes
done
echo "[*] Done. Check $OUT_DIR/eve.json (or eve-*.json depending on config)."
