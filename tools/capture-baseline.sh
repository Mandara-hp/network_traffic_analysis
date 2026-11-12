#!/usr/bin/env bash
# capture-baseline.sh: record normal traffic from your own Mac (case 05).
#
# While it runs: browse a few normal sites, check email, maybe stream a video. Act normally.
# PRIVACY: this capture contains YOUR IPs, MAC, device names and the sites you visit.
#          Do NOT publish the pcap. Publish only the summary statistics (see the case 05 README).
#
# Usage: tools/capture-baseline.sh [minutes] [interface]   (defaults: 10, en0 = Wi-Fi)
set -euo pipefail

MIN="${1:-10}"
IFACE="${2:-en0}"
OUT_DIR="$HOME/pcap-work/05-baseline"
OUT="$OUT_DIR/baseline.pcapng"
mkdir -p "$OUT_DIR"

echo "Capturing $MIN minutes on $IFACE -> $OUT"
echo "Use your Mac normally until it finishes."
# -a duration:N = stop automatically after N seconds
tshark -i "$IFACE" -a "duration:$((MIN*60))" -w "$OUT" -q
echo "Done. Next: tools/triage.sh $OUT > ~/pcap-work/05-baseline/triage.txt"
