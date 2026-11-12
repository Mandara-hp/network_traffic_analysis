#!/usr/bin/env bash
# capture-portscan.sh: generate and record a port scan of YOUR OWN Mac (case 03).
#
# Legal: only scan machines you own or have written permission to test.
# Scanning other people's systems can break the Computer Misuse Act 1990.
# Here the target is 127.0.0.1 (loopback = your own Mac), so nothing leaves the machine.
#
# Needs: Wireshark (tshark), nmap (brew install nmap), python3
# Usage: tools/capture-portscan.sh
set -euo pipefail
S1=""; S2=""; CAP=""

OUT_DIR="$HOME/pcap-work/03-port-scan"
OUT="$OUT_DIR/portscan.pcapng"
mkdir -p "$OUT_DIR"

echo "[1/4] Opening two 'services' so the scan has something to find (ports 8000 and 8080)"
python3 -m http.server 8000 --bind 127.0.0.1 >/dev/null 2>&1 & S1=$!
python3 -m http.server 8080 --bind 127.0.0.1 >/dev/null 2>&1 & S2=$!
trap 'kill $S1 $S2 $CAP 2>/dev/null || true' EXIT
sleep 1

echo "[2/4] Starting capture on lo0 (loopback) -> $OUT"
tshark -i lo0 -f "tcp" -w "$OUT" -q & CAP=$!
sleep 2

echo "[3/4] Running a TCP connect scan of ports 1-1024 plus 8000 and 8080"
# -sT = full TCP connect scan (works without sudo). -T4 = faster timing. -Pn = skip the host-alive check.
nmap -sT -Pn -T4 -p 1-1024,8000,8080 127.0.0.1

sleep 2
kill $CAP; wait $CAP 2>/dev/null || true
echo "[4/4] Saved: $OUT"
echo "Optional: compare with a SYN ('half-open') scan:  sudo nmap -sS -Pn -p 1-1024 127.0.0.1"
