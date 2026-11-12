#!/usr/bin/env bash
# triage.sh: first-look summary of a capture (methodology steps 1–2).
# Usage: tools/triage.sh capture.pcap > triage.txt
# Works with macOS's default bash 3.2. Needs tshark + capinfos (they come with Wireshark).
set -eu   # no pipefail: "| head" closes the pipe early and would kill the script

F="${1:?usage: triage.sh <capture.pcap>}"
# -n = no name resolution: never do DNS lookups for attacker IPs
t() { tshark -n -r "$F" "$@"; }

section() { printf '\n==================== %s ====================\n' "$1"; }

section "1. CAPTURE INFO (scope: how long, how big)"
capinfos "$F"

section "2. PROTOCOL HIERARCHY (what protocols are present)"
t -q -z io,phs

section "3. TOP IP CONVERSATIONS (who talked to whom, by bytes)"
t -q -z conv,ip | head -n 30

section "4. DNS QUERIES (count, name) - malware resolves its C2 first"
t -Y "dns.flags.response==0" -T fields -e dns.qry.name | sort | uniq -c | sort -rn | head -n 40

section "5. HTTP REQUESTS (time, src, dst, host, uri) - readable plain text"
t -Y "http.request" -T fields -E separator=' | ' \
   -e frame.time_utc -e ip.src -e ip.dst -e http.request.method -e http.host -e http.request.uri | head -n 60

section "6. HTTPS SITES (TLS SNI) - site names are visible even when encrypted"
t -Y "tls.handshake.type==1" -T fields -e ip.dst -e tls.handshake.extensions_server_name \
   | sort | uniq -c | sort -rn | head -n 40

section "7. TCP DESTINATION PORTS (count, port) - odd ports stand out"
t -Y "tcp.flags.syn==1 && tcp.flags.ack==0" -T fields -e tcp.dstport | sort | uniq -c | sort -rn | head -n 25

echo
echo "Next: tools/host-id.sh $F   (which machine and user?)"
