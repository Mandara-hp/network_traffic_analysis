#!/usr/bin/env bash
# Case 04 - reproduce. Generate first (see README).
F=~/pcap-work/04-dns-exfil/dns-exfil.pcapng
Q() { tshark -n -r "$1" -Y "dns.flags.response==0" -T fields -e dns.qry.name; }

capinfos "$F"
echo "Query types (1=A, 16=TXT):"
tshark -n -r "$F" -Y "dns.flags.response==0" -T fields -e dns.qry.type | sort | uniq -c
echo "Average query-name length:"
Q "$F" | awk '{s+=length($0)} END {printf "%.1f over %d queries\n", s/NR, NR}'
echo "Anomaly scores:"
Q "$F" | python3 tools/dns-anomaly.py
echo "Rebuilt exfiltrated data:"
Q "$F" | python3 tools/dns-rebuild.py --domain exfil.test

# Same scorer on the baseline (case 05) for comparison
B=~/pcap-work/05-baseline/baseline.pcapng
[ -f "$B" ] && { echo "Baseline scores:"; Q "$B" | python3 tools/dns-anomaly.py | head; }
