#!/usr/bin/env bash
# Case 05 - baseline stats. Generate first with: tools/capture-baseline.sh 10
F=~/pcap-work/05-baseline/baseline.pcapng

capinfos "$F"
tshark -n -r "$F" -q -z io,phs
echo "DNS queries + average name length:"
tshark -n -r "$F" -Y "dns.flags.response==0" -T fields -e dns.qry.name \
  | awk '{s+=length($0)} END {printf "%d queries, avg len %.1f\n", NR, (NR?s/NR:0)}'
tshark -n -r "$F" -Y "dns.flags.response==0" -T fields -e dns.qry.name | python3 tools/dns-anomaly.py | head
echo "Unique TCP destination ports:"
tshark -n -r "$F" -Y "tcp.flags.syn==1 && tcp.flags.ack==0" -T fields -e tcp.dstport | sort -u | wc -l
echo "Most regular flows (benign beaconing):"
tshark -n -r "$F" -Y "tcp.flags.syn==1 && tcp.flags.ack==0" -T fields \
  -e frame.time_epoch -e ip.src -e ip.dst -e tcp.dstport | python3 tools/beacon-check.py | head
echo "Plain HTTP requests:"
tshark -n -r "$F" -Y "http.request" | wc -l
