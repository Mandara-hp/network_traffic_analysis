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

# --- Run every detection from cases 01-04 against the baseline ---
echo "FP case 01 - cleartext HTTP on 443:"; tshark -n -r "$F" -Y 'http.request && tcp.dstport==443' | wc -l
echo "FP case 02 - HTTP with no User-Agent:"; tshark -n -r "$F" -Y 'http.request && !http.user_agent' | wc -l
echo "FP case 02 - TLS SNI is a bare IP:"; tshark -n -r "$F" -Y 'tls.handshake.type==1' -T fields -e tls.handshake.extensions_server_name | grep -cE '^[0-9]+(\.[0-9]+){3}$'
echo "FP case 02 - TLS hellos with no SNI / total:"; tshark -n -r "$F" -Y 'tls.handshake.type==1 && !tls.handshake.extensions_server_name' | wc -l; tshark -n -r "$F" -Y 'tls.handshake.type==1' | wc -l
echo "FP case 03 - most distinct ports to one destination:"; tshark -n -r "$F" -Y 'tcp.flags.syn==1 && tcp.flags.ack==0' -T fields -e ip.dst -e tcp.dstport | sort -u | awk '{c[$1]++} END{m=0; for(k in c) if(c[k]>m) m=c[k]; print m}'
echo "Unidentified UDP (\"data\") by port - QUIC check:"; tshark -n -r "$F" -Y 'udp && data' -T fields -e udp.srcport -e udp.dstport | sort | uniq -c | sort -rn | head -5
echo "DNS query types:"; tshark -n -r "$F" -Y 'dns.flags.response==0' -T fields -e dns.qry.type | sort | uniq -c | sort -rn
