#!/usr/bin/env bash
# Case 03 - reproduce. Connect-scan capture: tools/capture-portscan.sh
# SYN-scan capture (needs sudo) - see bottom of file.
F=~/pcap-work/03-port-scan/portscan.pcapng

capinfos "$F"
echo "SYNs sent (connection attempts):"
tshark -n -r "$F" -Y "tcp.flags.syn==1 && tcp.flags.ack==0" | wc -l
echo "Unique destination ports probed:"
tshark -n -r "$F" -Y "tcp.flags.syn==1 && tcp.flags.ack==0" -T fields -e tcp.dstport | sort -u | wc -l
echo "OPEN ports (answered SYN/ACK):"
tshark -n -r "$F" -Y "tcp.flags.syn==1 && tcp.flags.ack==1" -T fields -e tcp.srcport | sort -nu
echo "CLOSED ports = SYNs - SYN/ACKs (RST count alone also includes the scanner's own resets on open ports):"
echo $(( $(tshark -n -r "$F" -Y "tcp.flags.syn==1 && tcp.flags.ack==0" | wc -l) - $(tshark -n -r "$F" -Y "tcp.flags.syn==1 && tcp.flags.ack==1" | wc -l) ))
echo "Scan duration (first to last SYN, seconds):"
tshark -n -r "$F" -Y "tcp.flags.syn==1 && tcp.flags.ack==0" -T fields -e frame.time_relative | sed -n '1p;$p'
echo "Flag combinations (the scan's fingerprint):"
tshark -n -r "$F" -T fields -e tcp.flags.str | sort | uniq -c | sort -rn
echo "Closed port (80) vs open port (8000), packet by packet:"
tshark -n -r "$F" -Y 'tcp.port==80 || tcp.port==8000' -T fields -e frame.time_relative -e tcp.srcport -e tcp.dstport -e tcp.flags.str
echo "Distinct scanner source ports:"
tshark -n -r "$F" -Y 'tcp.flags.syn==1 && tcp.flags.ack==0' -T fields -e tcp.srcport | sort -u | wc -l
echo "Probe order (first 20):"
tshark -n -r "$F" -Y 'tcp.flags.syn==1 && tcp.flags.ack==0' -T fields -e tcp.dstport | head -20 | tr '\n' ' '; echo

# --- SYN ("half-open") scan comparison - run manually, needs sudo ---
# cd ~/pcap-work/03-port-scan
# python3 -m http.server 8000 --bind 127.0.0.1 >/dev/null 2>&1 & S=$!
# tshark -i lo0 -f tcp -w synscan.pcapng -q & C=$!; sleep 2
# sudo nmap -sS -Pn -p 1-1024,8000 127.0.0.1
# sleep 2; kill $C $S
# tshark -n -r synscan.pcapng -Y 'tcp.port==8000' -T fields -e tcp.srcport -e tcp.dstport -e tcp.flags.str
# tshark -n -r synscan.pcapng -Y 'tcp.flags.syn==1 && tcp.flags.ack==0' -T fields -e tcp.srcport | sort -u | wc -l
