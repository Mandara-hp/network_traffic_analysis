#!/usr/bin/env bash
# Case 03 - reproduce. Generate first with: tools/capture-portscan.sh
F=~/pcap-work/03-port-scan/portscan.pcapng

capinfos "$F"
echo "SYNs sent (connection attempts):"
tshark -n -r "$F" -Y "tcp.flags.syn==1 && tcp.flags.ack==0" | wc -l
echo "Unique destination ports probed:"
tshark -n -r "$F" -Y "tcp.flags.syn==1 && tcp.flags.ack==0" -T fields -e tcp.dstport | sort -u | wc -l
echo "OPEN ports (answered SYN/ACK):"
tshark -n -r "$F" -Y "tcp.flags.syn==1 && tcp.flags.ack==1" -T fields -e tcp.srcport | sort -nu
echo "Closed-port replies (RST):"
tshark -n -r "$F" -Y "tcp.flags.reset==1" | wc -l
echo "Scan duration (first to last SYN, seconds):"
tshark -n -r "$F" -Y "tcp.flags.syn==1 && tcp.flags.ack==0" -T fields -e frame.time_relative | sed -n '1p;$p'
