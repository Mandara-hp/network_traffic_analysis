#!/usr/bin/env bash
# Case 02 - reproduce every finding. Run from the repo root.
F=~/pcap-work/02-phishing-download/2025-01-22-traffic-analysis-exercise.pcap
VICTIM="${VICTIM:-SET_ME}"

capinfos "$F"
tools/triage.sh "$F"
tools/host-id.sh "$F"

# Everything the victim looked up, in time order (find the fake 'authenticator' site)
tshark -n -r "$F" -Y "ip.src==$VICTIM && dns.flags.response==0" -T fields -e frame.time_utc -e dns.qry.name

# HTTPS site names in time order
tshark -n -r "$F" -Y "ip.src==$VICTIM && tls.handshake.type==1" -T fields \
  -e frame.time_utc -e ip.dst -e tls.handshake.extensions_server_name

# Export HTTP objects OUTSIDE the repo, then hash (never open)
mkdir -p ~/pcap-work/02-phishing-download/exported
tshark -n -r "$F" -q --export-objects http,$HOME/pcap-work/02-phishing-download/exported
shasum -a 256 ~/pcap-work/02-phishing-download/exported/* 2>/dev/null

# Beaconing / C2
tshark -n -r "$F" -Y "tcp.flags.syn==1 && tcp.flags.ack==0" -T fields \
  -e frame.time_epoch -e ip.src -e ip.dst -e tcp.dstport | python3 tools/beacon-check.py

tools/extract-iocs.sh "$F" "$VICTIM" | python3 tools/defang.py
