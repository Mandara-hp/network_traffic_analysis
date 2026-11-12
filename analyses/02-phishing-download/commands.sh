#!/usr/bin/env bash
# Case 02 - reproduce every finding. Run from the repo root.
# PCAP lives OUTSIDE the repo (download from the source link; password infected_20250122)
D=~/pcap-work/02-phishing-download
F=$D/2025-01-22-traffic-analysis-exercise.pcap
C2=5.252.153.241

# Overview + victim
capinfos "$F"; tools/triage.sh "$F"; tools/host-id.sh "$F"

# 4.2 Initial access: DNS answers + TLS names around the lure (25-60 s into the capture)
tshark -n -r "$F" -Y 'dns.flags.response==1 && frame.time_relative > 25 && frame.time_relative < 60' -T fields -e frame.time_utc -e dns.qry.name -e dns.a
tshark -n -r "$F" -Y 'tls.handshake.type==1 && frame.time_relative < 70' -T fields -e frame.time_utc -e ip.dst -e tls.handshake.extensions_server_name

# 4.3-4.6 HTTP chain to the C2 (excluding the poll itself)
tshark -n -r "$F" -Y "ip.dst==$C2 && http.request && !(http.request.uri == \"/1517096937\")" -T fields -e frame.time_utc -e http.request.uri
tshark -n -r "$F" -Y "ip.src==$C2 && http.response && http.content_length > 1000" -T fields -e frame.time_utc -e http.content_length
tshark -n -r "$F" -Y "ip.dst==$C2 && http.request" -T fields -e http.user_agent | sort | uniq -c

# 4.5 Beacon (robust)
tshark -n -r "$F" -Y "ip.dst==$C2 && http.request.uri contains \"1517096937\"" -T fields -e frame.time_epoch -e ip.src -e ip.dst -e tcp.dstport | python3 tools/beacon-check.py

# 4.3-4.7 Export HTTP objects OUTSIDE the repo, then hash (never execute)
mkdir -p $D/exported && tshark -n -r "$F" -q --export-objects http,$D/exported && shasum -a 256 $D/exported/*

# Decode the obfuscated stage-2 PowerShell as TEXT (no execution)
python3 - "$D/exported/29842.ps1" <<'PY'
import re,sys,base64
s=open(sys.argv[1]).read(); enc=re.search(r"\('(J[^']+)'\.replace",s).group(1)
for ch in "};>": enc=enc.replace(ch,"")
print(base64.b64decode(enc).decode())
PY

# 4.7 Second C2: ports, TLS names, and timing vs loader delivery
tshark -n -r "$F" -Y 'ip.dst==45.125.66.32 || ip.dst==45.125.66.252' -T fields -e ip.dst -e tcp.dstport | sort | uniq -c
tshark -n -r "$F" -Y '(ip.dst==45.125.66.32 || ip.dst==45.125.66.252) && tls.handshake.type==1' -T fields -e frame.time_utc -e ip.dst -e tcp.dstport -e tls.handshake.extensions_server_name
tshark -n -r "$F" -Y 'http.request.uri contains "?k="' -T fields -e frame.time_utc -e http.request.uri
