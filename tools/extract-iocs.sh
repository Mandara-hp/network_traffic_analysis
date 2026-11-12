#!/usr/bin/env bash
# extract-iocs.sh: list IOC candidates from one suspect host's traffic (methodology step 6).
# Output is CANDIDATES. You still have to confirm each one (threat intel, context)
# and delete the benign ones (Microsoft, Google, CDNs...) before publishing.
# Usage: tools/extract-iocs.sh capture.pcap <victim-ip>
set -eu   # no pipefail: "| head" closes the pipe early and would kill the script

F="${1:?usage: extract-iocs.sh <capture.pcap> <victim-ip>}"
V="${2:?victim ip required}"
t() { tshark -n -r "$F" "$@"; }

echo "type,indicator,first_seen_utc,context"

# External IP:port the victim connected to
t -Y "ip.src==$V && tcp.flags.syn==1 && tcp.flags.ack==0" -T fields -E separator=, \
   -e ip.dst -e tcp.dstport -e frame.time_utc \
 | grep -vE '^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)' \
 | awk -F, '!seen[$1":"$2]++ {print "ip-port,"$1":"$2","$3",tcp connection"}'

# Domains queried
t -Y "ip.src==$V && dns.flags.response==0" -T fields -E separator=, -e dns.qry.name -e frame.time_utc \
 | awk -F, '!seen[$1]++ {print "domain,"$1","$2",dns query"}'

# HTTP URLs
t -Y "ip.src==$V && http.request" -T fields -E separator=, -e http.host -e http.request.uri -e frame.time_utc \
 | awk -F, '!seen[$1$2]++ {print "url,http://"$1$2","$3",http "}'

# TLS SNI
t -Y "ip.src==$V && tls.handshake.type==1" -T fields -E separator=, \
   -e tls.handshake.extensions_server_name -e frame.time_utc \
 | awk -F, '$1!="" && !seen[$1]++ {print "sni,"$1","$2",tls client hello"}'
