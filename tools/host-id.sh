#!/usr/bin/env bash
# host-id.sh: identify hosts on a Windows LAN (methodology step 3).
# Pulls IP, MAC, hostname and user account from DHCP, NBNS and Kerberos.
# Usage: tools/host-id.sh capture.pcap
set -eu   # no pipefail: "| head" closes the pipe early and would kill the script

F="${1:?usage: host-id.sh <capture.pcap>}"
t() { tshark -n -r "$F" "$@"; }

echo "== DHCP: IP / MAC / hostname (the PC asks for an address and gives its name) =="
t -Y "dhcp.option.hostname" -T fields -E separator=' | ' \
   -e frame.time_utc -e eth.src -e dhcp.option.requested_ip_address -e dhcp.option.hostname | sort -u

echo
echo "== NBNS: NetBIOS names announced on the LAN =="
t -Y "nbns" -T fields -E separator=' | ' -e ip.src -e nbns.name | sort -u | head -n 20

echo
echo "== Kerberos: user accounts (names ending in \$ are machine accounts) =="
t -Y "kerberos.CNameString" -T fields -E separator=' | ' \
   -e ip.src -e ip.dst -e kerberos.CNameString -e kerberos.crealm | sort -u

echo
echo "== Internal IPs seen (private ranges) =="
t -T fields -e ip.src | grep -E '^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)' | sort | uniq -c | sort -rn | head
