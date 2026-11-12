# 04 · Interview prep: questions this project lets me answer

| Question | Short answer | Where I showed it |
|----------|--------------|-------------------|
| Walk me through how you'd investigate a PCAP. | Scope → overview → identify host → find anomalies (DNS first) → confirm with intel → IOCs → detection. | `METHODOLOGY.md` |
| Capture vs display filter? | Capture filters (BPF) decide what's **saved**. Display filters only **hide**. I investigate with display filters so I never lose evidence. | `docs/02` |
| The traffic is encrypted. What can you still see? | IPs, ports, DNS queries, TLS SNI, certificate details, timing, sizes. | Cases 01, 05 |
| How do you identify an infected host? | IP/MAC from DHCP, hostname from DHCP/NBNS, user from Kerberos. | `tools/host-id.sh`, cases 01–02 |
| What is beaconing and how do you detect it? | Regular check-ins to C2. Measure the gaps between connections; low variation = suspicious. Jitter and legitimate updaters complicate it. | `tools/beacon-check.py`, case 01 |
| Open vs closed vs filtered port in a capture? | SYN/ACK = open, RST = closed, no reply = filtered. | Case 03 |
| SYN scan vs connect scan? | Connect completes the handshake (no root needed). SYN sends RST instead of the final ACK ("half-open"). | Case 03 |
| How does DNS tunnelling work, and how do you catch it? | Data encoded in subdomains. Catch it with length, unique subdomains, entropy, TXT volume, and only allowing DNS through internal resolvers. | Case 04 |
| How do you avoid false positives? | Know the baseline, confirm with a second source, allow-list known-good. | Case 05 |
| How would you test a new detection before deploying it? | Run it against clean baseline traffic. Mine flagged 2 innocent domains; I found the cause (no volume requirement), tuned it, and re-tested on both attack and clean data. | Cases 04 + 05 |
| What's QUIC and why does it matter to a SOC? | HTTP/3 over UDP 443. Over half my normal bytes were QUIC, so TCP/TLS-only monitoring misses most web traffic. Mid-stream QUIC can't even be labelled without the handshake. | Case 05 |
| What's an IOC, and why defang? | Evidence of compromise (IP, domain, URL, hash). Defanging stops accidental clicks and auto-linking. | Every case |
| Why hash a file instead of opening it? | Safe, unique, searchable on VirusTotal without running anything. | Case 02 |
| How would you handle malware samples safely? | Name resolution off, keep files zipped until needed, isolated folder, never execute, hash and look up. | `docs/01` |
| IOCs vs behaviour-based detection? | IOCs are easy for attackers to change (a new IP). Behaviours (beaconing, protocol mismatch, scan patterns) last longer. That's why each case ends with a behavioural detection. | "Detection opportunity" sections |
| What laws apply to scanning? | Computer Misuse Act 1990: only test systems you own or have written permission for. | Case 03 |

## Detection testing

**Did you test your rules?**
Yes. I replayed all five captures through Suricata 8 with only my 10 rules loaded. Every rule fired on its own attack and nothing fired on my clean baseline. The connect-scan capture was a deliberate negative test: the nmap "window 1024" rule had to stay quiet on it, and did.

**Did anything break?**
Two things. My DNS rule anchored its pattern to the start of the name, and the exfil queries start with a short sequence number, so it missed everything. An attacker could evade it the same way. I changed it to match a long label anywhere in the name and checked the change on the baseline: 0 false positives. Second, my "HTTP on port 443" rule fired on every packet, 273 alerts for one host, because 9 requests were retransmitted. I added a limit of one alert per host per hour, which brought it down to 5.

**Why did one rule count 264 and another 273 on the same traffic?**
Rule 001 matches HTTP transactions: 264 real requests, the same as my Wireshark count. Rule 002 had no HTTP content, so it matched packets, and that count included 9 TCP retransmissions.

