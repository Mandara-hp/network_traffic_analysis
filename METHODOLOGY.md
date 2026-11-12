# Methodology

Every case follows the same seven steps. Using a fixed process means nothing gets skipped, and the reasoning can be explained to anyone.

| Step | Question | How | Tool |
|------|----------|-----|------|
| 1. **Scope** | What am I looking at? | Time span, packet count, size | `capinfos` |
| 2. **Overview** | Which protocols, which hosts? | Protocol hierarchy, conversations, endpoints | `tools/triage.sh` |
| 3. **Identify the host** | Which machine and user are involved? | DHCP, NBNS, Kerberos | `tools/host-id.sh` |
| 4. **Find suspicious activity** | What's unusual? | DNS → web (HTTP/SNI) → odd ports → big transfers → timing | Wireshark filters |
| 5. **Confirm** | Is it actually malicious? | Follow streams, check against threat intel (VirusTotal, URLhaus, ThreatFox) | Wireshark + browser (**only look IOCs up, never visit them**) |
| 6. **Extract IOCs** | What can others block or hunt for? | IPs, domains, URLs, hashes, defanged | `tools/extract-iocs.sh`, `tools/defang.py` |
| 7. **Detect** | How would a SOC catch this next time? | A detection idea + ATT&CK technique | Suricata/Sigma-style logic |

## Why this order?

- **Scope before detail:** you can't judge "lots of traffic" without knowing the capture covers 10 minutes rather than 10 hours.
- **Host before activity:** an alert is useless if you can't say *which* machine and user to isolate.
- **DNS first among the clues:** malware has to resolve its C2 domain before connecting, and DNS is still readable when HTTPS isn't.
- **Confirm with a second source:** one odd connection isn't proof. Back a finding up with threat intel or a second piece of evidence before calling it malicious.
- **Finish with a detection:** finding one incident is a one-off. A detection idea is what stops the next one.

## Evidence standard

Every claim in a write-up names its **evidence**: a frame number, a filter, or a tshark command in `commands.sh` that reproduces it.
