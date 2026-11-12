# Network Traffic Analysis Portfolio

Five packet-capture (PCAP) investigations done with **Wireshark** and **tshark**. Each one answers the same questions a SOC analyst gets asked during triage:

1. **What happened?** (a short summary)
2. **Which host and user were affected?** (IP, MAC, hostname, account)
3. **What is the evidence?** (packets, streams, timeline)
4. **What are the IOCs?** (indicators of compromise: IPs, domains, URLs, hashes)
5. **How would we detect this next time?** (detection idea + MITRE ATT&CK mapping)

> Companion project: [SOC-lab](https://github.com/Mandara-hp/SOC-lab), where I build the SIEM detections that the "Detection opportunity" sections here feed into.

## Cases

| # | Case | Source | Key skill shown | ATT&CK | Status |
|---|------|--------|-----------------|--------|--------|
| 01 | [Malware infection: find the C2 (NetSupport RAT)](analyses/01-malware-c2/) | malware-traffic-analysis.net | Host ID, protocol mismatch, beaconing | T1219, T1071, T1571 | ✅ |
| 02 | [Malicious download → PowerShell C2 → TeamViewer + shellcode](analyses/02-phishing-download/) | malware-traffic-analysis.net | Full attack-chain timeline, exporting + decoding scripts, robust beacon stats | T1583.008, T1059.001, T1547.001, T1620 | 🔄 draft |
| 03 | [Port scan](analyses/03-port-scan/) | Self-generated (nmap against my own machine) | TCP flags, scan patterns | T1046 | ⏳ |
| 04 | [DNS tunnelling / exfiltration](analyses/04-dns-exfil/) | Self-generated (local simulation) | DNS anomalies, entropy, query length | T1071.004, T1048 | ⏳ |
| 05 | [Clean baseline](analyses/05-baseline/) | Self-generated (my own normal traffic) | Knowing what normal looks like | n/a | ⏳ |

## Start here if you're new to packet analysis

- [`docs/00-fundamentals.md`](docs/00-fundamentals.md): packets, layers, IPs and ports, TCP vs UDP, DNS, HTTP, TLS, in plain English
- [`docs/01-setup-and-safety.md`](docs/01-setup-and-safety.md): installing Wireshark on macOS (Apple Silicon) and handling malware captures safely
- [`docs/02-wireshark-basics.md`](docs/02-wireshark-basics.md): a tour of the interface, custom columns, following streams, statistics
- [`docs/03-filter-cheatsheet.md`](docs/03-filter-cheatsheet.md): the display filters and tshark commands used in this repo
- [`docs/04-interview-prep.md`](docs/04-interview-prep.md): interview questions this project answers
- [`METHODOLOGY.md`](METHODOLOGY.md): the repeatable workflow every case follows

## Repo layout

```
docs/        beginner guides (read in order)
templates/   the write-up template every case uses
tools/       tshark helper scripts (triage, host ID, IOC extraction, simulations)
analyses/    one folder per case: README write-up, iocs.csv, commands, screenshots
```

## Safety and ethics

- **No PCAPs or malware samples are stored in this repo.** Each case links to its original source, and only hashes are published.
- IOCs are **defanged** (`hxxp://`, `[.]`) so nothing can be clicked by accident.
- Scans and simulations were run **only against machines I own**, within the Computer Misuse Act 1990.
- My own captures were sanitised before publishing.

## Tools

Wireshark 4.x · tshark · capinfos · nmap · Python 3 (standard library only) · macOS on Apple Silicon

## Licence

Scripts: [MIT](LICENSE). Write-ups and docs: [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). Captures from malware-traffic-analysis.net belong to their author and are linked to, not redistributed.
