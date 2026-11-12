# Case NN: <title>

| | |
|--|--|
| **Source** | <link to the capture's page, not the file> |
| **Capture file** | `<name>.pcap`, SHA-256 `<hash>` |
| **Time span (UTC)** | <first packet> → <last packet> |
| **Analyst** | Mandara Hassan Puttaswamy |
| **Verdict** | Malicious / Benign / Suspicious |

## 1. Executive summary
<3–4 sentences for a manager: what happened, which host, impact, what to do.>

## 2. Infected / involved host
| Field | Value | Evidence |
|-------|-------|----------|
| IP address | | DHCP, frame # |
| MAC address | | |
| Hostname | | NBNS / DHCP / Kerberos |
| User account | | Kerberos CNameString |

## 3. Timeline (UTC)
| Time | Event | Evidence (frame / filter) |
|------|-------|---------------------------|
| | | |

## 4. Analysis
### 4.1 What I looked at first and why
### 4.2 Key findings
<One subsection per finding: screenshot (`img/`), filter used, and what it means.>

## 5. Indicators of compromise
Full list: `iocs.csv` (in the case folder). All defanged.

| Type | Indicator | Context |
|------|-----------|---------|
| Domain | | |
| IP:port | | |
| URL | | |
| SHA-256 | | |

## 6. Detection opportunity
- **ATT&CK:** <Txxxx: name>
- **Logic (plain English):** <e.g. "alert when one internal host makes more than N connections to the same external IP at a regular interval">
- **Rule sketch:** <Suricata / Sigma / SIEM query>
- **False positives to expect:** <e.g. software update checks also beacon>

## 7. Reproduce
All commands: `commands.sh` (in the case folder)

## 8. What I learned
<2–3 bullets: honest, specific.>
