# Case 05: Clean baseline (what normal looks like)

> **Status:** ⏳ in progress

| | |
|--|--|
| **Source** | Self-generated: `tools/capture-baseline.sh 10` (10 minutes of my normal Mac use over Wi-Fi) |
| **Privacy** | The pcap is **not published**. It contains my IPs, MAC, device names and browsing. Only aggregate statistics appear here, with my addresses replaced by labels (`MY-MAC`, `ROUTER`) |

## Why a baseline matters
You can't call something abnormal unless you know what normal looks like. Every threshold in cases 01–04 ("too many ports", "names too long", "too regular") only means something compared with this.

It also answers a common interview question: *"How do you avoid false positives?"* Answer: know your baseline, and tune your detections against it.

## Generate the capture
```bash
tools/capture-baseline.sh 10 en0     # browse, email, maybe a video for 10 minutes
tools/triage.sh ~/pcap-work/05-baseline/baseline.pcapng > ~/pcap-work/05-baseline/triage.txt
```

## What to record

| Measure | How | Baseline value | Compare with |
|---------|-----|----------------|--------------|
| Protocol mix | `tshark -q -z io,phs` | *TODO* (expect TLS-heavy, some QUIC/UDP 443, DNS, mDNS) | All cases |
| DNS queries per minute | count ÷ minutes | *TODO* | Case 04 |
| Average DNS name length | see `commands.sh` | *TODO* | Case 04 |
| Highest `dns-anomaly.py` score | run it | *TODO* (should be 0–1) | Case 04 |
| Unique destination ports per minute | see `commands.sh` | *TODO* | Case 03 |
| Most regular flow (`beacon-check.py`) | run it | *TODO*, likely a background service. Note it! | Case 01 |
| Plain HTTP requests | `http.request` count | *TODO* (probably few or none) | Cases 01–02 |

## Findings
*TODO: a short table of the numbers above. Note honestly anything that looks "suspicious" but is benign (e.g. Apple push/iCloud services beaconing). That's the false-positive lesson.*

## What I learned
*TODO*
