# 05: Testing the detection rules with Suricata

Every case ends with a rule idea. A rule nobody has tested is only a guess, so this step replays all five captures through **Suricata 8.0.8** using only my rules and checks two things:

1. **Does each rule fire on the attack it was written for?** (no misses)
2. **Does anything fire on clean traffic?** (no false positives)

## How to run it

```
brew install suricata
./tools/test-rules.sh
```

- [`rules/portfolio.rules`](../rules/portfolio.rules): the 10 rules, copied from the case write-ups
- [`tools/test-rules.sh`](../tools/test-rules.sh): replays each capture (`suricata -r`), reads the alerts from `eve.json`, and compares them with the rules expected to fire

Settings worth knowing about:

| Setting | Why |
| --- | --- |
| `-S portfolio.rules` | Load **only** my rules, not the thousands of default ones, so every alert is mine to explain |
| `-k none` | Ignore bad checksums. Loopback captures (cases 03–04) have them because the OS leaves checksums to the network card |
| `HOME_NET` includes `127.0.0.0/8`, `EXTERNAL_NET=any` | The port scan went from 127.0.0.1 to 127.0.0.1. With the default settings it would be out of scope, and the test would "pass" by ignoring it |
| Output in `~/pcap-work/suricata-test/` | Alert logs contain capture data, so they stay out of the repo |

## Final result

| Capture | Should fire | Fired (alerts) | Result |
| --- | --- | --- | --- |
| 01 NetSupport C2 | 1000001, 1000002, 1000003 | 001 ×264 · 002 ×5 · 003 ×2 | PASS |
| 02 Phishing → PowerShell C2 | 1000101–1000104 | 101 ×6 · 102 ×22 · 103 ×4 · 104 ×9 | PASS |
| 03 Connect scan | 1000201 only | 201 ×1 | PASS |
| 03 SYN scan | 1000201, 1000202 | 201 ×1 · 202 ×1 | PASS |
| 04 DNS exfiltration | 1000301 | 301 ×1 | PASS |
| 05 Clean baseline | **nothing** | nothing | PASS |

All 10 rules load (`10 rules successfully loaded, 0 rules failed`). Each one fires on its own attack, and none fires on my clean traffic.

**The connect scan is a deliberate negative test.** Rule 1000202 looks for nmap's crafted SYN (TCP window 1024). It fires on the SYN scan and stays quiet on the connect scan, which uses the normal OS handshake. On these two captures it told the scan types apart, rather than just reacting to "lots of SYNs".

## What testing found (two fixes)

### Fix 1: the DNS rule missed the attack entirely (1000301, rev 1 → rev 2)

First run: `04-dns FAIL, missed 1000301`. Suricata had parsed every DNS query correctly, so the problem was the rule itself:

```
rev 1   pcre:"/^[a-z0-9]{40,}\./i"        ^ = the long label must come FIRST
query   0000.inhu4rsjircu4vcjifgcaljaizauwrjakrcvgvbairaviqjaiz.exfil.test
        ^^^^ a short sequence label comes first, so it never matched
rev 2   pcre:"/(^|\.)[a-z0-9]{40,}\./i"   a 40+ character label ANYWHERE in the name
```

Real tools can add prefixes or counters too, so anchoring to the first label is an evasion risk. Before re-running, both patterns were checked against the real query names. Old pattern: 0 of 55 matched. New pattern: 40 of 55 (every full data chunk). On the baseline, both matched 0 of 88, so the fix adds no false positives.

It raises **one** alert, not 40, because of `threshold:type both, count 10, seconds 60`: one alert per source per minute once it has seen 10 long names.

### Fix 2: one rule flooded the queue (1000002, rev 1 → rev 2)

"Cleartext HTTP to port 443" fired **273** times for one infected host. Digging into the count:

- The capture has **264** real check-ins. Rule 1000001 works on HTTP **transactions** and counted exactly 264, which matches my Wireshark count.
- **9** of those POSTs were sent twice (TCP retransmissions), giving 273 packets.
- Rule 1000002 has no HTTP content to match, so it was firing on every **packet**, retransmissions included.

273 alerts for one host is noise an analyst would learn to ignore. Adding `threshold:type limit, track by_src, count 1, seconds 3600` caps it at one alert per host per hour. Over the 4 h 21 m capture that gives **5 alerts**, exactly as predicted.

Rule 1000003 fired only twice. That is correct: the `Server: NetSupport Gateway` header appears exactly twice in the whole capture.

## Limits of this test

- **Not an independent test.** Each rule was written from the capture it was then tested on, so passing there mostly shows the rule is written correctly. The more meaningful results are the **0 alerts on the clean baseline**, the **connect-scan negative test**, and the **two bugs testing exposed**. A real check needs captures the rules have never seen.
- **Small sample.** One clean baseline (about 10 minutes of my own traffic) can't prove a rule is false-positive-free on a corporate network. The rule write-ups list the expected false positives (legitimate NetSupport, vulnerability scanners, CDN names).
- **Lab captures.** Cases 03 and 04 are self-generated, so the rules match my simulation. Real tools may vary (e.g. nmap's window can be changed).
- **Campaign-specific rules age.** 1000101 (the `/api/file/get-file/` path) will stop working when the attacker changes the URL. The behaviour rules (no User-Agent, HTTP on 443, bare-IP SNI) last longer.

## Next step

Send Suricata's `eve.json` alerts into the Elastic SIEM in [SOC-lab](https://github.com/Mandara-hp/SOC-lab). Then the whole loop runs end to end: detect → triage → investigate → improve.
