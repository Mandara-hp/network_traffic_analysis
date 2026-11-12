#!/usr/bin/env python3
"""dns-anomaly.py: score domains for DNS-tunnelling signs (case 04).

DNS tunnelling hides data in the *subdomain* part of a query:
    MZXW6YTBOI.0001.exfil.test   <- the random-looking label is stolen data
Signs we measure, per parent domain:
  * unique_subs   - many different subdomains (normal sites reuse a few: www, mail)
  * avg_len       - long query names (data takes space; normal ones are short)
  * entropy       - randomness of the subdomain characters (encoded data looks random)

Usage:
  tshark -n -r cap.pcap -Y "dns.flags.response==0" -T fields -e dns.qry.name \
      | python3 tools/dns-anomaly.py

Note: "parent domain" here = last two labels (simple; wrong for e.g. .co.uk).
CDNs and anti-virus lookups can also look random, so check before calling it malicious.

Tuning (after the case 05 baseline): the first version flagged any domain
scoring 2 of 3, which raised two false positives on clean traffic:
  * _tcp.local - mDNS service discovery (long device/service names, never
    leaves the LAN), so .local is now excluded
  * azure.com  - long random-looking cloud hostnames, but only 2 queries
Both scored on length + entropy only. Real exfiltration needs VOLUME
(many unique subdomains), so a domain is now flagged only if
unique_subs >= 20 AND (avg_len > 40 OR entropy > 3.5).
"""
import math
import sys
from collections import Counter, defaultdict


def entropy(s: str) -> float:
    if not s:
        return 0.0
    c = Counter(s)
    return abs(-sum(n / len(s) * math.log2(n / len(s)) for n in c.values()))


def main() -> None:
    by_parent = defaultdict(list)
    skipped_local = 0
    for line in sys.stdin:
        name = line.strip().lower().rstrip(".")
        if not name:
            continue
        if name.endswith(".local"):          # mDNS: link-local, never leaves the LAN
            skipped_local += 1
            continue
        labels = name.split(".")
        parent = ".".join(labels[-2:])
        sub = ".".join(labels[:-2])
        by_parent[parent].append((name, sub))

    rows = []
    for parent, items in by_parent.items():
        subs = {s for _, s in items if s}
        avg_len = sum(len(n) for n, _ in items) / len(items)
        ent = entropy("".join(s.replace(".", "") for s in subs))
        volume = len(subs) >= 20
        score = volume + (avg_len > 40) + (ent > 3.5)
        flagged = volume and (avg_len > 40 or ent > 3.5)
        rows.append((score, len(items), parent, len(subs), avg_len, ent, flagged))

    rows.sort(reverse=True)
    print(f"{'score':>5} {'queries':>8} {'unique_subs':>11} {'avg_len':>8} {'entropy':>8}  parent")
    for score, q, parent, nsubs, avg_len, ent, flagged in rows[:30]:
        flag = "  <-- suspicious" if flagged else ""
        print(f"{score:>5} {q:>8} {nsubs:>11} {avg_len:>8.1f} {ent:>8.2f}  {parent}{flag}")
    if skipped_local:
        print(f"(skipped {skipped_local} .local mDNS queries)")


if __name__ == "__main__":
    main()
