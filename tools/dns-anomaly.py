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
    for line in sys.stdin:
        name = line.strip().lower().rstrip(".")
        if not name:
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
        score = (len(subs) >= 20) + (avg_len > 40) + (ent > 3.5)
        rows.append((score, len(items), parent, len(subs), avg_len, ent))

    rows.sort(reverse=True)
    print(f"{'score':>5} {'queries':>8} {'unique_subs':>11} {'avg_len':>8} {'entropy':>8}  parent")
    for score, q, parent, nsubs, avg_len, ent in rows[:30]:
        flag = "  <-- suspicious" if score >= 2 else ""
        print(f"{score:>5} {q:>8} {nsubs:>11} {avg_len:>8.1f} {ent:>8.2f}  {parent}{flag}")


if __name__ == "__main__":
    main()
