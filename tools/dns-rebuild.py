#!/usr/bin/env python3
"""dns-rebuild.py: rebuild exfiltrated data from captured DNS queries (case 04).

Recovering the stolen content proves exfiltration and shows the impact,
which is much stronger than "the queries looked weird".

Usage:
  tshark -n -r dns-exfil.pcapng -Y "dns.flags.response==0" -T fields -e dns.qry.name \
      | python3 tools/dns-rebuild.py --domain exfil.test
"""
import argparse
import base64
import sys


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--domain", default="exfil.test")
    a = ap.parse_args()
    suffix = "." + a.domain.strip(".").lower()

    parts = {}
    for line in sys.stdin:
        name = line.strip().lower().rstrip(".")
        if not name.endswith(suffix):
            continue
        labels = name[: -len(suffix)].split(".")
        if len(labels) != 2 or not labels[0].isdigit():
            continue
        parts[int(labels[0])] = labels[1]  # dict = duplicates/retransmits collapse

    if not parts:
        sys.exit(f"no queries found for *{suffix}")
    missing = [i for i in range(max(parts) + 1) if i not in parts]
    if missing:
        print(f"[!] missing chunks: {missing}", file=sys.stderr)

    enc = "".join(parts[i] for i in sorted(parts)).upper()
    enc += "=" * (-len(enc) % 8)  # base32 padding was stripped by the sender
    sys.stdout.write(base64.b32decode(enc).decode(errors="replace"))
    print(f"\n[+] rebuilt from {len(parts)} chunks", file=sys.stderr)


if __name__ == "__main__":
    main()
