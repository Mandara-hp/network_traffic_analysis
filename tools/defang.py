#!/usr/bin/env python3
"""defang.py: make IOCs unclickable before publishing.

  http://evil.com/a.exe  ->  hxxp://evil[.]com/a.exe
  185.1.2.3              ->  185.1.2[.]3

Usage:  python3 tools/defang.py < iocs_raw.csv > iocs.csv
Timestamps, ports and hashes are left alone.
"""
import re
import sys

SCHEME = re.compile(r"\bhttp(s?)://", re.I)
IPV4 = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3})\.(\d{1,3})\b")
# a dot between a label and a letters-only label (domains), not inside numbers like 12.5
DOMAIN_DOT = re.compile(r"(?<=[A-Za-z0-9-])\.(?=[A-Za-z][A-Za-z0-9-]*\b)")


def defang(line: str) -> str:
    line = SCHEME.sub(r"hxxp\1://", line)
    line = IPV4.sub(r"\1[.]\2", line)
    # only touch domain-ish dots in tokens that aren't timestamps
    out = []
    for tok in re.split(r"([,\s])", line):
        if re.search(r"[A-Za-z]", tok) and not re.match(r"^\d{4}-\d{2}-\d{2}", tok):
            tok = DOMAIN_DOT.sub("[.]", tok)
        out.append(tok)
    return "".join(out)


if __name__ == "__main__":
    for raw in sys.stdin:
        sys.stdout.write(defang(raw))
