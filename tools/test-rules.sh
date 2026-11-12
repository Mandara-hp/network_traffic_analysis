#!/usr/bin/env bash
# Replay every capture through Suricata using ONLY the portfolio rules,
# then compare the rules that fired with the rules that should have fired.
# Usage: tools/test-rules.sh [path-to-pcap-work]   (default: ~/pcap-work)
#
# Why these settings:
#   -r       read a saved capture instead of a live interface
#   -S       load only our rule file (not the thousands of default ET rules)
#   -k none  ignore bad checksums (loopback captures have them, because the
#            network card is meant to fill them in later)
#   HOME_NET includes 127.0.0.0/8 and EXTERNAL_NET=any so the loopback
#            port scan (127.0.0.1 -> 127.0.0.1) is still in scope
set -eu

REPO="$(cd "$(dirname "$0")/.." && pwd)"
WORK="${1:-$HOME/pcap-work}"
RULES="$REPO/rules/portfolio.rules"
OUT="$WORK/suricata-test"
HOME_NET="[10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,127.0.0.0/8]"

command -v suricata >/dev/null || { echo "suricata not found - run: brew install suricata"; exit 1; }
mkdir -p "$OUT"

echo "== Suricata $(suricata -V 2>&1 | grep -o '[0-9][0-9.]*' | head -1)"
echo "== Checking the rule file loads"
suricata -T -S "$RULES" -k none -v \
  --set vars.address-groups.HOME_NET="$HOME_NET" \
  --set vars.address-groups.EXTERNAL_NET=any 2>&1 \
  | grep -iE "rules successfully loaded|failed|error" || true

run() {
  name="$1"; pcap="$WORK/$2"
  if [ ! -f "$pcap" ]; then echo "missing capture: $pcap"; return 0; fi
  mkdir -p "$OUT/$name"
  rm -f "$OUT/$name/eve.json" "$OUT/$name/fast.log"
  suricata -r "$pcap" -S "$RULES" -k none -l "$OUT/$name" \
    --set vars.address-groups.HOME_NET="$HOME_NET" \
    --set vars.address-groups.EXTERNAL_NET=any \
    >"$OUT/$name/run.log" 2>&1 || echo "Suricata error on $name - see $OUT/$name/run.log"
}

echo "== Replaying captures (takes a minute)"
run 01-c2        01-malware-c2/2026-02-28-traffic-analysis-exercise.pcap
run 02-phishing  02-phishing-download/2025-01-22-traffic-analysis-exercise.pcap
run 03-connect   03-port-scan/portscan.pcapng
run 03-syn       03-port-scan/synscan.pcapng
run 04-dns       04-dns-exfil/dns-exfil.pcapng
run 05-baseline  05-baseline/baseline.pcapng

python3 - "$OUT" <<'PY'
import json, sys, os, collections
out = sys.argv[1]
expected = {
    "01-c2":       {1000001, 1000002, 1000003},
    "02-phishing": {1000101, 1000102, 1000103, 1000104},
    "03-connect":  {1000201},
    "03-syn":      {1000201, 1000202},
    "04-dns":      {1000301},
    "05-baseline": set(),
}
print("\n%-12s %-6s %-28s %-22s %s" % ("capture", "result", "fired (sid x count)", "missed", "unexpected"))
allok = True
for name, exp in expected.items():
    path = os.path.join(out, name, "eve.json")
    counts = collections.Counter()
    if os.path.exists(path):
        for line in open(path):
            try: e = json.loads(line)
            except ValueError: continue
            if e.get("event_type") == "alert":
                counts[e["alert"]["signature_id"]] += 1
    fired = set(counts)
    missed, extra = exp - fired, fired - exp
    ok = not missed and not extra
    allok &= ok
    f = " ".join("%d x%d" % (s % 1000, counts[s]) for s in sorted(counts)) or "-"
    print("%-12s %-6s %-28s %-22s %s" % (name, "PASS" if ok else "FAIL", f,
          " ".join(str(s) for s in sorted(missed)) or "-",
          " ".join(str(s) for s in sorted(extra)) or "-"))
print("\n(sids shown as last 3 digits, e.g. 001 = 1000001)")
print("ALL PASS" if allok else "Some rules need work - see the missed/unexpected columns.")
PY
