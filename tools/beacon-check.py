#!/usr/bin/env python3
"""beacon-check.py: spot C2 beaconing from regular connection timing (case 01).

Idea: people browse irregularly, but malware checks in on a timer (e.g. every 60 s).
For each (source -> destination:port) we measure the gaps between new
connections. Lots of connections with very similar gaps = likely beacon.

  CV (coefficient of variation) = stdev(gaps) / mean(gaps)
  CV close to 0  -> clockwork regular (suspicious)
  CV around 1+   -> irregular (human-like)

Usage:
  tshark -n -r cap.pcap -Y "tcp.flags.syn==1 && tcp.flags.ack==0" \
      -T fields -e frame.time_epoch -e ip.src -e ip.dst -e tcp.dstport \
      | python3 tools/beacon-check.py [--min-conns 5] [--max-cv 0.3]

Limits (say these in interviews): malware often adds random "jitter", and
legitimate software (updates, telemetry) beacons too. This finds candidates,
not verdicts.
"""
import argparse
import statistics
import sys
from collections import defaultdict


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--min-conns", type=int, default=5)
    ap.add_argument("--max-cv", type=float, default=0.3)
    a = ap.parse_args()

    flows = defaultdict(list)
    for line in sys.stdin:
        parts = line.split()
        if len(parts) < 4:
            continue
        ts, src, dst, port = float(parts[0]), parts[1], parts[2], parts[3]
        flows[(src, dst, port)].append(ts)

    rows = []
    for (src, dst, port), times in flows.items():
        if len(times) < a.min_conns:
            continue
        times.sort()
        gaps = [b - a_ for a_, b in zip(times, times[1:])]
        mean = statistics.mean(gaps)
        if mean == 0:
            continue
        cv = statistics.pstdev(gaps) / mean
        rows.append((cv, src, dst, port, len(times), mean))

    rows.sort()
    print(f"{'flag':<8}{'src':<16}{'dst:port':<24}{'conns':>6}{'mean_gap_s':>12}{'cv':>7}")
    for cv, src, dst, port, n, mean in rows:
        flag = "BEACON" if cv <= a.max_cv else ""
        print(f"{flag:<8}{src:<16}{dst + ':' + port:<24}{n:>6}{mean:>12.1f}{cv:>7.2f}")
    if not rows:
        print(f"(no flow with >= {a.min_conns} connections)")


if __name__ == "__main__":
    main()
