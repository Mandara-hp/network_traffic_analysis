# Case 04: DNS tunnelling / exfiltration

> **Status:** ⏳ in progress

| | |
|--|--|
| **Source** | Self-generated: `tools/dns-exfil-sim.py` sends fake "HR data" as DNS queries to localhost |
| **Safety** | Destination 127.0.0.1, and the domain is `exfil.test` (`.test` is reserved by RFC 2606 and never resolves). **No packet leaves my Mac.** The data is fake |

## Background in 30 seconds
Firewalls often let DNS out freely, because everything needs it. Attackers abuse that by hiding data inside the *names* they look up:

```
0007.mfrgg2lonbqw4zjaojswg33smqqgk6dbnvyg.exfil.test
 ^seq  ^ base32-encoded stolen data           ^ attacker's domain
```
The attacker's DNS server for that domain logs every query and rebuilds the file. Real tools: iodine, dnscat2.

**Signs (what we measure):**
1. **Very long query names.** Normal ones are ~15–30 characters.
2. **Many unique subdomains** under one parent domain.
3. **High entropy:** random-looking characters.
4. **Odd record types:** lots of TXT queries.
5. **Volume:** far more queries to one domain than normal.

## Generate the capture
```bash
mkdir -p ~/pcap-work/04-dns-exfil
# Terminal 1: capture
tshark -i lo0 -f "udp port 53" -w ~/pcap-work/04-dns-exfil/dns-exfil.pcapng
# Terminal 2: send (with normal-looking lookups mixed in as "noise")
python3 tools/dns-exfil-sim.py --noise
# back in Terminal 1: Ctrl+C
```

## How I worked it

| # | What | Command / filter | Why |
|---|------|------------------|-----|
| 1 | All queries | `dns.flags.response==0` | Start broad |
| 2 | Long names | `len(dns.qry.name) > 50` | Data takes space |
| 3 | Record types | Statistics → DNS | A TXT-heavy mix is unusual |
| 4 | Score domains | `... -e dns.qry.name \| python3 tools/dns-anomaly.py` | Unique subdomains + length + entropy in one table |
| 5 | Rebuild the data | see `commands.sh` (sort by sequence number, join, base32-decode) | **Proves** exfiltration and shows exactly what was stolen. That's the impact |
| 6 | Compare to baseline | Run the same scorer on case 05's capture | Shows the thresholds don't flag normal traffic |

## Findings
*TODO: queries per minute, average name length vs baseline, entropy score, rebuilt data (screenshot)*

## Detection opportunity
- **ATT&CK:** T1071.004 (Application Layer Protocol: DNS), T1048 (Exfiltration Over Alternative Protocol)
- **Logic:** per source host + parent domain over 10 minutes: unique subdomains > 50 **and** average query length > 40, or TXT queries > N.
- **Prevention:** only allow DNS through internal resolvers, and block direct outbound port 53.
- **False positives:** CDNs, anti-virus cloud lookups and some telemetry use long random-looking names. Allow-list known parents.

## What I learned
*TODO*
