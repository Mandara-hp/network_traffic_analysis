# 03 · Filter and tshark cheat sheet

## Display filters

### Basics
| Goal | Filter |
|------|--------|
| Traffic to or from one IP | `ip.addr == 10.0.0.5` |
| Only from that IP | `ip.src == 10.0.0.5` |
| Exclude an IP | `!(ip.addr == 10.0.0.5)` |
| One port | `tcp.port == 443` |
| Combine | `ip.addr == 10.0.0.5 and tcp.port == 80` |
| Text inside a packet | `frame contains "password"` |

### Host identification
| Goal | Filter |
|------|--------|
| DHCP (IP, MAC, hostname) | `dhcp` |
| NetBIOS names | `nbns` |
| Kerberos user accounts | `kerberos.CNameString` |
| Hostname in DHCP | `dhcp.option.hostname` |

### Web traffic
| Goal | Filter |
|------|--------|
| HTTP requests + HTTPS connections | `http.request or tls.handshake.type == 1` |
| Only HTTP GET/POST | `http.request.method == "GET"` / `== "POST"` |
| Downloads of Windows programs | `http.response and http.content_type contains "application"` |
| HTTPS site names | `tls.handshake.extensions_server_name` |
| Plain HTTP on an unusual port | `http and !(tcp.port == 80)` |

### DNS
| Goal | Filter |
|------|--------|
| All queries | `dns.flags.response == 0` |
| Failed lookups (NXDOMAIN) | `dns.flags.rcode == 3` |
| Very long names (tunnelling sign) | `len(dns.qry.name) > 50` |
| TXT records (often abused) | `dns.qry.type == 16` |

### TCP / scanning
| Goal | Filter |
|------|--------|
| Connection attempts (SYN only) | `tcp.flags.syn == 1 and tcp.flags.ack == 0` |
| Open ports (SYN/ACK replies) | `tcp.flags.syn == 1 and tcp.flags.ack == 1` |
| Closed ports (RST replies) | `tcp.flags.reset == 1` |
| Retransmissions / problems | `tcp.analysis.flags` |

## tshark one-liners

```bash
F=capture.pcap

capinfos $F                                   # time span, packet count, size
tshark -r $F -q -z io,phs                     # protocol hierarchy
tshark -r $F -q -z conv,ip                    # IP conversations (who talked to whom)
tshark -r $F -q -z endpoints,ip               # every IP seen
tshark -r $F -q -z http,tree                  # HTTP request summary

# DNS queries, counted
tshark -r $F -Y "dns.flags.response==0" -T fields -e dns.qry.name | sort | uniq -c | sort -rn

# HTTP requests
tshark -r $F -Y http.request -T fields -e frame.time_utc -e ip.src -e ip.dst -e http.host -e http.request.uri

# HTTPS site names
tshark -r $F -Y "tls.handshake.type==1" -T fields -e frame.time_utc -e ip.dst -e tls.handshake.extensions_server_name

# Export HTTP files (into the current folder: run this in ~/pcap-work only)
tshark -r $F -q --export-objects http,./exported
shasum -a 256 exported/*
```

## Defanging

| Real | Defanged |
|------|----------|
| `http://evil.com/a.exe` | `hxxp://evil[.]com/a.exe` |
| `185.1.2.3` | `185.1.2[.]3` |

Or run `python3 tools/defang.py < iocs_raw.csv > iocs.csv`.
