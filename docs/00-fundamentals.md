# 00 · Fundamentals: what you need before opening a PCAP

Short and plain. Every idea here comes up again in the cases.

## 1. What is a packet? What is a PCAP?

Data crosses a network in small chunks called **packets**. Each packet is like an envelope: an address on the outside (**headers**) and the content inside (**payload**).

A **PCAP** (or the newer **PCAPNG**) is a recording of packets. Wireshark opens it so you can replay what happened, packet by packet, after the event. That's why PCAPs are used in incident response: they're evidence.

## 2. Layers (the simplified TCP/IP model)

Each layer wraps the one above it, like envelopes inside envelopes. Wireshark's middle pane shows these layers top to bottom.

| Layer | What it does | Examples | What you see in Wireshark |
|-------|--------------|----------|---------------------------|
| Link | Delivers the packet on the local network | Ethernet, Wi-Fi | MAC addresses, e.g. `00:1a:2b:...` |
| Internet | Routes between networks | IPv4, IPv6, ICMP | Source/destination IP |
| Transport | Delivers to the right program | TCP, UDP | Source/destination **port** |
| Application | The actual conversation | DNS, HTTP, TLS, SMB, Kerberos | Domains, URLs, file names |

**Why it matters:** an investigation moves through the layers. The MAC address identifies the device, the IP its network location, the port the service, and the application data what it was actually doing.

## 3. IP addresses and ports

- **IP address**: where the host is. Private ranges (`10.x`, `172.16–31.x`, `192.168.x`) are internal. Anything else is the internet.
- **Port**: which program on that host. Common ones: `53` DNS, `80` HTTP, `443` HTTPS, `445` SMB, `88` Kerberos, `3389` RDP, `22` SSH.
- **Rule of thumb:** an internal host talking to an unknown external IP on an odd port (like `4444` or `8080`), especially again and again, is worth a closer look.

## 4. TCP vs UDP

**TCP** is reliable and connection-based. It always starts with the **three-way handshake**:

```
Client  --SYN-->      Server   "I'd like to talk"
Client  <--SYN/ACK--  Server   "OK, I'm listening"
Client  --ACK-->      Server   "Great, starting"
```

- **RST** = "go away / no one's here". **FIN** = "polite goodbye".
- Lots of SYNs with no handshake completing usually means a **port scan** (case 03).

**UDP** is fire-and-forget: no handshake, no guarantee it arrives. DNS normally uses UDP. That's quick, but it also means DNS can be abused to sneak data out (case 04).

## 5. DNS: the internet's phonebook

Before connecting to `example.com`, a computer asks a DNS server "what's the IP for this name?"

- **Query**: the question (`dns.flags.response == 0`)
- **Response**: the answer, with the IP in an **A** (IPv4) or **AAAA** (IPv6) record
- **Why analysts love DNS:** malware almost always looks up its server's domain first. So the DNS queries in a capture are often the quickest way to find malicious domains, *even when the later traffic is encrypted*.

## 6. HTTP vs HTTPS (TLS)

- **HTTP** (port 80) is **plain text**. You can read the URLs, headers and the files being downloaded. Attackers still use it, which helps us (case 02).
- **HTTPS** = HTTP inside **TLS** encryption (port 443). You *can't* read the content, but you can still see:
  - **who** it talked to (IP)
  - **which site** it asked for: the **SNI** (Server Name Indication), sent unencrypted in the TLS "Client Hello"
  - **when, how often, how much**: timing and size patterns, e.g. **beaconing** (case 01)

## 7. Identifying a host on a Windows network

In MTA captures the victim is usually a Windows PC on a company network. These protocols give away who it is:

| Clue | Protocol | Why it leaks |
|------|----------|--------------|
| IP + MAC | DHCP, ARP, Ethernet | The PC asks for an IP when it joins the network |
| Hostname | DHCP, NBNS, Kerberos | Windows announces its name |
| User account | Kerberos | The user logs in to the domain controller |

## 8. Key words

| Term | Meaning |
|------|---------|
| **IOC** | Indicator of compromise: evidence like a bad IP, domain, URL or file hash |
| **C2 / C&C** | Command and control: the attacker's server that infected machines report to |
| **Beaconing** | Malware "checking in" with its C2 at regular intervals |
| **Exfiltration** | Stealing data out of the network |
| **Defanging** | Writing `evil[.]com` instead of `evil.com` so it can't be clicked |
| **Hash (SHA-256)** | A fingerprint of a file. Same file, same hash, so it can be looked up on VirusTotal without opening the file |
| **Baseline** | What normal traffic looks like, so abnormal traffic stands out |
| **MITRE ATT&CK** | A public catalogue of attacker techniques, e.g. T1046 = network service discovery |

## Check yourself (likely interview questions)

1. Why can you still investigate HTTPS traffic you can't decrypt? *(DNS, SNI, IPs, timing, sizes.)*
2. What does a SYN with no SYN/ACK reply mean? *(The port is filtered, or the host is down or dropping traffic.)*
3. Why look at DNS first? *(Malware has to resolve its C2 domain before it can connect.)*
4. Why hash a file instead of opening it? *(It's safe, and the hash can be shared and searched.)*
