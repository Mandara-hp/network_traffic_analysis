# 02 · Wireshark basics

## The three panes

```
┌──────────────────────────────────────────────┐
│ 1. Packet list: one row per packet           │  <- the "what and when"
├──────────────────────────────────────────────┤
│ 2. Packet details: layers you can expand     │  <- the "envelopes" from 00-fundamentals
├──────────────────────────────────────────────┤
│ 3. Packet bytes: raw hex + ASCII             │  <- the actual data
└──────────────────────────────────────────────┘
```

The filter bar above the list is where you type **display filters** (green = valid, red = typo).

## Capture filters vs display filters (classic interview question)

| | Capture filter | Display filter |
|--|----------------|----------------|
| When | Before or while recording | After, on a saved capture |
| Effect | Packets that don't match are **never saved** | Packets are only **hidden**, and come back when you clear the filter |
| Syntax | BPF: `port 53`, `host 10.0.0.5` | Wireshark: `dns`, `ip.addr == 10.0.0.5` |
| Use for | Keeping captures small | Investigating |

Analysts mostly use display filters, because you never want to throw away evidence.

## Make an "Analysis" profile (one-time setup, about 5 minutes)

A profile is a saved set of settings, so your investigation setup stays separate from the defaults.

1. **Edit → Configuration Profiles → +** → name it `Analysis`.
2. **Time format:** View → Time Display Format → **UTC Date and Time of Day**.
   *Why:* incident timelines and threat-intel reports use UTC. Local time causes mistakes.
3. **Remove** the `No.` and `Length` columns if you like (right-click the column header → untick).
4. **Add columns** (right-click any field in the details pane → *Apply as Column*, or Settings → Columns):

| Column title | Type / field | Why |
|--------------|--------------|-----|
| Src port | `tcp.srcport or udp.srcport` | See which service |
| Dst port | `tcp.dstport or udp.dstport` | Spot odd ports |
| Host | `http.host` | The website name in HTTP |
| SNI | `tls.handshake.extensions_server_name` | The website name in HTTPS |
| Info | (keep the default) | Wireshark's summary |

5. **Settings → Name Resolution → untick everything** (see the safety guide).
6. **Filter buttons:** click **+** at the right of the filter bar and save:
   - `web`: `(http.request or tls.handshake.type == 1) and !(ssdp)`
   - `dns`: `dns.flags.response == 0`
   - `syn`: `tcp.flags.syn == 1 and tcp.flags.ack == 0`

## The five features you'll use most

| Feature | Where | What it answers |
|---------|-------|-----------------|
| **Follow TCP/HTTP stream** | Right-click a packet → Follow | "Show me the whole conversation as text" |
| **Statistics → Conversations** | Statistics menu | "Who talked to whom, and how much?" Sort by bytes to find the big transfers |
| **Statistics → Protocol Hierarchy** | Statistics menu | "Which protocols are in this capture?" A quick first look |
| **Export Objects → HTTP** | File menu | "Which files were downloaded over HTTP?" Only save them to `~/pcap-work` |
| **Statistics → I/O Graphs** | Statistics menu | "Is there a regular pattern over time?" This shows beaconing |

## tshark: the same thing from the terminal

```bash
tshark -r capture.pcap -Y "dns.flags.response == 0" -T fields -e frame.time_utc -e ip.src -e dns.qry.name
#      -r  read file   -Y  display filter   -T fields -e  print only these fields
```

Why bother when the GUI exists? tshark output can be **copied into the write-up and re-run by anyone**, so your findings are reproducible. Your exact commands go in every case's `commands.sh`.
