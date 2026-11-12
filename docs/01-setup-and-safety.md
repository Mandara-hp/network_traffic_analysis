# 01 · Setup and safety (macOS, Apple Silicon)

## Install

Pick **one**:

```bash
# Option A: Homebrew (the cask used to be called "wireshark"; it's now "wireshark-app")
brew install --cask wireshark-app

# Option B: download the "Arm 64" .dmg from wireshark.org and tick
#   "Install ChmodBPF" and "Add Wireshark to the system path"
```

Don't use `brew install wireshark` (without `--cask`). That gives you the command-line tools only, with no GUI.

Optional extras for cases 03–04:
```bash
brew install nmap
```

## Check it works

```bash
tshark --version     # CLI installed and on your PATH
tshark -D            # lists interfaces: en0 = Wi-Fi, lo0 = loopback
capinfos -h | head   # capinfos comes with Wireshark too
```

If `tshark -D` shows no interfaces, log out and back in (or reboot).

### Why ChmodBPF?

macOS captures packets through `/dev/bpf*` devices, which only root can read by default. ChmodBPF adds your user to the `access_bpf` group so you can capture **without running Wireshark as root**. Wireshark parses hostile input, and its parsers have had bugs before, so it should never run as root.

Opening a saved PCAP doesn't need capture rights at all. You only need ChmodBPF for live capture (cases 03–05).

## Safety rules for malware captures (read before case 01)

| Rule | Why |
|------|-----|
| **Turn off name resolution**: Settings → Name Resolution → untick "Resolve network addresses" | Otherwise Wireshark does live DNS lookups for attacker IPs from *your* connection. That's an OPSEC leak and can tip off the attacker |
| Work in `~/pcap-work/`, **not** in an iCloud/Dropbox folder | Don't sync malware to the cloud |
| Keep the downloaded `.zip` files password-protected until you need them | That's why MTA zips them: antivirus and email filters won't flag or delete them |
| **Never open exported files.** Hash them: `shasum -a 256 <file>` | They're real malware. Windows payloads won't run on macOS, but malicious Office documents and scripts are still not safe to open |
| Don't visit IOC URLs or domains. Look them up on VirusTotal or urlscan instead | Visiting them contacts live attacker infrastructure |
| Never commit PCAPs, ZIPs or exported objects to git (`.gitignore` blocks them) | The repo is public. Distributing live malware breaks GitHub policy and is unsafe |
| Defang every IOC you write down: `tools/defang.py` | Stops accidental clicks and auto-linking |

macOS XProtect may quarantine or delete some exported files. That's expected; record the hash first.

## Folder layout on your Mac

```
~/pcap-work/              <- NOT in git, NOT synced
├── 01-malware-c2/        downloaded zip, extracted pcap, exported objects
├── 02-phishing-download/
└── ...
~/Projects/network-traffic-analysis/   <- this repo (write-ups only)
```
