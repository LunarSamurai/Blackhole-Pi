# 🛡️ Pi Ad Blocker

A lightweight, Go-based DNS sinkhole ad blocker for Raspberry Pi. Like Pi-hole, but a single Go binary.

## Features

- **DNS-level ad blocking** — blocks ads, trackers, and malware across your entire network
- **Multiple blocklist sources** — Steven Black's hosts, AdGuard, Firebog, and more (~200k+ domains)
- **Web dashboard** — real-time stats at `http://<pi-ip>:8080`
- **Automatic updates** — refreshes blocklists every 24 hours
- **Whitelist support** — easily allow specific domains
- **Subdomain matching** — blocking `ads.example.com` also blocks `sub.ads.example.com`
- **Lightweight** — single binary, ~10MB RAM usage
- **JSON API** — `GET /api/stats` for integration with other tools

## Quick Install

```bash
# Clone/copy files to your Pi, then:
cd pi-adblock
sudo bash install.sh
```

The installer will:
1. Install Go if needed (detects ARM architecture automatically)
2. Build the binary
3. Disable systemd-resolved (if active)
4. Install and start a systemd service
5. Print your Pi's IP for router configuration

## Router Setup

**Option A — Network-wide blocking (recommended):**
1. Log into your router admin panel (usually `192.168.1.1`)
2. Find DNS settings (under DHCP, LAN, or Network settings)
3. Set **Primary DNS** to your Pi's IP address
4. Set **Secondary DNS** to `1.1.1.1` (fallback if Pi goes down)
5. Save and reboot router

**Option B — Per-device:**
Set the DNS server on individual devices to your Pi's IP address.

## Configuration

Edit the config in `main.go` and rebuild, or modify these files:

| File | Purpose |
|------|---------|
| `/etc/pi-adblock/whitelist.txt` | Domains to allow (one per line) |
| `/var/log/pi-adblock.log` | Application logs |

### Adding/Removing Blocklists

Edit the `BlocklistURLs` slice in `main.go`. Supports:
- **Hosts format:** `0.0.0.0 domain.com` or `127.0.0.1 domain.com`
- **Adblock format:** `||domain.com^`
- **Plain domain lists:** `domain.com`

## Commands

```bash
sudo systemctl status pi-adblock     # Check if running
sudo systemctl restart pi-adblock    # Restart (reloads blocklists)
sudo systemctl stop pi-adblock       # Stop
sudo journalctl -u pi-adblock -f     # Live logs

# Edit whitelist (restart after changes)
sudo nano /etc/pi-adblock/whitelist.txt
sudo systemctl restart pi-adblock
```

## Building Manually

```bash
# On the Pi
go mod tidy
go build -o pi-adblock .
sudo ./pi-adblock

# Cross-compile from another machine
GOOS=linux GOARCH=arm64 go build -o pi-adblock .  # Pi 4/5 (64-bit)
GOOS=linux GOARCH=arm GOARM=7 go build -o pi-adblock .  # Pi 3 (32-bit)
```

## Architecture

```
Internet ← Upstream DNS (Cloudflare/Quad9/Google)
               ↑
          Pi Ad Blocker (port 53)
          ├── Blocked? → Return 0.0.0.0
          └── Allowed? → Forward to upstream
               ↑
          Your Router (DHCP hands out Pi's IP as DNS)
               ↑
          All devices on your network
```

## Upstream DNS Servers

By default, allowed queries are forwarded to (in order):
1. Cloudflare (`1.1.1.1`, `1.0.0.1`) — fast, privacy-focused
2. Quad9 (`9.9.9.9`) — malware blocking
3. Google (`8.8.8.8`) — reliable fallback