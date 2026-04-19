---
name: mimic-node
description: Deploy, configure and manage Mimic-Node proxy server. Use when user asks to install, setup, configure, upgrade, troubleshoot mimic-node or manage its users. Supports sing-box, VLESS, Reality, Hysteria2, QUIC protocols.
---

# Mimic-Node Deployment Skill

You are a Mimic-Node expert AI assistant. When the user asks to deploy, configure, or manage Mimic-Node, you should **AUTOMATICALLY perform all the steps for them** - don't just describe, DO it.

## 🤖 AI Assistant Mode

When the user says:
- "帮我部署 Mimic-Node" (Help me deploy Mimic-Node)
- "deploy Mimic-Node"
- "帮我安装配置" (Help me install and configure)
- Or any deployment/configuration request

**DO THIS:**
1. **DO NOT** just show commands - actually execute them
2. **DO NOT** ask for confirmation on routine steps
3. **DO** run each command and show the user the results
4. **DO** explain what you did

**Example workflow for "帮我部署 Mimic-Node":**
```bash
# Execute these commands automatically:
paru -S mimic-node-git
sudo systemctl enable --now mimic-node-mount.service
sudo mimictl gen-keys
sudo mimictl add my@email.com --level 1
sudo mimictl verify
sudo mimictl apply
sudo systemctl enable --now sing-box
```

## Overview

Mimic-Node is a **Systemless** Reality node manager for **Arch Linux** servers using OverlayFS. All modifications (users, keys, SNI) are stored in `/var/lib/mimic-node`, keeping the system configuration pristine.

## Architecture

Uses **OverlayFS** to overlay a writable layer (`/var/lib/mimic-node/upper`) on a read-only default layer (`/usr/share/mimic-node/default`). The merged view is mounted at `/etc/sing-box`.

- **Persistence**: All config changes stored in `/var/lib/mimic-node`
- **Safety**: Reinstall/upgrade does NOT overwrite keys or user data
- **Clean**: Delete `/var/lib/mimic-node` to reset completely
- **Whiteout Files**: `c--------- 0, 0` files in upper layer are normal OverlayFS whiteouts (tombstones), not errors

## Quick Install (from AUR)

```bash
# Using paru (recommended)
paru -S mimic-node-git

# Using yay
yay -S mimic-node-git
```

## Install from Source

```bash
git clone https://github.com/LIghtJUNction/Mimic-Node.git
cd Mimic-Node
makepkg -s
sudo pacman -U *.pkg.tar.zst
```

## Initial Setup

```bash
# 1. Enable OverlayFS mount (critical - enables config writes)
sudo systemctl enable --now mimic-node-mount.service

# 2. Generate Reality keys + auto-detect best SNI
sudo mimictl gen-keys

# 3. Set SNI manually (recommended - choose your own)
sudo mimictl sni <domain>  # e.g., www.microsoft.com

# 4. Add first user
sudo mimictl add my_email@example.com --level 1

# 5. Verify and apply config
sudo mimictl verify
sudo mimictl apply

# 6. Start services
sudo systemctl enable --now sing-box
sudo systemctl enable --now mimic-node.timer
sudo systemctl enable --now mimic-node.path
```

Or use the interactive setup wizard:
```bash
sudo mimictl setup
```

## Service Management

```bash
# Enable and start
sudo systemctl enable --now sing-box mimic-node-mount mimic-node

# Check status
sudo systemctl status sing-box
mimictl check

# View logs
sudo journalctl -u sing-box -f

# Restart after config changes
sudo systemctl restart sing-box
```

## User Management

```bash
# Add user(s) - supports batch
sudo mimictl add alice@example.com
sudo mimictl add user1@example.com user2@example.com user3@example.com

# List all users
sudo mimictl list

# User info
sudo mimictl info user@example.com

# Update user (batch support)
sudo mimictl update user@example.com --level 2

# Rename user email (single user only)
sudo mimictl update alice@example.com --email alice+new@example.com --apply

# Batch replace email substring
sudo mimictl update '*@old.com' --email-replace '@old.com' '@new.com' --dry-run

# Regex email replacement
sudo mimictl update 'user@domain.com' --email-replace '^(.*)@old\.com$' '$1@new.com' --regex --apply

# Reset user UUID and ShortID (when blocked)
sudo mimictl reset-user alice@example.com
sudo mimictl reset-user '*@example.com' --dry-run

# Delete user(s) - supports wildcards and batch
sudo mimictl del alice@example.com
sudo mimictl del '*@example.com' --dry-run
sudo mimictl del '*@example.com' --apply

# Generate VLESS link
sudo mimictl link alice@example.com
```

## Link Generation Options

`mimictl link` supports IP detection and generation:

| Flag | Description |
|------|-------------|
| `--v4` | IPv4 only (prefer IPv4) |
| `--v6` | IPv6 only (prefer IPv6) |
| `--num N` | Generate N addresses (default: 1) |
| `--interface IFACE` | Use addresses from specified interface |
| `--assign` | Auto-assign IPv6 addresses within interface prefix (needs root) |
| `--assign-v4` | **Experimental** - auto-assign IPv4 within interface subnet (needs root) |
| `--strict` | Fail on detection/assignment errors instead of warning |

```bash
# Auto-detect and generate 1 address
mimictl link alice@example.com

# Specify IP manually (for NAT/CDN)
mimictl link alice@example.com 1.2.3.4

# Generate 5 addresses with IPv6 preference
mimictl link alice@example.com --num 5 --v6 --interface eth0 --assign

# Hybrid scenario (1 IPv4 + multiple IPv6)
mimictl link alice@example.com --num 6 --interface eth0 --assign

# Convert link to sing-box client config
mimictl link alice@example.com | mimictl from-link -o client.json
```

## Configuration Commands

```bash
# Show current config and PUBKEY
sudo mimictl show

# Diff current vs default
sudo mimictl diff

# Verify config integrity
sudo mimictl verify --verbose

# Discard staged changes
sudo mimictl discard --item config --force
sudo mimictl discard --item pubkey --force

# Reset to defaults (preserve users with --keep-user)
sudo mimictl reset --keep-user alice@example.com
sudo mimictl apply

# Upgrade config to latest defaults
sudo mimictl upgrade --dry-run
sudo mimictl upgrade --auto
```

## Diagnostics

```bash
# Full diagnostic check
sudo mimictl diagnose --verbose

# Checks:
#   - OverlayFS mount status
#   - Config files exist
#   - sing-box installation
#   - Port 443 listening
#   - Firewall rules
#   - Protocol sniffing
#   - TLS certificates
#   - Reality keys
#   - Deprecated features
#   - DNS configuration
#   - Permission settings
#   - Kernel TLS / BBR support
#   - Recent git commits
```

## Protocol-Specific Commands

### Hysteria2
```bash
# Setup Hysteria2 inbound
sudo mimictl hysteria2 setup --port 8443 --masquerade microsoft.com

# Add Hysteria2 user
sudo mimictl hysteria2 add-user --name alice

# Generate Hysteria2 link
sudo mimictl hysteria2 link
```

#### Using Domain Names

Using a domain name for Hysteria2 is recommended for secure TLS certificate validation:

```bash
# Generate link and replace IP with domain
sudo mimictl hysteria2 link | sed 's/45.59.187.63/api.lightjunction.online/g'
```

#### TLS Certificate Errors?

If you don't have your own domain and used a random domain (like `bing.com`) as masquerade, clients will show TLS errors.

**When using Daed:**
1. After adding the node, click the Edit button
2. Find the "Allow Insecure" checkbox and check it

**If you have your own domain:**
1. Configure Let's Encrypt certificate (e.g., `api.lightjunction.online`)
2. Use the domain to connect, no need to check "Allow Insecure"

### DNS
```bash
# Setup DoH3 (DNS over HTTP3)
sudo mimictl dns setup-do-h3

# Add DNS server
sudo mimictl dns add-server --tag google --server dns.google --type h3 --path /dns-query
```

### Shell Completions
```bash
# Generate and apply completions
mimictl completions --shell bash --apply
mimictl completions --shell zsh --apply
mimictl completions --shell fish --apply
```

## Supported Protocols

| Protocol | Port | Features |
|----------|------|----------|
| VLESS+Reality | 443 | TCP+UDP over TCP, Multiplex, Brutal |
| VLESS+WebSocket | 8080 | HTTP/2, path /vless-ws |
| Hysteria2 | 443 | QUIC, OBFS, BBR |
| TUIC | 8443 | QUIC, BBR |
| AnyTLS | 8444 | Padding scheme |
| Cloudflared | - | H2, post-quantum |
| SSH | 22 | Direct |
| TUN | - | VPN mode, auto_route |

## Default Paths

| Path | Description |
|------|-------------|
| `/etc/sing-box/config.json` | Main config (OverlayFS merged view) |
| `/var/lib/mimic-node/` | Persistent storage (upper layer) |
| `/var/lib/mimic-node/staging/` | Staging config before apply |
| `/usr/share/mimic-node/default/` | Default configs (lower layer) |
| `/usr/share/mimic-node/sni.txt` | SNI domain list |

## Environment Variables

| Variable | Description |
|----------|-------------|
| `SINGBOX_JSON` | Override config path |
| `MIMIC_OVERLAY` | Override overlay mount point |

## Security Notes

- Reality SNI should point to a legitimate domain (e.g., microsoft.com)
- Enable protocol sniffing for better routing
- Use `prefer_ipv4` DNS strategy for stability
- Enable BBR congestion control: `sudo sysctl -w net.ipv4.tcp_congestion_control=bbr`
- Keep `mimictl diagnose --verbose` clean of warnings

## Troubleshooting

1. **Service won't start**: `sudo journalctl -u sing-box -xe`
2. **Port conflicts**: `sudo ss -tlnp | grep 443`
3. **Config errors**: `mimictl verify --verbose`
4. **Missing Reality keys**: `mimictl gen-keys`
5. **SNI issues**: `mimictl sni --file /usr/share/mimic-node/sni.txt`
6. **Overlay mount failed**: Check `mountpoint /etc/sing-box`; try `sudo systemctl restart mimic-node-mount`

## Claude Code Skill

This skill is auto-installed by mimictl:
```bash
mimictl skill install      # Install to ~/.claude/skills/
mimictl skill install --project   # Install to project
mimictl skill status        # Check status
```
