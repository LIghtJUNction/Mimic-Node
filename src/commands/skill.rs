use anyhow::Result;
use colored::*;
use std::fs;
use std::path::{Path, PathBuf};

const SKILL_DOC: &str = r#"---
name: mimic-node
description: Deploy, configure and manage Mimic-Node on Arch Linux. Use for installation, VLESS Reality setup, optional Hysteria2 setup, user management and diagnostics.
---

# Mimic-Node Deployment Skill

Help the user carry out authorized Mimic-Node maintenance. Inspect the target host, installed sing-box version, service state and existing configuration before making changes. Back up persistent state before a reset or migration. Preserve existing users and keys when upgrading.

## 🤖 AI Assistant Mode

For an authorized deployment, execute the necessary commands and verify their results. Explain what changed in the user's language. Package installation and service changes must target the host the user chose. Do not regenerate an existing node's keys unless requested.

Example workflow for "帮我部署 Mimic-Node":
```bash
# On a new Arch Linux server:
paru -S mimic-node-git
sudo systemctl enable --now mimic-node-mount.service
sudo mimictl gen-keys
sudo mimictl add my@email.com --level 1
sudo mimictl check && sudo mimictl apply
sudo systemctl enable --now sing-box
```

## Overview

Mimic-Node is a **Systemless** Reality node manager for **Arch Linux** servers using OverlayFS. All modifications (users, keys, SNI) are stored in `/var/lib/mimic-node`, keeping the system configuration pristine.

## Architecture

Uses **OverlayFS** to overlay a writable layer (`/var/lib/mimic-node/upper`) on a read-only default layer (`/usr/share/mimic-node/default`). The merged view is mounted at `/etc/sing-box`.

- **Persistence**: All config changes stored in `/var/lib/mimic-node`
- **Safety**: Reinstall/upgrade does NOT overwrite keys or user data
- **Reset**: Back up persistent state, stage changes with `mimictl reset`, review them, then apply. Deleting `/var/lib/mimic-node` destroys keys, users and recovery data.
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
makepkg -si
```

## Initial Setup

```bash
# 1. Enable OverlayFS mount (critical - enables config writes)
sudo systemctl enable --now mimic-node-mount.service

# 2. Generate Reality keys for a new installation
sudo mimictl gen-keys

# 3. Set SNI manually (recommended - choose your own)
sudo mimictl sni <domain>  # e.g., www.microsoft.com

# 4. Add first user
sudo mimictl add my_email@example.com --level 1

# 5. Check with sing-box and apply config
sudo mimictl check && sudo mimictl apply

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
sudo systemctl enable --now mimic-node-mount.service
sudo systemctl enable --now sing-box.service mimic-node.timer mimic-node.path

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

# Verify VLESS Reality key and user integrity
sudo mimictl verify --verbose

# Discard staged changes
sudo mimictl discard --item config --force
sudo mimictl discard --item pubkey --force

# Reset to defaults (preserve users with --keep-user)
sudo mimictl reset --keep-user alice@example.com
sudo mimictl check && sudo mimictl apply

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
```

## Protocol-Specific Commands

### Hysteria2
```bash
# Optional: stage Hysteria2 with an existing certificate and private key
sudo mimictl hysteria2 setup --port 443 --masquerade https://microsoft.com --cert /etc/ssl/node/fullchain.pem --key /etc/ssl/node/privkey.pem --up 100 --down 200

# Add Hysteria2 user
sudo mimictl hysteria2 add-user --name alice
sudo mimictl check && sudo mimictl apply
```

Hysteria2 is not enabled by default. Supply real TLS certificate/key paths and allow the selected UDP port in the firewall. VLESS Reality uses TCP, so it can share port 443 with Hysteria2 on UDP.

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

## Default and Optional Protocols

| Protocol | Port | Features |
|----------|------|----------|
| VLESS+Reality | TCP 443 | Default inbound; generate keys and add users before use |
| Hysteria2 | UDP 443 | Optional; configure with real TLS certificates |

Other sing-box protocols require a configuration you create and validate yourself; they are not preconfigured by Mimic-Node.

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
- Validate staged changes with the installed sing-box before applying them
- Keep private keys and persistent configuration readable only by the intended service account and administrator
- Review `mimictl diagnose --verbose` warnings in the context of the selected protocols

## Troubleshooting

1. **Service won't start**: `sudo journalctl -u sing-box -xe`
2. **Port conflicts**: `sudo ss -tlnp | grep 443`
3. **Config errors**: `mimictl check`; for VLESS Reality keys and users, also run `mimictl verify --verbose`
4. **Missing Reality keys**: `mimictl gen-keys`
5. **SNI issues**: `mimictl sni --file /usr/share/mimic-node/sni.txt`
6. **Overlay mount failed**: Check `mountpoint /etc/sing-box`; try `sudo systemctl restart mimic-node-mount`

## Claude Code Skill

Install this skill explicitly with the installed mimictl (without sudo):
```bash
mimictl skill install      # Install to ~/.claude/skills/
mimictl skill install --project   # Install to project
mimictl skill status        # Check status
```
"#;

fn get_skill_dir(project: bool) -> PathBuf {
    if project {
        std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(".claude/skills/mimic-node")
    } else {
        dirs::home_dir()
            .unwrap_or_else(|| {
                PathBuf::from(&format!(
                    "/home/{}",
                    std::env::var("USER").unwrap_or_default()
                ))
            })
            .join(".claude/skills/mimic-node")
    }
}

fn is_installed(skill_dir: &Path) -> bool {
    skill_dir.exists() && skill_dir.join("SKILL.md").exists()
}

pub fn install(project: bool, force: bool) -> Result<()> {
    let skill_dir = get_skill_dir(project);

    println!();
    if project {
        println!("{}", "  Installing Mimic-Node skill to project...".cyan());
    } else {
        println!(
            "{}",
            "  Installing Mimic-Node skill to ~/.claude/skills/...".cyan()
        );
    }

    if is_installed(&skill_dir) && !force {
        println!();
        println!(
            "{} Skill already installed at {}",
            "[INFO]".cyan(),
            skill_dir.display()
        );
        println!("{} Use --force to reinstall", "[*]".yellow());
        return Ok(());
    }

    // Create directory
    fs::create_dir_all(&skill_dir)?;

    // Write skill file
    let skill_path = skill_dir.join("SKILL.md");
    fs::write(&skill_path, SKILL_DOC)?;

    println!();
    println!("{}", "  [OK] Skill installed successfully!".green());
    println!();
    println!("  Skill location: {}", skill_path.display());
    println!();
    println!("  Usage in Claude Code:");
    println!("    /mimic-node");
    println!();
    println!("  The skill provides commands for:");
    println!("    - Installing Mimic-Node (AUR, source)");
    println!("    - Initial setup and configuration");
    println!("    - User management (add, list, update, delete)");
    println!("    - Service management (systemctl)");
    println!("    - Diagnostics and troubleshooting");
    println!("    - Protocol-specific commands (Hysteria2, DNS, etc.)");
    println!();

    Ok(())
}

pub fn uninstall(project: bool) -> Result<()> {
    let skill_dir = get_skill_dir(project);

    println!();
    if project {
        println!(
            "{}",
            "  Uninstalling Mimic-Node skill from project...".cyan()
        );
    } else {
        println!(
            "{}",
            "  Uninstalling Mimic-Node skill from ~/.claude/skills/...".cyan()
        );
    }

    if !is_installed(&skill_dir) {
        println!();
        println!(
            "{} Skill not installed at {}",
            "[INFO]".yellow(),
            skill_dir.display()
        );
        return Ok(());
    }

    // Remove the skill directory
    fs::remove_dir_all(&skill_dir)?;

    println!();
    println!("{}", "  [OK] Skill uninstalled successfully!".green());
    println!();

    Ok(())
}

pub fn status() -> Result<()> {
    let global_dir = get_skill_dir(false);
    let project_dir = get_skill_dir(true);

    println!();
    println!("{}", "  Mimic-Node Skill Status".cyan().bold());
    println!();

    // Check global installation
    print!("  Global (~/.claude/skills): ");
    if is_installed(&global_dir) {
        println!("{}", "[INSTALLED]".green());
        println!("    {}", global_dir.display());
    } else {
        println!("{}", "[NOT INSTALLED]".dimmed());
    }

    // Check project installation
    print!("  Project (.claude/skills): ");
    if is_installed(&project_dir) {
        println!("{}", "[INSTALLED]".green());
        println!("    {}", project_dir.display());
    } else {
        println!("{}", "[NOT INSTALLED]".dimmed());
    }

    println!();
    println!("  To install: {}", "mimictl skill install".cyan());
    println!("  To uninstall: {}", "mimictl skill uninstall".cyan());
    println!();

    Ok(())
}
