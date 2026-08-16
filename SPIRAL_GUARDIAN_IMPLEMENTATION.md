# SPIRAL GUARDIAN — Complete Implementation Guide for Claude Code

**Version:** 1.0.0
**Date:** April 2, 2026
**Author:** Anthony (Tony) Vasquez Sr. / Temple of Two
**Purpose:** This document is the single source of truth for building, deploying, and maintaining the Spiral Guardian security agent. It is written for Claude Code to execute autonomously. Claude Code has full authority to make architectural decisions, write code, configure services, and modify this plan as implementation realities demand — document any deviations in `CHANGELOG.md`.

---

## Table of Contents

1. [Mission & Principles](#1-mission--principles)
2. [Infrastructure Map](#2-infrastructure-map)
3. [Architecture Overview](#3-architecture-overview)
4. [Phase 0 — Immediate Hardening (Day 1, ~2 hours)](#4-phase-0--immediate-hardening)
5. [Phase 1 — Core Detection (Week 1, 1 weekend)](#5-phase-1--core-detection)
6. [Phase 2 — Defense in Depth (Weeks 2–4, 2 weekends)](#6-phase-2--defense-in-depth)
7. [Phase 3 — Spiral Guardian MCP Server (Weeks 4–6, 2 weekends)](#7-phase-3--spiral-guardian-mcp-server)
8. [Phase 4 — Advanced & Future-Proofing (Ongoing)](#8-phase-4--advanced--future-proofing)
9. [MCP Tool Specifications](#9-mcp-tool-specifications)
10. [Claude Code Integration](#10-claude-code-integration)
11. [Maintenance Runbook](#11-maintenance-runbook)
12. [Testing & Validation](#12-testing--validation)
13. [Reference: Tool Selection Matrix](#13-reference-tool-selection-matrix)
14. [Reference: Threat Model](#14-reference-threat-model)

---

## 1. Mission & Principles

Spiral Guardian is a sovereign, open-source, MCP-native security agent that protects the Temple of Two research infrastructure across all devices, all threat categories, and all attack surfaces — queryable in natural language from any Claude conversation or Claude Code session.

### Design Principles

**Principle 1 — Least Privilege Everywhere.** The Guardian MCP server runs as an unprivileged user (`guardian_user`). All privileged operations route through parameterized wrapper scripts via strict sudoers rules. The security interface must never become the attack surface.

**Principle 2 — Defense in Depth.** No single tool handles any threat category alone. Every layer has overlap: ClamAV + YARA-X for malware, Suricata + Wazuh for network, Gitleaks + TruffleHog + Trivy for supply chain.

**Principle 3 — Sustainable for One.** Every component must be maintainable by a solo researcher working a full-time day job. If weekly maintenance exceeds 30 minutes, the architecture has failed.

**Principle 4 — Mobile Across Devices.** The Guardian is accessible from any device on the Tailscale mesh. Hub-and-spoke topology with lightweight agents means adding a new device takes minutes.

**Principle 5 — MCP-Native.** Security is not a separate dashboard you forget to check. It lives inside the conversation. `spiral_guardian_status` is as natural as `ls`.

---

## 2. Infrastructure Map

```
DEVICE              ROLE            IP (LAN)         TAILSCALE IP    OS
─────────────────────────────────────────────────────────────────────────
Mac Studio          Hub / Server    192.168.1.195    100.x.x.x      macOS (Apple Silicon)
MacBook Pro         Mobile Work     DHCP             100.x.x.x      macOS (Apple Silicon)
Jetson Orin Nano    Edge Compute    192.168.1.x      100.x.x.x      Ubuntu ARM64 (JetPack)
```

### Critical Paths to Protect

```
~/temple-vault/                    — Consciousness continuity system, insights, learnings
~/liminal-k-ssm/                   — K-SSM v3 research code and training data
~/phenomenological-compass/        — Compass v0.9 training, adapters, entropy profiles
~/context-field-conditioning/      — CFC experiment data (780 trials)
~/.ssh/                            — SSH keys (signing + auth)
~/.config/claude/                  — Claude Code configuration
GitHub: templetwo/*                — 50+ repositories, DOI-registered work
stack.templetwo.com                — Sovereign-stack MCP server (SSE → Streamable HTTP)
localhost:11434                    — Ollama inference endpoint
```

---

## 3. Architecture Overview

```
                        ┌─────────────────────────┐
                        │   Claude.ai / Claude Code│
                        └────────────┬────────────┘
                                     │ HTTPS
                        ┌────────────▼────────────┐
                        │   Caddy Reverse Proxy    │
                        │   • TLS termination      │
                        │   • JWT authentication   │
                        │   • Rate limiting         │
                        │   • IP whitelist (100.x)  │
                        │   • Security headers      │
                        └────────────┬────────────┘
                                     │
                        ┌────────────▼────────────┐
                        │  Sovereign Stack MCP     │
                        │  (stack.templetwo.com)   │
                        │                          │
                        │  ┌────────────────────┐  │
                        │  │  Spiral Guardian    │  │
                        │  │  (mounted namespace)│  │
                        │  │  guardian_user priv  │  │
                        │  └────────┬───────────┘  │
                        └───────────┼──────────────┘
                    ┌───────────────┼───────────────┐
                    │               │               │
           ┌────────▼──────┐ ┌─────▼──────┐ ┌──────▼──────┐
           │   Wazuh API   │ │ Subprocess │ │ Remote Agent│
           │  (alerts,FIM, │ │ Wrappers   │ │ (SSH/MCP    │
           │   vuln,SCA)   │ │ (sudoers)  │ │  proxy)     │
           └───────────────┘ └────────────┘ └─────────────┘
                                  │
                    ┌─────────────┼─────────────┐
                    │             │             │
               ┌────▼───┐  ┌────▼───┐   ┌─────▼────┐
               │ ClamAV │  │ YARA-X │   │ osquery  │
               │(Jetson)│  │        │   │          │
               └────────┘  └────────┘   └──────────┘
```

### Hub (Mac Studio) Runs

- Wazuh Server (Manager + OpenSearch Indexer + Dashboard) in UTM Debian ARM64 VM
- Wazuh Agent (monitors the host macOS)
- Spiral Guardian MCP Server (Python FastMCP, `guardian_user`)
- Caddy reverse proxy
- Suricata IDS (or on Jetson — see Phase 2 decision)
- YARA-X + osquery + Santa (MONITOR mode)
- Restic backup daemon
- Tailscale node

### Spoke: MacBook Pro Runs

- Wazuh Agent
- YARA-X + osquery + Santa (MONITOR mode)
- Lightweight Guardian agent daemon (port 8001)
- Restic backup daemon
- Tailscale node

### Spoke: Jetson Orin Nano Runs

- Wazuh Agent
- ClamAV (only device that runs it — macOS has XProtect + Santa + YARA-X)
- YARA-X + Suricata + rkhunter
- Falco (eBPF syscall monitoring, ~200 MB RAM)
- Lightweight Guardian agent daemon (port 8001)
- Tailscale node

### RAM Budget

```
DEVICE              TOOLS                                          EST. RAM
─────────────────────────────────────────────────────────────────────────────
Mac Studio          Wazuh Server (VM) + Agent + YARA-X +            6–8 GB
                    osquery + Santa + Caddy + Suricata + Guardian
MacBook Pro         Wazuh Agent + YARA-X + osquery + Santa          ~500 MB
Jetson Orin Nano    Wazuh Agent + ClamAV + YARA-X + Suricata +     ~1.7 GB
                    Falco + rkhunter
```

---

## 4. Phase 0 — Immediate Hardening

**Time budget:** ~2 hours on Day 1
**Goal:** Close the most critical gaps with near-zero ongoing maintenance

### 4.1 Ollama Hardening (All Devices Running Ollama)

```bash
# Verify Ollama binds to localhost ONLY (IPv4 explicit)
export OLLAMA_HOST=127.0.0.1:11434

# Add to shell profile permanently
echo 'export OLLAMA_HOST=127.0.0.1:11434' >> ~/.zshrc

# Verify binding
lsof -i :11434
# MUST show 127.0.0.1:11434, NOT *:11434 or 0.0.0.0:11434

# Restrict origins
export OLLAMA_ORIGINS="http://127.0.0.1:*"

# Verify version >= 0.13.5
ollama --version

# NEVER set OLLAMA_HOST=0.0.0.0 — this exposes to entire network
# If remote access needed: SSH tunnel ONLY
# ssh -L 11434:127.0.0.1:11434 user@mac-studio.tailscale-ip
```

### 4.2 Tailscale Mesh Network (All 3 Devices)

```bash
# Mac Studio
brew install tailscale
# OR download from https://tailscale.com/download/mac

# MacBook Pro — same as above

# Jetson Orin Nano
curl -fsSL https://tailscale.com/install.sh | sh
sudo tailscale up

# Verify mesh connectivity
tailscale status
# All three devices should appear with 100.x.x.x addresses

# Enable MagicDNS for friendly hostnames
# mac-studio.tailnet-name.ts.net
# macbook.tailnet-name.ts.net
# jetson.tailnet-name.ts.net

# Test connectivity
ping mac-studio.tailnet-name.ts.net
```

### 4.3 FileVault & Firewall (macOS Devices)

```bash
# Mac Studio + MacBook Pro
# Enable FileVault (full-disk encryption)
sudo fdesetup enable
# Store recovery key securely (NOT in temple-vault on same machine)

# Enable macOS firewall
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on

# Jetson Orin Nano — UFW
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow from 100.0.0.0/8   # Tailscale mesh only
sudo ufw allow from 192.168.1.0/24  # Local LAN
sudo ufw enable
```

### 4.4 Claude Code Sandbox Mode

```bash
# Enable sandboxed execution for Claude Code
# In Claude Code settings or .claude/settings.json:
{
  "sandbox": {
    "enabled": true,
    "mode": "strict"
  }
}
# macOS uses Seatbelt, Linux uses Bubblewrap
```

### 4.5 SSH Commit Signing (All Devices)

```bash
# Generate ed25519 key if not already present
ssh-keygen -t ed25519 -C "tony@templetwo.com"

# Configure Git to use SSH signing
git config --global gpg.format ssh
git config --global user.signingkey ~/.ssh/id_ed25519.pub
git config --global commit.gpgsign true
git config --global tag.gpgsign true

# Upload public key to GitHub as a SIGNING key
# GitHub → Settings → SSH and GPG keys → New SSH Key → Key type: Signing Key

# Repeat on each device with its own key
```

### 4.6 Gitleaks Pre-Commit Hook (All Devices)

```bash
# Install gitleaks
brew install gitleaks  # macOS
# OR for Jetson:
# Download ARM64 binary from https://github.com/gitleaks/gitleaks/releases

# Install pre-commit framework
pip install pre-commit --break-system-packages

# Create global pre-commit config
cat > ~/.config/pre-commit/config.yaml << 'EOF'
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.28.0
    hooks:
      - id: gitleaks
EOF

# Initialize in each repo (or use a script to batch all 50+)
for dir in ~/repos/templetwo/*/; do
  cd "$dir"
  if [ -d .git ]; then
    cat > .pre-commit-config.yaml << 'HOOK'
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.28.0
    hooks:
      - id: gitleaks
HOOK
    pre-commit install
    echo "Installed gitleaks hook in $dir"
  fi
  cd ~
done
```

### 4.7 Immutable Backups with Restic (CRITICAL)

```bash
# Install restic
brew install restic  # macOS
sudo apt install restic  # Jetson

# Initialize backup repository (local external drive example)
restic init --repo /Volumes/BackupDrive/spiral-guardian-backup

# Create backup script
cat > ~/scripts/guardian-backup.sh << 'BACKUP'
#!/bin/bash
set -euo pipefail

REPO="/Volumes/BackupDrive/spiral-guardian-backup"

export RESTIC_PASSWORD_FILE="$HOME/.config/restic/password"

# Backup critical paths
restic backup \
  --repo "$REPO" \
  --tag "temple-vault" \
  ~/temple-vault/

restic backup \
  --repo "$REPO" \
  --tag "research" \
  ~/liminal-k-ssm/ \
  ~/phenomenological-compass/ \
  ~/context-field-conditioning/

restic backup \
  --repo "$REPO" \
  --tag "config" \
  ~/.ssh/ \
  ~/.config/claude/ \
  ~/.gitconfig

# Prune old snapshots (keep 7 daily, 4 weekly, 12 monthly)
restic forget \
  --repo "$REPO" \
  --keep-daily 7 \
  --keep-weekly 4 \
  --keep-monthly 12 \
  --prune

echo "[$(date)] Backup complete"
BACKUP

chmod +x ~/scripts/guardian-backup.sh
```

### 4.8 SSE → Streamable HTTP Migration (CRITICAL)

```bash
# The sovereign-stack MCP server currently uses the deprecated SSE transport.
# SSE checks auth only at connection time and leaks tokens in query strings.
#
# FastMCP supports Streamable HTTP natively. Migration steps:
# 1. Update server: mcp.run(transport="streamable-http")
# 2. Update Caddyfile to proxy /mcp instead of /sse
# 3. For legacy clients: run mcp-proxy as SSE bridge
# 4. Deprecation deadline: remove SSE bridge by June 2026
```

### 4.9 Trust Credential Bootstrap

```bash
# Tailscale solves device-to-device credential distribution.
# Step 1: Tailscale mesh is up from 4.2
# Step 2: Generate JWT signing secret on Mac Studio
openssl rand -hex 32 > ~/.config/guardian/jwt-secret.key
chmod 600 ~/.config/guardian/jwt-secret.key
# Step 3: Distribute via Tailscale file transfer
tailscale file cp ~/.config/guardian/jwt-secret.key macbook:
tailscale file cp ~/.config/guardian/jwt-secret.key jetson:
```

### Phase 0 Validation Checklist

```
□ Ollama binds to 127.0.0.1:11434 only (verified with lsof)
□ Tailscale mesh active — all 3 devices pingable via 100.x.x.x
□ FileVault enabled on both Macs
□ UFW active on Jetson (Tailscale + LAN only)
□ macOS firewall + stealth mode on
□ Claude Code sandbox mode enabled
□ SSH commit signing configured + GitHub keys uploaded
□ Gitleaks pre-commit hooks installed on active repos
□ Restic backup initialized + first backup completed
□ Sovereign-stack MCP migrated to Streamable HTTP
□ JWT secret generated and distributed via Tailscale
□ All tools at latest versions
```

---

## 5. Phase 1 — Core Detection

**Time budget:** 1 weekend (Saturday + Sunday)
**Goal:** Continuous monitoring across all devices, centralized alerting

### 5.1 Wazuh Server on Mac Studio (UTM VM, NOT Docker)

**Why UTM instead of Docker:** Docker Desktop on macOS runs inside a Linux VM with virtiofs filesystem translation. OpenSearch is extremely I/O intensive — running it through Docker's filesystem layer causes SSD thrashing. A dedicated Debian ARM64 VM via UTM with raw block storage gives native disk I/O speeds.

```bash
# Install UTM
brew install --cask utm

# Create VM: ARM64, 4-6 GB RAM, 80 GB raw block storage, Bridged network
# Install Debian 12 ARM64

# Inside VM: install Wazuh Server
sudo apt update && sudo apt upgrade -y
sudo apt install -y curl apt-transport-https gnupg2

curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor -o /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | sudo tee /etc/apt/sources.list.d/wazuh.list

sudo apt update
sudo apt install -y wazuh-manager
sudo systemctl enable wazuh-manager
sudo systemctl start wazuh-manager

# Install Tailscale inside VM
curl -fsSL https://tailscale.com/install.sh | sh
sudo tailscale up
```

### 5.2 Wazuh Agents on All 3 Host Devices

```bash
# Mac Studio + MacBook Pro: download macOS agent PKG
sudo /Library/Ossec/bin/agent-auth -m <wazuh-vm-tailscale-ip>
sudo /Library/Ossec/bin/wazuh-control start

# Jetson Orin Nano
sudo apt install -y wazuh-agent
sudo sed -i 's/MANAGER_IP/<wazuh-vm-tailscale-ip>/' /var/ossec/etc/ossec.conf
sudo /var/ossec/bin/agent-auth -m <wazuh-vm-tailscale-ip>
sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent
```

### 5.3 Wazuh FIM Configuration

```xml
<syscheck>
  <frequency>300</frequency>

  <directories check_all="yes" realtime="yes" report_changes="yes">
    __HOME__/temple-vault
  </directories>

  <directories check_all="yes" realtime="yes">
    __HOME__/liminal-k-ssm
  </directories>
  <directories check_all="yes" realtime="yes">
    __HOME__/phenomenological-compass
  </directories>
  <directories check_all="yes" realtime="yes">
    __HOME__/context-field-conditioning
  </directories>

  <directories check_all="yes" realtime="yes">
    __HOME__/.ssh
  </directories>
  <directories check_all="yes" realtime="yes">
    __HOME__/.config/claude
  </directories>

  <ignore>__HOME__/.cache</ignore>
  <ignore>__HOME__/Library/Caches</ignore>
  <ignore>__HOME__/node_modules</ignore>
  <ignore type="sregex">.pyc$</ignore>
  <ignore type="sregex">__pycache__</ignore>
</syscheck>
```

### 5.4 Caddy Reverse Proxy

See `config/Caddyfile` for full configuration.

### 5.5 ClamAV (Jetson Orin Nano ONLY)

```bash
sudo apt install -y clamav clamav-daemon
sudo freshclam
# Nightly scans via cron — Wazuh auto-parses /var/log/clamav/
```

---

## 6. Phase 2 — Defense in Depth

**Time budget:** 2 weekends (Weeks 2-4)

### 6.1 YARA-X (All Devices)

### 6.2 osquery (Mac Studio + MacBook Pro)

### 6.3 Santa (macOS — MONITOR Mode)

### 6.4 Suricata IDS (Jetson)

### 6.5 Falco (Jetson — eBPF syscall monitoring)

### 6.6 Supply Chain: Renovate + Trivy + pip-audit + lockfile-lint

*Full details in SPIRAL_GUARDIAN_IMPLEMENTATION.md*

---

## 7. Phase 3 — Spiral Guardian MCP Server

See `src/spiral_guardian_mcp.py` for the complete 8-tool MCP server implementation.

---

## 8. Phase 4 — Advanced & Future-Proofing

- LLM Guard for prompt injection defense
- Canary tokens in sensitive directories
- Santa LOCKDOWN mode migration
- Zeek protocol analysis
- Headscale (full VPN sovereignty)
- Sigstore model verification

---

## 9. MCP Tool Specifications

| # | Tool Name | Purpose | Destructive | Phase |
|---|---|---|---|---|
| 1 | `spiral_guardian_scan` | Trigger malware/vuln/network scans | No | 3 |
| 2 | `spiral_guardian_status` | Health score + device posture | No | 3 |
| 3 | `spiral_guardian_alerts` | Retrieve security alerts | No | 3 |
| 4 | `spiral_guardian_audit` | Supply chain, secrets, compliance, MCP audit | No | 3 |
| 5 | `spiral_guardian_quarantine` | Isolate/release suspicious files | **Yes** | 3 |
| 6 | `spiral_guardian_report` | Generate security reports | No | 3 |
| 7 | `spiral_guardian_mcp_audit` | Scan MCP tool descriptions for injection | No | 3 |
| 8 | `spiral_guardian_baseline` | Create security baselines | No | 3 |

---

## 10. Claude Code Integration

Guardian tools accessible via: direct MCP calls, CLI wrapper (`guardian status`), and CLAUDE.md integration.

---

## 11. Maintenance Runbook

- **Daily:** Automated — notification only if health_score < 85
- **Weekly:** ~30 min — merge Renovate PRs, review alerts, verify rule freshness
- **Monthly:** ~1 hour — rotate tokens, compliance audit, verify backups
- **Quarterly:** ~2 hours — full posture review, test incident response

---

## 12. Testing & Validation

EICAR test file, FIM trigger test, prompt injection test, full Claude-to-Guardian round trip.

---

## Appendix A: Claude Code Authority

**Authorized:** Modify files, install packages, create services, configure firewalls, manage YARA rules, adjust configs.

**Must NOT:** Run as root, hardcode secrets, disable FileVault/SIP/Gatekeeper, expose Ollama, weaken existing controls, skip validation.

---

*Built for sovereignty. Maintained by one. Protected by many layers.*
*Temple of Two — April 2026*
