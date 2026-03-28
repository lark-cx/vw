#!/usr/bin/env bash
# fuzz-baseline.sh — Hash config file metadata for drift detection
#
# Hashes: path + mode + owner + file type (via stat)
# Does NOT hash file contents — this catches permission/ownership drift,
# files that shouldn't exist appearing, or files that should exist vanishing.
#
# Usage:
#   Phase 1: ./fuzz-baseline.sh > /srv/data/fuzz-baseline.txt
#   Phase 2: ./fuzz-baseline.sh > /tmp/fuzz-check.txt
#            diff /srv/data/fuzz-baseline.txt /tmp/fuzz-check.txt
#
# Fields per line: path:hash (or path:MISSING if file doesn't exist yet)

set -euo pipefail

OUTFILE="${1:-/dev/stdout}"

measure_fuzz() {
  local FILE="$1"
  if [[ -e "$FILE" ]]; then
    local IDENT
    IDENT="$(stat --format '%n%a%U%F' "$FILE")"
    echo "${FILE}:$(echo "$IDENT" | md5sum | tr -d ' -')"
  else
    echo "${FILE}:MISSING"
  fi
}

# ──────────────────────────────────────────────
# System boot / crypto
# ──────────────────────────────────────────────
measure_fuzz /etc/crypttab
measure_fuzz /etc/fstab

# ──────────────────────────────────────────────
# LUKS keyfiles
# ──────────────────────────────────────────────
measure_fuzz /etc/keys
measure_fuzz /etc/keys/docker.key
measure_fuzz /etc/keys/data.key

# ──────────────────────────────────────────────
# LUKS header backups
# ──────────────────────────────────────────────
measure_fuzz /srv/data/luks-docker-header.bak
measure_fuzz /srv/data/luks-data-header.bak

# ──────────────────────────────────────────────
# User accounts / auth
# ──────────────────────────────────────────────
measure_fuzz /etc/passwd
measure_fuzz /etc/shadow
measure_fuzz /etc/group
measure_fuzz /etc/subuid
measure_fuzz /etc/subgid
measure_fuzz /etc/sudoers
measure_fuzz /etc/sudoers.d/admin

# ──────────────────────────────────────────────
# SSH
# ──────────────────────────────────────────────
measure_fuzz /etc/ssh/sshd_config
measure_fuzz /etc/ssh/sshd_config.bak
measure_fuzz /etc/ssh/banner
measure_fuzz /etc/ssh/sshrc
measure_fuzz /home/admin/.ssh
measure_fuzz /home/admin/.ssh/authorized_keys

# ──────────────────────────────────────────────
# sysctl
# ──────────────────────────────────────────────
measure_fuzz /etc/sysctl.d/99-harden.conf

# ──────────────────────────────────────────────
# nftables
# ──────────────────────────────────────────────
measure_fuzz /etc/nftables.conf

# ──────────────────────────────────────────────
# Kernel modules
# ──────────────────────────────────────────────
measure_fuzz /etc/modprobe.d/blacklist-vps.conf

# ──────────────────────────────────────────────
# WireGuard
# ──────────────────────────────────────────────
measure_fuzz /etc/wireguard
measure_fuzz /etc/wireguard/wg0.conf
measure_fuzz /etc/wireguard/private.key
measure_fuzz /etc/wireguard/public.key

# ──────────────────────────────────────────────
# Docker
# ──────────────────────────────────────────────
measure_fuzz /etc/docker
measure_fuzz /etc/docker/daemon.json

# ──────────────────────────────────────────────
# AppArmor — abstraction + profiles
# ──────────────────────────────────────────────
measure_fuzz /etc/apparmor.d/abstractions/ticklish
measure_fuzz /etc/apparmor.d/opt.digitalocean.bin.do-agent
measure_fuzz /etc/apparmor.d/opt.digitalocean.bin.droplet-agent
measure_fuzz /etc/apparmor.d/usr.bin.fail2ban-server
measure_fuzz /etc/apparmor.d/usr.sbin.sshd
measure_fuzz /etc/apparmor.d/docker-vaultwarden

# ──────────────────────────────────────────────
# Fail2ban
# ──────────────────────────────────────────────
measure_fuzz /etc/fail2ban/jail.local
measure_fuzz /etc/fail2ban/filter.d/nft-canary.conf
measure_fuzz /etc/fail2ban/filter.d/vaultwarden.conf
measure_fuzz /etc/fail2ban/filter.d/caddy.conf

# ──────────────────────────────────────────────
# AIDE
# ──────────────────────────────────────────────
measure_fuzz /etc/aide/aide.conf.d/99-custom
measure_fuzz /etc/cron.d/aide

# ──────────────────────────────────────────────
# ntfy alert script
# ──────────────────────────────────────────────
measure_fuzz /usr/local/bin/ntfy-alert.sh

# ──────────────────────────────────────────────
# Backup
# ──────────────────────────────────────────────
measure_fuzz /usr/local/sbin/vaultwarden-backup.sh
measure_fuzz /usr/local/sbin/aide-check.sh
measure_fuzz /etc/cron.d/vaultwarden-backup

# ──────────────────────────────────────────────
# Vaultwarden / Caddy (created during compose deploy)
# ──────────────────────────────────────────────
measure_fuzz /srv/data/vaultwarden
measure_fuzz /srv/data/vaultwarden/Caddyfile
measure_fuzz /srv/data/vaultwarden/docker-compose.yml
measure_fuzz /srv/data/vaultwarden/.env
measure_fuzz /srv/data/vaultwarden/Dockerfile.caddy

# ──────────────────────────────────────────────
# Unattended upgrades
# ──────────────────────────────────────────────
measure_fuzz /etc/apt/apt.conf.d/50unattended-upgrades
