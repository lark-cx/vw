## 16. Fail2ban + Canary Port

Fail2ban watches logs for brute force patterns and bans offending IPs at the firewall. It converts a passive log into an adaptive defense.

Port 22 canary: sshd isn't on port 22. Our real SSH is on 2222. Any TCP connection to port 22 is a scanner or attacker. Any attempt triggers an immediate 48-hour ban. The home network /16 is allowlisted across all jails. We use /16 rather than /24 to avoid broadcasting a specific home address.

### Install and configure

The canary jail needs a custom filter that matches the nftables log prefix, not the sshd filter (since sshd isn't listening on 22).

```shell
apt install -y fail2ban

# Custom filter for nftables canary log entries
cat > /etc/fail2ban/filter.d/nft-canary.conf << 'EOF'
[Definition]
failregex = nft-canary:.*SRC=<HOST>
ignoreregex =
EOF

cat > /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
# Allowlist — home /16, WireGuard subnet, loopback
# Use /16 to avoid broadcasting your exact home subnet in recordings
# Students substitute their own network prefix
ignoreip = 127.0.0.1/8 ::1 10.255.255.0/24 10.x.0.0/16

bantime   = 3600
findtime  = 600
maxretry  = 5
backend   = systemd

banaction          = nftables-multiport
banaction_allports = nftables-allports

# ntfy notification on every ban
actionban = /usr/local/bin/ntfy-alert.sh \
  "Fail2ban: <jail>" \
  "Banned <ip> after <failures> failures on <jail>" \
  "high"

# Port 22 canary — nftables log, not sshd
# maxretry=1: single attempt = immediate ban
# bantime=172800: 48 hours
[nft-canary]
enabled   = true
filter    = nft-canary
logpath   = /var/log/kern.log
maxretry  = 1
findtime  = 86400
bantime   = 172800
actionban = /usr/local/bin/ntfy-alert.sh \
  "Canary: port 22 hit" \
  "Scanner hit port 22 from <ip> — banned 48h" \
  "urgent"

# Real SSH — port 2222, WireGuard only
[sshd]
enabled   = true
port      = 2222
logpath   = %(sshd_log)s
maxretry  = 3
bantime   = 86400

# Vaultwarden
[vaultwarden]
enabled   = true
port      = 80,443
logpath   = /srv/data/vaultwarden/vw-data/vaultwarden.log
maxretry  = 5
bantime   = 3600

# Caddy / WAF
[caddy]
enabled   = true
port      = 80,443
logpath   = /var/log/caddy/access.log
maxretry  = 20
findtime  = 300
bantime   = 3600
EOF

cat > /etc/fail2ban/filter.d/vaultwarden.conf << 'EOF'
[Definition]
failregex = ^.*Username or password is incorrect\. Try again\. IP: <HOST>\..*$
            ^.*Invalid admin token\. IP: <HOST>\..*$
ignoreregex =
EOF

cat > /etc/fail2ban/filter.d/caddy.conf << 'EOF'
[Definition]
failregex = ^.*"<HOST>.*" (4\d\d) .*$
ignoreregex = ^.*"<HOST>.*" (400|404) .*$
EOF

systemctl enable fail2ban
systemctl start fail2ban
```

### Demonstrate fail2ban + canary working

```shell
# Watch fail2ban in real time
tail -f /var/log/fail2ban.log

# From another machine — trigger the canary (single connection to port 22)
# nc -zv <server-ip> 22
# Watch: instant ban appears in fail2ban log and ntfy notification fires

# Confirm ban landed in nftables
nft list set inet filter blocklist
```

### How to check things

```shell
fail2ban-client status
fail2ban-client status nft-canary
fail2ban-client status vaultwarden

# Test canary filter against kernel log
fail2ban-regex /var/log/kern.log /etc/fail2ban/filter.d/nft-canary.conf

# Test vaultwarden filter
fail2ban-regex \
  /srv/data/vaultwarden/vw-data/vaultwarden.log \
  /etc/fail2ban/filter.d/vaultwarden.conf
```

### Keep it happy

```shell
# Unban yourself if locked out
fail2ban-client set sshd unbanip <your-ip>

# Reload config
fail2ban-client reload

# Monitor
journalctl -u fail2ban -f
```

---

