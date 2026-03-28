## 5. SSH Hardening

Default SSH configuration has a large attack surface — many authentication methods, two address families, root login, and legacy algorithms. We reduce it to exactly what is needed. Our model:

* SSH listens only on the WireGuard interface after initial setup
* Port 2222
* Public key authentication only
* Root login disabled
* Modern algorithms only
* Short login grace time

### Configure SSH

```shell
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak

cat > /etc/ssh/sshd_config << 'EOF'
# SETUP PHASE: uncomment the next line until WireGuard is confirmed
# ListenAddress 0.0.0.0
# PRODUCTION: WireGuard only
ListenAddress 10.255.255.2
Port 2222
AddressFamily inet

PermitRootLogin no
AuthenticationMethods publickey
PubkeyAuthentication yes
PasswordAuthentication no
PermitEmptyPasswords no
ChallengeResponseAuthentication no
KbdInteractiveAuthentication no
UsePAM no
LoginGraceTime 20s
MaxAuthTries 3
MaxSessions 5
MaxStartups 3:50:10

X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no
PermitTunnel no
GatewayPorts no
PermitUserEnvironment no

KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com

LogLevel VERBOSE
SyslogFacility AUTH

ClientAliveInterval 300
ClientAliveCountMax 3

AllowUsers admin

Banner /etc/ssh/banner
EOF

cat > /etc/ssh/banner << 'EOF'
# Authorized access only. All activity is logged.         #
EOF
```

### Wire up SSH login notifications via sshrc

```shell
# sshd runs /etc/ssh/sshrc on every successful login — no PAM complexity
cat > /etc/ssh/sshrc << 'EOF'
# Notify on every successful SSH login
# SSH_CLIENT is set by sshd: "sourceIP sourcePort destPort"
/usr/local/bin/ntfy-alert.sh \
  "SSH login: ${USER}" \
  "Login by ${USER} from ${SSH_CLIENT%% *} at $(date '+%Y-%m-%d %H:%M %Z')" \
  "default"
EOF
```

### Validate and restart

```shell
sshd -t && echo "Config OK" || echo "CONFIG ERROR — DO NOT RESTART"
systemctl restart ssh
```

### How to check things

```shell
# Confirm listening address and port
ss -tlnp | grep sshd

# Active sessions
who && w

# Auth failures
journalctl -u ssh --since "1 hour ago" | grep -i "fail\|invalid"

# Active algorithms
ssh -G localhost 2>/dev/null | grep -E 'cipher|mac|kex'
```

### Keep it happy

```shell
# After WireGuard confirmed — comment out the 0.0.0.0 ListenAddress, then:
sshd -t && systemctl restart ssh
```

---

