## 7. sysctl Hardening

Kernel runtime parameters default to compatibility, not security. We tune network stack behavior, memory protections, and process isolation.

### Apply hardened settings

```shell
cat > /etc/sysctl.d/99-harden.conf << 'EOF'
## Network
# Docker bridge networking requires forwarding — lockdown via nftables forward chain
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 0

# Ignore ICMP redirects — used to manipulate routing tables
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Ignore source-routed packets
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0

# SYN cookies — defense against SYN flood
net.ipv4.tcp_syncookies = 1

# Ignore broadcast pings — Smurf DDoS amplification
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Ignore bogus ICMP error responses & log impossible source addresses
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# Reverse path filtering — drop packets that couldn't arrive on this interface
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# TCP timestamps can leak uptime
net.ipv4.tcp_timestamps = 0

## Memory and Process
# Restrict ptrace — 2 = only root can attach to processes
kernel.yama.ptrace_scope = 2

# Hide kernel symbol addresses from non-root
kernel.kptr_restrict = 2

# Restrict dmesg to root
kernel.dmesg_restrict = 1

# Disable magic SysRq — can force crash or reboot
kernel.sysrq = 0

# Protect hardlinks and symlinks in shared directories
fs.protected_hardlinks = 1
fs.protected_symlinks = 1

# Disable core dumps for SUID binaries
fs.suid_dumpable = 0

# Disable unprivileged user namespace creation — not needed with rootful Docker
kernel.unprivileged_userns_clone = 0
vm.unprivileged_userfaultfd = 0

## Performance
# Reduce swap — sensitive data stays in encrypted RAM
vm.swappiness = 10
EOF

sysctl -p /etc/sysctl.d/99-harden.conf
```

### How to check things

```shell
sysctl net.ipv4.ip_forward
sysctl net.ipv4.conf.all.log_martians
sysctl kernel.unprivileged_userns_clone
```

---

