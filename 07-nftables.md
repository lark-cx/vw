## 8. nftables Firewall

We define an explicit allowlist across three tables, each at a different point in the packet processing pipeline:

```
Packet arrives on eth0
      ↓
netdev ingress  (priority -500)   cheapest drop — before conntrack
      ↓   bogons, IP fragments, XMAS/NULL, bad TCP MSS
inet mangle prerouting  (-150)    conntrack-aware pre-filter
      ↓   invalid state, non-SYN new connections
inet filter input  (0)            main allowlist, default drop
      ↓
Your services
```

Bogon addresses — RFC 1918 and reserved ranges arriving on a public interface are spoofed or misconfigured. Drop them before conntrack even touches the packet.

TCP XMAS and NULL scans — malformed flag combinations used for OS fingerprinting. Legitimate traffic never sends these combinations.

Processing at earlier hook priorities saves CPU — a bogon dropped at the netdev layer never reaches the main filter chain.

### Remove ufw if installed

```shell
apt purge -y ufw
systemctl enable nftables
```

### Full hardened ruleset

```shell
cat > /etc/nftables.conf << 'EOF'
#!/usr/sbin/nft -f

flush ruleset

# Early drop — before conntrack
table netdev filter {
    chain ingress {
        type filter hook ingress device eth0 priority -500;

        # IP fragments — evasion and DDoS
        ip frag-off & 0x1fff != 0 counter drop

        # Bogon source addresses — RFC 1918 and reserved ranges
        ip saddr {
            0.0.0.0/8,
            10.0.0.0/8,
            100.64.0.0/10,
            127.0.0.0/8,
            169.254.0.0/16,
            172.16.0.0/12,
            192.0.0.0/24,
            192.0.2.0/24,
            192.168.0.0/16,
            198.18.0.0/15,
            198.51.100.0/24,
            203.0.113.0/24,
            224.0.0.0/3
        } counter drop

        # TCP XMAS scan — fin+psh+urg simultaneously, no legitimate use
        tcp flags & (fin|psh|urg) == fin|psh|urg counter drop

        # TCP NULL scan — no flags, used for OS fingerprinting
        tcp flags & (fin|syn|rst|psh|ack|urg) == 0x0 counter drop

        # Abnormally small TCP MSS — evasion technique
        tcp flags syn tcp option maxseg size 1-535 counter drop
    }
}

# Conntrack pre-filter
table inet mangle {
    chain prerouting {
        type filter hook prerouting priority -150;

        # Drop packets conntrack considers invalid
        ct state invalid counter drop

        # New TCP connections that are not SYN — spoofed or malformed
        tcp flags & (fin|syn|rst|ack) != syn ct state new counter drop
    }
}

# Main filter
table inet filter {

    # Dynamic blocklist — populated by fail2ban
    set blocklist {
        type ipv4_addr
        flags dynamic, timeout
        timeout 24h
    }

    chain input {
        type filter hook input priority 0; policy drop;

        ip saddr @blocklist drop

        ct state established,related accept
        iif lo accept

        # ICMP — rate limited
        ip protocol icmp icmp type {
            echo-request, echo-reply,
            destination-unreachable,
            time-exceeded, parameter-problem
        } limit rate 10/second accept

        # WireGuard — crypto handles authentication
        udp dport 51820 accept

        # SSH canary — port 22 is NOT running sshd — logged for fail2ban
        tcp dport 22 log prefix "nft-canary: " flags all limit rate 5/minute

        # SSH — WireGuard interface only after initial setup
        iifname "wg0" tcp dport 2222 accept

        # DNS — LAN and WireGuard peers
        iifname { "eth0", "wg0" } tcp dport 53 accept
        iifname { "eth0", "wg0" } udp dport 53 accept

        # HTTPS — WireGuard only
        iifname "wg0" tcp dport 443 accept

        # HTTP — Caddy ACME only
        tcp dport 80 accept

        limit rate 5/minute log prefix "nft-drop: " flags all
        drop
    }

    chain forward {
        type filter hook forward priority 0; policy drop;
    }

    chain output {
        type filter hook output priority 0; policy accept;
    }
}
EOF

nft -c -f /etc/nftables.conf && echo "Syntax OK" || echo "SYNTAX ERROR"
nft -f /etc/nftables.conf
systemctl enable nftables
```

### How to check things

```shell
# Full active ruleset
nft list ruleset

# Packet counters — see what is being dropped and why
nft list chain netdev filter ingress
nft list chain inet filter input

# Watch drops and canary hits in real time
journalctl -f | grep -E "nft-drop|nft-canary"

# Blocklist contents
nft list set inet filter blocklist
```

### Keep it happy

```shell
# Reload after changes
nft -c -f /etc/nftables.conf && nft -f /etc/nftables.conf

# Manual blocklist management
nft add element inet filter blocklist { 1.2.3.4 }
nft delete element inet filter blocklist { 1.2.3.4 }
```

---

