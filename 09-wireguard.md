## 9. WireGuard

Services that should not be publicly reachable are bound only to the WireGuard interface. Even if nftables rules were misconfigured, a service bound to 10.255.255.2 is unreachable from the public internet.

WireGuard only responds to peers presenting valid keypairs; port scans see a closed port.

### Generate server keys

```shell
wg genkey | tee /etc/wireguard/private.key | wg pubkey > /etc/wireguard/public.key
chmod 600 /etc/wireguard/private.key
cat /etc/wireguard/public.key
```

### Configure server

```shell
cat > /etc/wireguard/wg0.conf << 'EOF'
[Interface]
PrivateKey = PASTE_SERVER_PRIVATE_KEY_HERE
Address = 10.255.255.2/24
ListenPort = 51820

[Peer]
PublicKey = PASTE_PEER_PUBLIC_KEY_HERE
AllowedIPs = 10.255.255.1/32
PersistentKeepalive = 25
EOF

chmod 600 /etc/wireguard/wg0.conf
systemctl enable wg-quick@wg0
systemctl start wg-quick@wg0
```

### How to check things

```shell
wg show                         # handshake time, transfer bytes
ip addr show wg0
ping -c 3 10.255.255.1          # test peer connectivity

# Confirm WG before removing public SSH listener
ssh -p 2222 admin@10.255.255.2
```

### Keep it happy

```shell
# Add peer without restart
wg set wg0 peer <pubkey> allowed-ips 10.255.255.x/32 persistent-keepalive 25
wg-quick save wg0

# Revoke a peer
wg set wg0 peer <pubkey> remove
wg-quick save wg0
```

---

