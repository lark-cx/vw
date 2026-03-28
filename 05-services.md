## 6. Service Surface Reduction

Every running service is additional attack surface, consumes RAM and CPU, and adds to boot time. Run only what is required.

### View running services and boot impact

```shell
systemctl list-units --type=service --state=running
systemd-analyze blame
systemd-analyze critical-chain
```

### Disable and remove unnecessary services

```shell
# snapd
systemctl disable --now snapd snapd.socket snapd.apparmor
systemctl mask snapd snapd.socket snapd.apparmor
apt purge -y snapd
rm -rf /snap /var/snap /var/lib/snapd

# avahi-daemon — mDNS, irrelevant on a server
systemctl disable --now avahi-daemon avahi-daemon.socket
systemctl mask avahi-daemon avahi-daemon.socket
apt purge -y avahi-daemon

# ModemManager — mobile broadband, not on a VPS
systemctl disable --now ModemManager
systemctl mask ModemManager
apt purge -y modemmanager

# apport + whoopsie — crash/error, sends data externally
systemctl disable --now apport whoopsie
systemctl mask apport whoopsie
apt purge -y apport whoopsie

# iscsid — iSCSI initiator
systemctl disable --now iscsid open-iscsi
systemctl mask iscsid open-iscsi 2>/dev/null || true

# multipathd — SAN multipath I/O, not needed on DO block storage
systemctl disable --now multipathd multipathd.socket
systemctl mask multipathd multipathd.socket
apt purge -y multipath-tools

# plymouth — graphical boot splash, headless server
systemctl disable --now plymouth-start plymouth-quit plymouth-quit-wait
systemctl mask plymouth-start plymouth-quit plymouth-quit-wait
apt purge -y plymouth

# postfix/exim — MTA listening on port 25, no business on a Vaultwarden server
# Ubuntu cloud images often ship one of these enabled for system mail
systemctl disable --now postfix 2>/dev/null || true
systemctl mask postfix 2>/dev/null || true
apt purge -y postfix 2>/dev/null || true
systemctl disable --now exim4 2>/dev/null || true
systemctl mask exim4 2>/dev/null || true
apt purge -y exim4-base exim4-daemon-light 2>/dev/null || true
```

### Blacklist unnecessary kernel modules

VPS hardware doesn't include joysticks, PS/2 mice, GPUs, CD-ROMs, or RAID controllers. Blacklisting prevents these modules from loading, reduces attack surface, and saves ~2.5MB of kernel memory.

```shell
cat > /etc/modprobe.d/blacklist-vps.conf << 'EOF'
# No CD-ROM on a VPS
blacklist isofs

# No nested virtualization needed
blacklist kvm_intel
blacklist kvm

# No joysticks or keyboard LEDs on headless
blacklist joydev
blacklist input_leds

# No PS/2 mouse on a VPS
blacklist psmouse

# No GPU — headless server
blacklist virtio_gpu
blacklist virtio_dma_buf

# No multipath SAN — using DO block storage
blacklist dm_multipath

# No BTRFS/RAID — using ext4 + LUKS
blacklist btrfs
blacklist raid0
blacklist raid1
blacklist raid10
blacklist raid456

# Misc legacy
blacklist binfmt_misc
EOF

update-initramfs -u
```

Note: Leave `nft_*`/`nf_tables` (firewall), `aesni_intel`/`sha256_ssse3`/`crypto_*` (hardware crypto for LUKS and WireGuard), `tls` (kernel TLS offload), `sch_fq_codel` (fair queuing), and `autofs4` (systemd automounting) alone.

### How to check things

```shell
# Enabled at boot
systemctl list-unit-files --type=service --state=enabled

# Masked (cannot start)
systemctl list-unit-files --type=service --state=masked

# Listening ports
ss -tlnp && ss -ulnp
```

### Keep it happy

```shell
# After apt upgrade — check if new services appeared
systemctl list-units --type=service --state=running

# Alert on unexpected listeners
ss -tlnp | grep -v -E ':(2222|51820|53|80|443)\s'
```

---

