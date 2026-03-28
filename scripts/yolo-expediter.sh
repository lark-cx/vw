#!/usr/bin/env bash
# yolo-it-phase1.sh — Initial hardening: packages, swap, LUKS, users, services, kernel, AppArmor
#
# Run as root on a fresh Ubuntu 24.04 droplet with three DO volumes attached:
#   vaultwarden-docker  → /var/lib/docker   (LUKS)
#   vaultwarden-data    → /srv/data         (LUKS)
#   vaultwarden-log     → /var/log          (unencrypted, preserves existing logs)
#
# Prerequisites:
#   - Droplet provisioned via deploy-vaultwarden.sh (or manually with 3 volumes)
#   - Volumes attached but NOT formatted (we LUKS them here)
#   - Running as root over SSH
#
# This script sends ntfy notifications as it progresses so you can watch
# from your phone if the SSH session drops.

set -euo pipefail

# ──────────────────────────────────────────────
# ntfy — progress notifications
# ──────────────────────────────────────────────
ntfy() {
  local TOKEN="tk_pqejf1uimjs3leny3hf5zguzg22co"
  curl -sf \
    -H "Authorization: Bearer $TOKEN" \
    -H "Title: ${1:-Alert}" \
    -H "Tags: white_check_mark" \
    -d "${2:-no message}" \
    https://ntfy.lrk.cx/server_alerts_31fb4 \
    > /dev/null 2>&1 || true
}

# ──────────────────────────────────────────────
# Volume device paths — stable across reboots
# DO volumes appear as /dev/disk/by-id/scsi-0DO_Volume_<name>
# These names match what deploy-vaultwarden.sh creates.
# After first login, verify with: ls -l /dev/disk/by-id/scsi-0DO_*
# ──────────────────────────────────────────────
VOL_DOCKER="/dev/disk/by-id/scsi-0DO_Volume_vaultwarden-docker"
VOL_DATA="/dev/disk/by-id/scsi-0DO_Volume_vaultwarden-data"
VOL_LOG="/dev/disk/by-id/scsi-0DO_Volume_vaultwarden-log"

# Sanity check — bail if volumes aren't attached
for vol in "$VOL_DOCKER" "$VOL_DATA" "$VOL_LOG"; do
  if [[ ! -e "$vol" ]]; then
    echo "ERROR: Volume not found: $vol"
    echo "Run: ls -l /dev/disk/by-id/scsi-0DO_* to see what's attached"
    exit 1
  fi
done
ntfy "deploy" "Volume paths verified — all three attached"

# ══════════════════════════════════════════════
# 1. PACKAGES
# ══════════════════════════════════════════════
apt update && ntfy "apt" "apt update complete"
apt upgrade -y && ntfy "apt" "apt upgrade complete"
apt autoremove -y

apt install -y curl wget git \
  nftables cryptsetup fail2ban \
  aide aide-common \
  wireguard wireguard-tools net-tools dnsutils \
  unattended-upgrades apt-listchanges \
  apparmor apparmor-utils apparmor-profiles \
  sqlite3 && ntfy "apt" "package install complete"

dpkg-reconfigure --priority=low unattended-upgrades && ntfy "apt" "unattended-upgrades configured"

# ══════════════════════════════════════════════
# 2. ENCRYPTED SWAP
# Must come before LUKS — Argon2 KDF needs more memory than a 1GB droplet has.
# With swap available, cryptsetup can hit its full memory target.
# Ephemeral random key — each boot renders previous swap unrecoverable.
# ══════════════════════════════════════════════
fallocate -l 2G /swapfile
chmod 600 /swapfile

cat >> /etc/crypttab << 'EOF'
cryptswap  /swapfile  /dev/urandom  swap,cipher=aes-xts-plain64,size=256,offset=8
EOF

cat >> /etc/fstab << 'EOF'
/dev/mapper/cryptswap  none  swap  sw  0 0
EOF

cryptdisks_start cryptswap
swapon /dev/mapper/cryptswap
ntfy "swap" "encrypted swap enabled (2G)"

# ══════════════════════════════════════════════
# 3. ENCRYPTED STORAGE + MOUNT HARDENING
# ══════════════════════════════════════════════

# --- Keyfiles ---
mkdir -p /etc/keys && chmod 700 /etc/keys
dd if=/dev/urandom of=/etc/keys/docker.key bs=512 count=1 2>/dev/null
dd if=/dev/urandom of=/etc/keys/data.key   bs=512 count=1 2>/dev/null
chmod 400 /etc/keys/*.key
ntfy "luks" "keyfiles created"

# --- LUKS format + open ---
# --pbkdf-memory 512000: keeps Argon2 comfortable on 1GB + 2G swap
cryptsetup luksFormat "$VOL_DOCKER" --type luks2 --batch-mode \
  --key-file /etc/keys/docker.key \
  --pbkdf argon2id --pbkdf-memory 512000
cryptsetup open "$VOL_DOCKER" docker-data --key-file /etc/keys/docker.key

cryptsetup luksFormat "$VOL_DATA" --type luks2 --batch-mode \
  --key-file /etc/keys/data.key \
  --pbkdf argon2id --pbkdf-memory 512000
cryptsetup open "$VOL_DATA" app-data --key-file /etc/keys/data.key

ntfy "luks" "LUKS volumes formatted and opened"

# --- Filesystems ---
mkfs.ext4 -q /dev/mapper/docker-data
mkfs.ext4 -q /dev/mapper/app-data

mkdir -p /var/lib/docker /srv/data

mount /dev/mapper/docker-data /var/lib/docker
mount /dev/mapper/app-data    /srv/data

# Log volume — preserve existing /var/log contents!
# Format the volume, copy current logs onto it, then mount in place.
mkfs.ext4 -q "$VOL_LOG"
mkdir -p /mnt/newlog
mount "$VOL_LOG" /mnt/newlog
cp -a /var/log/* /mnt/newlog/
umount /mnt/newlog
rmdir /mnt/newlog
mount "$VOL_LOG" /var/log

ntfy "luks" "filesystems created and mounted (logs preserved)"

# --- crypttab — auto-unlock at boot ---
cat >> /etc/crypttab << EOF
docker-data  ${VOL_DOCKER}  /etc/keys/docker.key  luks,discard
app-data     ${VOL_DATA}    /etc/keys/data.key    luks,discard
EOF

# --- fstab — hardened mount options ---
cat >> /etc/fstab << EOF
/dev/mapper/docker-data  /var/lib/docker  ext4  defaults,nosuid,nodev              0 2
/dev/mapper/app-data     /srv/data        ext4  defaults,nosuid,noexec,nodev        0 2
${VOL_LOG}               /var/log         ext4  defaults,nosuid,noexec,nodev        0 2
EOF

# --- Harden standard mounts ---
echo "tmpfs  /tmp  tmpfs  defaults,nosuid,noexec,nodev,size=512m  0 0" >> /etc/fstab
echo "proc  /proc  proc  defaults,hidepid=2  0 0" >> /etc/fstab

# Apply fstab changes — systemd caches mount units, must reload
systemctl daemon-reload
mount -o remount /tmp 2>/dev/null || true
mount -o remount /proc 2>/dev/null || true

ntfy "luks" "crypttab + fstab + mount hardening complete"

# --- LUKS header backups ---
cryptsetup luksHeaderBackup "$VOL_DOCKER" --header-backup-file /srv/data/luks-docker-header.bak
cryptsetup luksHeaderBackup "$VOL_DATA"   --header-backup-file /srv/data/luks-data-header.bak
ntfy "luks" "LUKS header backups saved to /srv/data"

# ══════════════════════════════════════════════
# 4. USER ACCOUNTS
# Docker daemon.json is written later in Section 10 when Docker is installed.
# We create the remap user + subuid/subgid ranges here so they're ready.
# ══════════════════════════════════════════════

# Admin user — password set via hash (change this or use passwd after)
useradd --create-home --shell /bin/bash --groups sudo \
  --password '$6$f.jJK.6WxZfuDIbw$1wMXJqMU56Ot8wr1J7Rhq1NtSaVoBhZanHKoqOlXHMwu/zUIK8XLw6a0Emlj.WG22C8z9GRqAxCHFRxOpW2bW.' \
  admin

# Copy root's authorized_keys so the deploy key works for admin too
mkdir -p /home/admin/.ssh
cp /root/.ssh/authorized_keys /home/admin/.ssh/
chmod 700 /home/admin/.ssh
chmod 600 /home/admin/.ssh/authorized_keys
chown -R admin:admin /home/admin/.ssh

# Sudoers — password required, no NOPASSWD
echo "admin ALL=(ALL:ALL) ALL" > /etc/sudoers.d/admin
chmod 440 /etc/sudoers.d/admin

ntfy "users" "admin user created with sudo"

# Docker namespace remap user — no login, just owns subordinate UID/GID range
useradd -r -s /usr/sbin/nologin dockremap
echo "dockremap:100000:65536" >> /etc/subuid
echo "dockremap:100000:65536" >> /etc/subgid

ntfy "users" "dockremap user + subuid/subgid configured"

# ══════════════════════════════════════════════
# 6. SERVICE SURFACE REDUCTION
# ══════════════════════════════════════════════

# snapd
systemctl disable --now snapd snapd.socket snapd.apparmor 2>/dev/null || true
systemctl mask snapd snapd.socket snapd.apparmor 2>/dev/null || true
apt purge -y snapd 2>/dev/null || true
rm -rf /snap /var/snap /var/lib/snapd

# avahi-daemon — mDNS, irrelevant on a server
systemctl disable --now avahi-daemon avahi-daemon.socket 2>/dev/null || true
systemctl mask avahi-daemon avahi-daemon.socket 2>/dev/null || true
apt purge -y avahi-daemon 2>/dev/null || true

# ModemManager — mobile broadband, not on a VPS
systemctl disable --now ModemManager 2>/dev/null || true
systemctl mask ModemManager 2>/dev/null || true
apt purge -y modemmanager 2>/dev/null || true

# apport + whoopsie — crash/error reporting, phones home
systemctl disable --now apport whoopsie 2>/dev/null || true
systemctl mask apport whoopsie 2>/dev/null || true
apt purge -y apport whoopsie 2>/dev/null || true

# iscsid — iSCSI initiator, not needed on DO
systemctl disable --now iscsid open-iscsi 2>/dev/null || true
systemctl mask iscsid open-iscsi 2>/dev/null || true

# multipathd — SAN multipath, not needed on DO block storage
systemctl disable --now multipathd multipathd.socket 2>/dev/null || true
systemctl mask multipathd multipathd.socket 2>/dev/null || true
apt purge -y multipath-tools 2>/dev/null || true

# plymouth — graphical boot splash, headless server
systemctl disable --now plymouth-start plymouth-quit plymouth-quit-wait 2>/dev/null || true
systemctl mask plymouth-start plymouth-quit plymouth-quit-wait 2>/dev/null || true
apt purge -y plymouth 2>/dev/null || true

# postfix/exim — MTA listening on port 25, no business on a Vaultwarden server
systemctl disable --now postfix 2>/dev/null || true
systemctl mask postfix 2>/dev/null || true
apt purge -y postfix 2>/dev/null || true
systemctl disable --now exim4 2>/dev/null || true
systemctl mask exim4 2>/dev/null || true
apt purge -y exim4-base exim4-daemon-light 2>/dev/null || true

ntfy "hardening" "unnecessary services disabled and purged"

# ══════════════════════════════════════════════
# KERNEL MODULE BLACKLIST
# ══════════════════════════════════════════════

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

update-initramfs -u && ntfy "hardening" "kernel module blacklist applied"

# ══════════════════════════════════════════════
# 7. SYSCTL HARDENING
# ══════════════════════════════════════════════

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

sysctl -p /etc/sysctl.d/99-harden.conf && ntfy "hardening" "sysctl hardening applied"

# ══════════════════════════════════════════════
# APPARMOR — ticklish abstraction + service profiles
# All profiles start in complain mode. Run in complain for a few days,
# check journalctl | grep apparmor.*DENIED, then aa-enforce when clean.
# ══════════════════════════════════════════════

# --- Shared abstraction: deny sensitive paths, shells, escalation tools ---
cat > /etc/apparmor.d/abstractions/ticklish << 'TICKLISH'
# vim:syntax=apparmor
# ------------------------------------------------------------------
# Explicit deny statements on particularly ticklish areas
# ------------------------------------------------------------------

# Secrets, privileged users, authN keys
audit deny /etc/keys/*.key r,
audit deny /etc/wireguard/*.key r,
audit deny /etc/shadow r,
audit deny /etc/sudoers r,
audit deny /etc/sudoers.d/** r,
audit deny /root/.ssh/** rw,
audit deny @{HOME}/.ssh/** rw,

# Shells
audit deny /usr/bin/bash x,
audit deny /bin/bash x,
audit deny /usr/bin/sh x,
audit deny /bin/sh x,
audit deny /usr/bin/dash x,
audit deny /bin/dash x,

# Privilege escalation
audit deny /usr/bin/sudo x,
audit deny /bin/sudo x,
audit deny /usr/bin/su x,
audit deny /bin/su x,
audit deny /usr/sbin/chroot x,
audit deny /sbin/chroot x,

# Raw networking
audit deny network raw,
audit deny network packet,
TICKLISH

ntfy "apparmor" "ticklish abstraction installed"

# --- DigitalOcean do-agent ---
cat > /etc/apparmor.d/opt.digitalocean.bin.do-agent << 'DOAGENT'
# Cleaned: globbed sysfs/udev paths
abi <abi/3.0>,

include <tunables/global>

/opt/digitalocean/bin/do-agent flags=(complain) {
  include <abstractions/base>
  include <abstractions/ticklish>

  network inet stream,
  network netlink raw,

  /opt/digitalocean/bin/do-agent mr,

  # /proc — metrics collection
  /proc/ r,
  /proc/*/mounts r,
  /proc/*/net/netstat r,
  /proc/*/net/snmp r,
  /proc/*/net/snmp6 r,
  /proc/*/net/softnet_stat r,
  /proc/*/net/udp r,
  /proc/*/net/udp6 r,
  /proc/*/stat r,
  /proc/diskstats r,
  /proc/loadavg r,
  /proc/pressure/cpu r,
  /proc/pressure/io r,
  /proc/pressure/memory r,
  /proc/schedstat r,

  # udev — block device metadata
  /run/udev/data/b* r,

  # sysfs — network interfaces (globbed, survives interface changes)
  /sys/class/net/ r,
  /sys/class/power_supply/ r,
  /sys/class/powercap/ r,
  /sys/class/thermal/ r,
  /sys/class/watchdog/ r,
  /sys/devices/pci0000:00/*/virtio*/net/eth*/** r,
  /sys/devices/virtual/net/lo/** r,

  # sysfs — CPU topology
  /sys/devices/system/cpu/** r,

  # sysfs — DMI / hardware identity
  /sys/devices/virtual/dmi/id/ r,
  /sys/devices/virtual/dmi/id/** r,

  # sysfs — thermal
  /sys/devices/virtual/thermal/** r,
}
DOAGENT

# --- DigitalOcean droplet-agent ---
cat > /etc/apparmor.d/opt.digitalocean.bin.droplet-agent << 'DROPLETAGENT'
# Cleaned: denied net_raw + sys_admin, deduped binary path
abi <abi/3.0>,

include <tunables/global>

/opt/digitalocean/bin/droplet-agent flags=(complain) {
  include <abstractions/base>
  include <abstractions/ticklish>

  # Deny capabilities a monitoring agent shouldn't need.
  # If these break, DO backup/recovery/console features may require them —
  # re-evaluate per feature rather than granting blanket sys_admin.
  deny capability net_raw,
  deny capability sys_admin,

  network inet stream,
  deny network inet raw,

  /opt/digitalocean/bin/droplet-agent mrix,
  owner /etc/passwd r,
  owner /etc/ssh/sshd_config r,
  owner /proc/*/cgroup r,
  owner /proc/*/mountinfo r,
  owner /sys/kernel/mm/transparent_hugepage/hpage_pmd_size r,
}
DROPLETAGENT

# --- fail2ban ---
cat > /etc/apparmor.d/usr.bin.fail2ban-server << 'FAIL2BAN'
# Cleaned: globbed journal paths, added nft exec, wildcard filter.d
abi <abi/3.0>,

include <tunables/global>

/usr/bin/fail2ban-server flags=(complain) {
  include <abstractions/base>
  include <abstractions/python>
  include <abstractions/ticklish>

  network inet dgram,
  network netlink raw,

  /run/systemd/resolve/stub-resolv.conf r,
  /usr/bin/fail2ban-server r,
  /usr/bin/python3.12 ix,

  # nft — fail2ban execs this to manage bans. Without it, bans silently fail.
  /usr/sbin/nft ix,

  # Config — wildcard so custom filters (nft-canary, vaultwarden) work
  owner /etc/fail2ban/action.d/*.conf r,
  owner /etc/fail2ban/fail2ban.conf r,
  owner /etc/fail2ban/fail2ban.d/ r,
  owner /etc/fail2ban/filter.d/*.conf r,
  owner /etc/fail2ban/jail.conf r,
  owner /etc/fail2ban/jail.local r,
  owner /etc/fail2ban/jail.d/ r,
  owner /etc/fail2ban/jail.d/*.conf r,
  owner /etc/fail2ban/paths-common.conf r,
  owner /etc/fail2ban/paths-debian.conf r,

  # Name resolution
  owner /etc/gai.conf r,
  owner /etc/host.conf r,
  owner /etc/hosts r,
  owner /etc/nsswitch.conf r,
  owner /etc/passwd r,

  # Runtime
  owner /run/fail2ban/fail2ban.pid w,
  owner /run/fail2ban/fail2ban.sock rw,

  # Database
  owner /var/lib/fail2ban/fail2ban.sqlite3 rwk,

  # Logs — globbed journal paths survive machine-id changes
  owner /var/log/fail2ban.log w,
  owner /var/log/journal/ r,
  owner /var/log/journal/*/ r,
  owner /var/log/journal/*/*.journal r,
  owner /run/log/journal/ r,
  owner /run/log/journal/*/ r,
  owner /run/log/journal/*/*.journal r,

  # Vaultwarden + Caddy logs for their jails
  /srv/data/vaultwarden/vw-data/vaultwarden.log r,
  /var/log/caddy/access.log r,

  # Kernel log for nft-canary jail
  /var/log/kern.log r,
}
FAIL2BAN

# --- sshd (upstream Ubuntu profile, minor cleanup) ---
cat > /etc/apparmor.d/usr.sbin.sshd << 'SSHD'
# Upstream Ubuntu sshd profile with minor cleanup.
# Lines marked REVIEW are overly broad — tighten before enforcing.
abi <abi/3.0>,

include <tunables/global>

# vim:syntax=apparmor

/usr/sbin/sshd flags=(complain) {
  include <abstractions/authentication>
  include <abstractions/base>
  include <abstractions/consoles>
  include <abstractions/hosts_access>
  include <abstractions/libpam-systemd>
  include <abstractions/nameservice>
  include <abstractions/wutmp>
  include if exists <local/usr.sbin.sshd>

  # NOTE: ticklish abstraction intentionally NOT included here.
  # sshd legitimately needs to exec shells and read auth files.

  deny capability net_admin,

  capability audit_control,
  capability audit_write,
  capability chown,
  capability dac_override,
  capability dac_read_search,
  capability fowner,
  capability kill,
  capability net_bind_service,
  capability setgid,
  capability setuid,
  capability sys_chroot,
  capability sys_ptrace,
  capability sys_resource,
  capability sys_tty_config,

  dbus send bus=system path=/org/freedesktop/login1 interface=org.freedesktop.login1.Manager member=CreateSessionWithPIDFD peer=(label=unconfined),

  ptrace (read trace) peer=unconfined,

  unix (bind) type=stream addr="@*/bus/sshd/system",

  # REVIEW: these two lines grant read to the entire filesystem.
  # Safe in complain mode. Before enforcing, replace with explicit paths.
  # / r,
  # /** r,

  /dev/ptmx rw,
  /dev/pts/[0-9]* rw,
  /dev/urandom r,
  /etc/default/locale r,
  /etc/environment r,
  /etc/legal r,
  /etc/modules.conf r,
  /etc/motd r,
  /etc/security/** r,
  /etc/ssh/** r,
  /etc/ssl/openssl.cnf r,
  /tmp/krb5cc* wk,
  /tmp/ssh-[a-zA-Z0-9]*/ w,
  /tmp/ssh-[a-zA-Z0-9]*/agent.[0-9]* wl,
  /usr/bin/passwd Cx -> passwd,
  /usr/lib/openssh/sftp-server PUx,
  /usr/sbin/sshd mrix,
  /usr/share/ssh/blacklist.* r,
  /var/log/btmp rw,

  # Login shells — sshd needs to exec the user's shell
  /{usr/,}bin/ash rUx,
  /{usr/,}bin/bash rUx,
  /{usr/,}bin/bash2 rUx,
  /{usr/,}bin/bsh rUx,
  /{usr/,}bin/csh rUx,
  /{usr/,}bin/dash rUx,
  /{usr/,}bin/false rUx,
  /{usr/,}bin/ksh rUx,
  /{usr/,}bin/sh rUx,
  /{usr/,}bin/tcsh rUx,
  /{usr/,}bin/zsh rUx,
  /{usr/,}bin/zsh4 rUx,
  /{usr/,}bin/zsh5 rUx,
  /{usr/,}sbin/nologin rUx,

  @{HOME}/.ssh/authorized_keys{,2} r,
  @{PROC}/1/environ r,
  @{PROC}/@{pids}/fd/ r,
  @{PROC}/@{pid}/task/@{pid}/attr/exec w,
  @{PROC}/cmdline r,
  @{run}/motd.d/ r,
  @{run}/motd.d/* r,
  @{run}/motd{,.dynamic}{,.new} rw,
  @{run}/systemd/notify w,
  @{sys}/fs/cgroup/*/user/*/[0-9]*/ rw,
  @{sys}/fs/cgroup/systemd/user.slice/user-[0-9]*.slice/session-c[0-9]*.scope/ rw,

  # REVIEW: owner /** rwl grants read/write/link to everything owned by sshd's UID.
  # Tighten before enforcing.
  owner /** rwl,

  owner @{HOME}/.cache/ w,
  owner @{HOME}/.cache/motd.legal-displayed w,
  owner @{PROC}/@{pid}/limits r,
  owner @{PROC}/@{pid}/loginuid rw,
  owner @{PROC}/@{pid}/mounts r,
  owner @{PROC}/@{pid}/oom_adj rw,
  owner @{PROC}/@{pid}/oom_score_adj rw,
  owner @{PROC}/@{pid}/uid_map r,
  owner @{run}/sshd{,.init}.pid wl,

  profile passwd flags=(complain) {
    include <abstractions/authentication>
    include <abstractions/base>
    include <abstractions/nameservice>

    capability audit_write,
    capability chown,
    capability fsetid,
    capability ipc_lock,
    capability setgid,
    capability setuid,

    /dev/pts/[0-9]* rw,
    /usr/bin/gnome-keyring-daemon ix,
    /usr/bin/passwd r,
    @{run}/utmp rwk,
    owner /etc/.pwd.lock rwk,
    owner /etc/nshadow rw,
    owner /etc/shadow rw,
    owner @{HOME}/.cache/keyring-*/ rw,
    owner @{HOME}/.cache/keyring-*/control rw,
    owner @{PROC}/@{pid}/loginuid r,
    owner @{PROC}/@{pid}/status r,
  }
}
SSHD

# Load all profiles
apparmor_parser -r /etc/apparmor.d/opt.digitalocean.bin.do-agent
apparmor_parser -r /etc/apparmor.d/opt.digitalocean.bin.droplet-agent
apparmor_parser -r /etc/apparmor.d/usr.bin.fail2ban-server
apparmor_parser -r /etc/apparmor.d/usr.sbin.sshd

ntfy "apparmor" "all profiles loaded in complain mode"

# ══════════════════════════════════════════════
# DONE — summary
# ══════════════════════════════════════════════

ntfy "deploy" "Phase 1 complete. Ready for SSH hardening + nftables + WireGuard."

cat << 'SUMMARY'

╔══════════════════════════════════════════════════════╗
║  Phase 1 Complete                                    ║
╠══════════════════════════════════════════════════════╣
║  ✓ Packages installed + unattended-upgrades          ║
║  ✓ Encrypted swap (2G) enabled                       ║
║  ✓ LUKS volumes formatted, mounted, fstab written    ║
║  ✓ /var/log preserved on separate volume             ║
║  ✓ Admin user created, SSH key copied                ║
║  ✓ Docker remap user + subuid/subgid configured      ║
║  ✓ Unnecessary services purged                       ║
║  ✓ Kernel modules blacklisted                        ║
║  ✓ sysctl hardened                                   ║
║  ✓ AppArmor profiles loaded (complain mode):         ║
║      ticklish abstraction                            ║
║      do-agent, droplet-agent, fail2ban, sshd         ║
║                                                      ║
║  Next steps (manual — don't script these):           ║
║    1. Add LUKS recovery passphrases:                 ║
║       cryptsetup luksAddKey $VOL_DOCKER \            ║
║         --key-file /etc/keys/docker.key \            ║
║         --pbkdf argon2id --pbkdf-memory 512000       ║
║       cryptsetup luksAddKey $VOL_DATA \              ║
║         --key-file /etc/keys/data.key \              ║
║         --pbkdf argon2id --pbkdf-memory 512000       ║
║    2. Test SSH as admin before locking out root       ║
║    3. Configure SSH hardening (Section 5)            ║
║    4. Deploy nftables ruleset (Section 8)            ║
║    5. Configure WireGuard (Section 9)                ║
║    6. Then lock SSH to WireGuard interface            ║
║                                                      ║
║  Verify:                                             ║
║    findmnt /var/lib/docker                           ║
║    findmnt /srv/data                                 ║
║    findmnt /var/log                                  ║
║    ls /var/log/syslog  (should still exist!)         ║
║    aa-status                                         ║
║    lsblk -f                                          ║
╚══════════════════════════════════════════════════════╝
SUMMARY
