## 1. Initial Droplet Setup

Every second a fresh server is on the internet without hardening it is accumulating automated scan traffic. Bots scan the entire IPv4 space in under an hour. Your droplet will receive SSH brute force attempts within minutes of provisioning. We harden before doing anything else.

### First login — as root

```shell
# Update everything before touching anything else
apt update && apt upgrade -y && apt autoremove -y
apt install -y curl wget git \
  nftables cryptsetup fail2ban aide \
  wireguard wireguard-tools net-tools dnsutils \
  unattended-upgrades apt-listchanges \
  apparmor apparmor-utils apparmor-profiles sqlite3
```

### Enable automatic security updates

```shell
dpkg-reconfigure --priority=low unattended-upgrades
```

### How to check things

```shell
# What is installed
dpkg -l | grep <package>
# Confirm unattended-upgrades is configured
cat /etc/apt/apt.conf.d/50unattended-upgrades
```

### Keep it happy

```shell
# Manual dry run
unattended-upgrade --dry-run --debug
# See what would be upgraded
apt list --upgradable
```

---

