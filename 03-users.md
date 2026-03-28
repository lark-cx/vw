## 4. User Accounts

Root should never be used for day-to-day operations. If an attacker gains code execution in a root process, they own the system immediately.

By default, root inside a container maps to root on the host, so container escapees land with full host privileges. With remapping, container root maps to an unprivileged host UID. A container escape lands as a UID that owns nothing.

```
Without remapping:                With remapping:
Container UID 0 (root)            Container UID 0 (root)
      ↓                                 ↓
Host UID 0 (root)                 Host UID 100000 (nobody)
← owns everything                 ← owns nothing
```

### Create admin user

```shell
useradd -m -s /bin/bash -G sudo admin
passwd admin   # strong password — gates all sudo access

mkdir -p /home/admin/.ssh
chmod 700 /home/admin/.ssh
cat >> /home/admin/.ssh/authorized_keys << 'EOF'
ssh-ed25519 AAAA... your-public-key-here
EOF
chmod 600 /home/admin/.ssh/authorized_keys
chown -R admin:admin /home/admin/.ssh
```

### Configure sudo — password required, no exceptions

```shell
visudo -f /etc/sudoers.d/admin
```

```
admin ALL=(ALL:ALL) ALL
# Intentionally no NOPASSWD anywhere
```

### Create the Docker namespace remap user

This user never logs in. It owns the subordinate UID/GID range that Docker uses to remap container root to an unprivileged host UID. The `daemon.json` that references it is written later when Docker is installed (Section 10).

```shell
useradd -r -s /usr/sbin/nologin dockremap
echo "dockremap:100000:65536" >> /etc/subuid
echo "dockremap:100000:65536" >> /etc/subgid
```

### How to check things

```shell
# List users with interactive shells
grep -v nologin /etc/passwd | grep -v false

# Confirm subuid/subgid allocations
cat /etc/subuid && cat /etc/subgid
```

### Keep it happy

```shell
# Audit sudo access
grep -Po '^sudo.+:\K.*$' /etc/group

# Check for empty passwords
awk -F: '($2 == "") {print $1}' /etc/shadow

# Lock a compromised account
passwd -l username
usermod -s /sbin/nologin username
```

---

