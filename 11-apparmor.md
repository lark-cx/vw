## 11. AppArmor

AppArmor is Mandatory Access Control (MAC) — it defines exactly what files, network resources, and capabilities a confined process may access, enforced by the kernel regardless of what the process attempts.

Compare to normal Unix permissions (Discretionary Access Control):

* DAC: Process can access anything its UID allows. Compromised www-data can read any file www-data owns.
* MAC: Process can only access what the AppArmor profile explicitly permits, regardless of UID. Compromised Vaultwarden cannot read /etc/shadow even running as root.

### The ticklish abstraction

A shared deny-list for paths no service should touch. Include it in any profile for processes that have no business reading secrets, spawning shells, or escalating privileges.

```shell
cat > /etc/apparmor.d/abstractions/ticklish << 'EOF'
# vim:syntax=apparmor
# Explicit deny statements on particularly ticklish areas

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
EOF
```

### Host service profiles

These are deployed by the phase 1 script. All start in complain mode — run `aa-logprof` after a few days to review denials, then `aa-enforce` when clean.

**DigitalOcean agents:** `do-agent` collects metrics (CPU, disk, network) for the DO dashboard. `droplet-agent` handles console access and recovery. Both run as root and phone home — we cage them with ticklish + explicit path/network rules. The droplet-agent profile denies `sys_admin` and `net_raw` capabilities; if DO backup/recovery features break, re-evaluate per feature.

**fail2ban:** Runs as root, parses logs, execs `nft` to manage bans. Profile includes wildcard `filter.d/*.conf` so custom filters (nft-canary, vaultwarden, caddy) work without per-file entries. The `/usr/sbin/nft ix` rule is critical — without it, bans silently fail.

**sshd:** Uses the upstream Ubuntu profile with wide-open lines (`/** r`, `owner /** rwl`) commented and marked REVIEW. Ticklish is intentionally NOT included — sshd legitimately execs shells and reads auth files.

### How to generate a profile for a new service

```shell
# Start the profiler — it watches the binary
aa-genprof /path/to/binary

# In another terminal, exercise the service through normal operations
# Back in the genprof terminal, press S to scan, work through prompts:
#   - Pick numbered option (specific path) over abstractions (broad)
#   - Use * globs for /proc/<pid>/ paths — PIDs change every boot
#   - (I)nherit for self-exec, (A)llow for legitimate access, (D)eny for suspicious
# Press F to finish

# Start in complain mode
aa-complain /etc/apparmor.d/<profile>

# Review accumulated denials interactively
aa-logprof

# When clean, enforce
aa-enforce /etc/apparmor.d/<profile>
```

### Write the Vaultwarden profile

Docker containers already get the `docker-default` AppArmor profile unless you override it. For Vaultwarden, we write a tighter custom profile.

```shell
cat > /etc/apparmor.d/docker-vaultwarden << 'EOF'
#include <tunables/global>

profile docker-vaultwarden flags=(attach_disconnected,mediate_deleted) {
  #include <abstractions/base>
  #include <abstractions/nameservice>
  #include <abstractions/ssl_certs>

  network inet tcp,
  network inet udp,

  /data/** rw,
  /tmp/** rw,
  /usr/bin/vaultwarden r,
  /usr/bin/vaultwarden ix,
  /usr/lib/** rm,
  /lib/** rm,

  /proc/cpuinfo r,
  /proc/meminfo r,

  # Explicit denials
  deny /etc/shadow r,
  deny /etc/sudoers r,
  deny /root/** rw,
  deny /home/** rw,
  deny /proc/sys/kernel/** w,
  deny /proc/sysrq-trigger w,
  deny @{HOME}/.ssh/** r,
  deny /var/lib/docker/** rw,

  deny capability setuid,
  deny capability setgid,
  deny capability sys_admin,
  deny capability sys_ptrace,
  deny capability net_raw,
  deny capability net_admin,
}
EOF

apparmor_parser -r /etc/apparmor.d/docker-vaultwarden
```

Important: The profile name (`docker-vaultwarden`) must match the `apparmor=` value in docker-compose.yml. Writing the profile file alone does nothing — the container must be launched with `security_opt: - apparmor=docker-vaultwarden`.

### How to check things

```shell
# All profiles — enforced, complain, unconfined
aa-status

# Live denial stream
journalctl -f | grep apparmor

# Denials for a specific profile
journalctl | grep "apparmor.*do-agent.*DENIED"

# Interactive review of accumulated denials
aa-logprof

# Verify container profile attachment
docker inspect vaultwarden | grep -i apparmor
```

### Keep it happy

```shell
# After service update — check for new denied paths
journalctl | grep "apparmor.*DENIED" | tail -20

# Reload after profile edit
apparmor_parser -r /etc/apparmor.d/<profile>

# Flip complain → enforce when clean
aa-enforce /etc/apparmor.d/<profile>

# Emergency: flip back to complain without restarting the service
aa-complain /etc/apparmor.d/<profile>
```

---

