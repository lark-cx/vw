## 18. Corrections from original

Summary of what changed from the initial draft and why:

1. **Removed rootless Docker.** The original configured both rootful `userns-remap` (Section 4) and rootless Docker (Section 10). These are mutually exclusive isolation models. Rootful + userns-remap is the right choice here — it supports low ports, AppArmor, gVisor, and the encrypted `/var/lib/docker` mount cleanly.

2. **Fixed sysctl typo.** `inet.ipv4.conf.all.log_martians` → `net.ipv4.conf.all.log_martians`. The typo caused silent failure — no martian logging.

3. **Fixed sysctl comment/value mismatch.** Comment said "restrict unprivileged user namespace creation" but the value (`1`) enabled it. Now set to `0` since rootful Docker doesn't need unprivileged user namespaces.

4. **Fixed ip_forward.** Changed from `0` to `1`. Docker bridge networking requires IP forwarding between the bridge and containers. The nftables forward chain (default drop) handles the lockdown.

5. **Fixed canary/fail2ban wiring.** The original used the `sshd` filter against `auth.log` for port 22 canary hits. Since sshd isn't on port 22, nothing ever matched. Now uses a custom `nft-canary` filter that matches the nftables `nft-canary:` log prefix in `/var/log/kern.log`.

6. **Fixed SSH config inconsistency.** Standardized on port 2222. Added explicit commented `ListenAddress 0.0.0.0` for setup phase so the sequence is clear.

7. **Fixed AppArmor/Docker wiring.** Added `apparmor=docker-vaultwarden` to Vaultwarden's `security_opt` in compose. Without this, the AppArmor profile exists but is never attached to the container.

8. **Removed custom seccomp profile.** Docker's default seccomp profile blocks ~44 dangerous syscalls and is well-tested. A hand-rolled allowlist on day one is a maintenance burden — if Vaultwarden or gVisor needs a syscall not on your list, it fails silently. Start with default; custom seccomp is an advanced exercise.

9. **Moved backup script off noexec volume.** `backup.sh` was stored on `/srv/data` (mounted noexec) but executed by cron. Moved to `/usr/local/sbin/vaultwarden-backup.sh`.

10. **Pinned container images by digest** in docker-compose.yml. Floating `:latest` tags on a password server are a supply chain risk.

11. **Added `auto_https disable_redirects`** to Caddyfile. Since port 80 is only for ACME challenges, we don't want generic HTTP→HTTPS redirects.

12. **Added `dockerd --validate`** before daemon restarts as operational habit.

13. **Added `/usr/local/sbin` to AIDE watch paths.** Since we moved scripts there, AIDE should monitor it.

14. **Replaced all `/dev/sdX` with `/dev/disk/by-id/scsi-0DO_Volume_*` paths.** Device letters (`/dev/sdb`, `/dev/sdc`, `/dev/sdd`) are not stable across reboots on DigitalOcean — volumes can reorder. The by-id paths are symlinks tied to the volume identity, not the attachment order. Used in crypttab, fstab, cryptsetup commands, and the backup script.

15. **Added multipathd and plymouth to service purge list.** multipathd (SAN multipath I/O) and plymouth (graphical boot splash) are both unnecessary on a headless VPS and were found running on fresh Ubuntu 24.04 droplets.

16. **Added kernel module blacklist.** Blacklisted ~15 unnecessary modules (RAID, BTRFS, KVM, joystick, PS/2 mouse, GPU, CD-ROM, multipath) via `/etc/modprobe.d/blacklist-vps.conf`. Saves ~2.5MB kernel memory and reduces attack surface. Left crypto acceleration, nftables, TLS offload, and systemd automounting modules alone.

17. **Added postfix/exim purge.** Ubuntu cloud images ship with an MTA that listens on TCP port 25 by default. On a Vaultwarden server this is unnecessary attack surface and a spam relay risk.

18. **Moved encrypted swap before LUKS volume setup.** LUKS key derivation (Argon2) needs more memory than a 1GB droplet has. With swap available, Argon2 can hit its memory target instead of falling back to weaker parameters.

19. **Added `--pbkdf argon2id --pbkdf-memory 512000`** to all `cryptsetup luksFormat` and `luksAddKey` commands. Explicit lower memory target avoids warnings and keeps KDF parameters predictable on small droplets.

20. **Fixed `luksAddKey` to specify `--key-file`.** Volumes were formatted with keyfiles, not passphrases. Without `--key-file`, `luksAddKey` prompts for a passphrase that doesn't exist yet.

21. **Added `systemctl daemon-reload` + `mount -a`** after fstab/crypttab changes. systemd caches mount units — without a daemon-reload, fstab changes don't take effect until reboot.

22. **Moved Docker daemon.json out of user accounts section.** The original configured `daemon.json` in Section 3 before Docker was installed (Section 10). Now Section 4 creates the `dockremap` user and subuid/subgid ranges, and Section 10 writes `daemon.json` after Docker is installed.

---

