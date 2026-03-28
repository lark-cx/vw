## 3. Volume Setup — Encrypted Storage + Mount Hardening

LUKS encryption: If someone images a cloud volume snapshot or physically pulls a disk, unencrypted data is immediately readable. LUKS (Linux Unified Key Setup) encrypts the entire block device. Without the key, the data is unrecoverable.

Mount options: Even on encrypted volumes, filesystem mount flags control what the OS allows on that mount regardless of file permissions:

* nosuid — SUID/SGID bits on executables are ignored. A malicious SUID binary dropped into /tmp or a data volume cannot escalate privileges.
* noexec — No executing binaries from this mount. An attacker who writes a script to /srv/data cannot run it directly.
* nodev — No device files. Prevents creation of device nodes that could be used to access raw hardware.

We use three DigitalOcean block storage volumes. On DO, volumes appear as `/dev/disk/by-id/scsi-0DO_Volume_<name>` — use these stable paths everywhere instead of `/dev/sdX` letters, which can shift across reboots.

```
/dev/disk/by-id/scsi-0DO_Volume_vaultwarden-docker  →  /var/lib/docker  LUKS  nosuid, nodev
/dev/disk/by-id/scsi-0DO_Volume_vaultwarden-data    →  /srv/data        LUKS  nosuid, noexec, nodev
/dev/disk/by-id/scsi-0DO_Volume_vaultwarden-log     →  /var/log               nosuid, noexec, nodev
```

Verify your volume paths after first login:

```shell
ls -l /dev/disk/by-id/scsi-0DO_*
```

For convenience, the rest of this section uses shell variables. Set these once per session:

```shell
VOL_DOCKER="/dev/disk/by-id/scsi-0DO_Volume_vaultwarden-docker"
VOL_DATA="/dev/disk/by-id/scsi-0DO_Volume_vaultwarden-data"
VOL_LOG="/dev/disk/by-id/scsi-0DO_Volume_vaultwarden-log"
```

Auto-unlock uses a keyfile so the server can reboot unattended. A recovery passphrase is also enrolled and stored in Vaultwarden after setup.

### Create keyfiles

```shell
mkdir -p /etc/keys
chmod 700 /etc/keys

# 512 bytes of random key material per volume
dd if=/dev/urandom of=/etc/keys/docker.key bs=512 count=1
dd if=/dev/urandom of=/etc/keys/data.key   bs=512 count=1
chmod 400 /etc/keys/*.key
```

### Format and open LUKS volumes

On a 1GB droplet, Argon2 needs a lower memory target. With swap enabled (Section 2), the default would work — but `--pbkdf-memory 512000` keeps it comfortable and avoids warnings.

```shell
# Docker volume
cryptsetup luksFormat "$VOL_DOCKER" --type luks2 --batch-mode \
  --key-file /etc/keys/docker.key \
  --pbkdf argon2id --pbkdf-memory 512000
cryptsetup open "$VOL_DOCKER" docker-data --key-file /etc/keys/docker.key

# App data volume
cryptsetup luksFormat "$VOL_DATA" --type luks2 --batch-mode \
  --key-file /etc/keys/data.key \
  --pbkdf argon2id --pbkdf-memory 512000
cryptsetup open "$VOL_DATA" app-data --key-file /etc/keys/data.key

# Add recovery passphrase to each — store in Vaultwarden later
# --key-file authenticates with the existing keyfile, then prompts for the new passphrase
cryptsetup luksAddKey "$VOL_DOCKER" \
  --key-file /etc/keys/docker.key \
  --pbkdf argon2id --pbkdf-memory 512000
cryptsetup luksAddKey "$VOL_DATA" \
  --key-file /etc/keys/data.key \
  --pbkdf argon2id --pbkdf-memory 512000
```

### Format filesystems and mount

```shell
mkfs.ext4 /dev/mapper/docker-data
mkfs.ext4 /dev/mapper/app-data

mkdir -p /var/lib/docker /srv/data

mount /dev/mapper/docker-data /var/lib/docker
mount /dev/mapper/app-data    /srv/data

# Log volume — no encryption, but still restricted
# IMPORTANT: preserve existing /var/log contents or journald/sshd/etc break
mkfs.ext4 "$VOL_LOG"
mkdir -p /mnt/newlog
mount "$VOL_LOG" /mnt/newlog
cp -a /var/log/* /mnt/newlog/
umount /mnt/newlog
rmdir /mnt/newlog
mount "$VOL_LOG" /var/log
```

### Configure auto-unlock and hardened mount options

```shell
# /etc/crypttab — auto-unlock at boot (by-id paths survive reboot)
cat >> /etc/crypttab << EOF
docker-data  ${VOL_DOCKER}  /etc/keys/docker.key  luks,discard
app-data     ${VOL_DATA}    /etc/keys/data.key    luks,discard
EOF

# /etc/fstab — hardened mount options
cat >> /etc/fstab << EOF
/dev/mapper/docker-data  /var/lib/docker  ext4  defaults,nosuid,nodev              0 2
/dev/mapper/app-data     /srv/data        ext4  defaults,nosuid,noexec,nodev        0 2
${VOL_LOG}               /var/log         ext4  defaults,nosuid,noexec,nodev        0 2
EOF
```

Note on noexec and Docker: The Docker data volume needs to be executable — container images contain binaries the runtime executes from that path. nosuid and nodev still apply.

### Apply fstab changes

systemd caches mount units from fstab. After any fstab change, reload and remount:

```shell
systemctl daemon-reload
mount -a
```

### Harden standard filesystem mounts

```shell
# /tmp as tmpfs — writable by all, high-value target for privilege escalation
echo "tmpfs  /tmp  tmpfs  defaults,nosuid,noexec,nodev,size=512m  0 0" >> /etc/fstab
# /proc — restrict process information visibility
# hidepid=2: users can only see their own processes
echo "proc  /proc  proc  defaults,hidepid=2  0 0" >> /etc/fstab

# Reload and apply
systemctl daemon-reload
mount -o remount /tmp
mount -o remount /proc
```

### How to check things

```shell
# View LUKS header — shows enrolled key slots
cryptsetup luksDump "$VOL_DOCKER"

# List open encrypted volumes
lsblk -f
dmsetup ls --target crypt

# Confirm mount options are active
findmnt /var/lib/docker
findmnt /srv/data
findmnt /var/log
findmnt /tmp

# Demonstrate nosuid working
cp /bin/id /tmp/test-suid
chmod u+s /tmp/test-suid
/tmp/test-suid   # does NOT show root despite SUID bit
rm /tmp/test-suid

# Demonstrate noexec working
echo '#!/bin/bash' > /srv/data/test.sh
echo 'echo executed' >> /srv/data/test.sh
chmod +x /srv/data/test.sh
/srv/data/test.sh   # Permission denied
rm /srv/data/test.sh
```

### Keep it happy

```shell
# Test recovery passphrase before you need it
cryptsetup open --test-passphrase "$VOL_DOCKER"

# Back up LUKS headers offsite — without these, encrypted data is permanently lost
cryptsetup luksHeaderBackup "$VOL_DOCKER" --header-backup-file /srv/data/luks-docker-header.bak
cryptsetup luksHeaderBackup "$VOL_DATA"   --header-backup-file /srv/data/luks-data-header.bak

# After kernel or initramfs update
update-initramfs -u
```

---

