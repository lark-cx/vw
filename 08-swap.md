## 2. Encrypted Swap

Swap pages can contain passwords, session tokens, and decrypted vault data. We use an ephemeral random key. Each boot renders the previous session's swap unrecoverable.

We set up swap before LUKS volumes because LUKS key derivation (Argon2) needs more memory than a 1GB droplet has available. With swap in place, Argon2 can page out to hit its memory target. Without it, `cryptsetup luksFormat` falls back to weaker KDF parameters.

```shell
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
```

### How to check things

```shell
swapon --show
dmsetup info cryptswap
free -h
```

---

