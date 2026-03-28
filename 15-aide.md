## 15. AIDE — File Integrity Monitoring

AIDE takes hashes of files, permissions, ownership, and timestamps. Run again later, it reports any differences. AIDE catches:

* A legitimate binary replaced with a backdoored version
* New SUID/SGID files
* Permission changes on /etc/sudoers, /etc/passwd
* New cron jobs or init scripts added for persistence
* Configuration file modifications

### Install and initialize

```shell
apt install -y aide aide-common

cat >> /etc/aide/aide.conf.d/99-custom << 'EOF'
/etc p+i+u+g+sha512
/bin p+i+u+g+sha512
/sbin p+i+u+g+sha512
/usr/bin p+i+u+g+sha512
/usr/sbin p+i+u+g+sha512
/usr/local/bin p+i+u+g+sha512
/usr/local/sbin p+i+u+g+sha512

/var/log p+u+g

!/var/log/.*\.log$
!/proc
!/sys
!/dev
!/run
!/tmp
!/var/lib/docker
EOF

# Initialize baseline
aide --init
mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
echo "Baseline created: $(date)" | tee /var/lib/aide/baseline-date.txt
```

### Wire up ntfy alerts on AIDE discrepancy

```shell
cat > /usr/local/sbin/aide-check.sh << 'EOF'
#!/bin/bash
REPORT=$(aide --check 2>&1)
EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
  SUMMARY=$(echo "$REPORT" | grep -E 'changed|added|removed' | head -20 | cut -c1-500)
  /usr/local/bin/ntfy-alert.sh \
    "AIDE: Filesystem change detected" \
    "${SUMMARY:-See /var/log/aide-check.log for details}" \
    "urgent"
fi

echo "=== AIDE check $(date) exit=${EXIT_CODE} ===" >> /var/log/aide-check.log
echo "$REPORT" >> /var/log/aide-check.log
EOF
chmod +x /usr/local/sbin/aide-check.sh

cat > /etc/cron.d/aide << 'EOF'
0 3 * * * root /usr/local/sbin/aide-check.sh
EOF
```

### Test AIDE

```shell
# Drop a suspicious file
touch /usr/bin/definitely-not-malware

# Run check — catches it immediately
aide --check

# Clean up, update baseline after legitimate changes
rm /usr/bin/definitely-not-malware
aide --update
mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
```

### How to check things

```shell
aide --check

# Find SUID files — compare to known list
find / -perm /6000 -type f 2>/dev/null | sort

ls -la /var/lib/aide/
tail -50 /var/log/aide-check.log
```

### Keep it happy

```shell
# After ANY intentional system change — update and document
aide --update
mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
echo "Updated: $(date) — reason: <describe change>" >> /var/lib/aide/baseline-date.txt

# Store baseline offsite — an attacker who updates AIDE's database hides their tracks
scp /var/lib/aide/aide.db admin@offsite:/backups/aide/aide-$(date +%F).db
```

---

