## 13. ntfy — Notification Infrastructure

We wire up a lightweight notification script so every security event — SSH logins, fail2ban bans, canary hits, AIDE discrepancies — immediately ping a phone via ntfy. Swap the placeholders before publishing any recordings.

ntfy auth uses a Bearer token — not embedded in the URL. The token is generated in the ntfy admin UI or CLI and passed in the Authorization header on every request.

### Deploy ntfy (Docker, WireGuard-only)

```shell
mkdir -p /srv/data/ntfy

docker run -d \
  --name ntfy \
  --restart unless-stopped \
  -v /srv/data/ntfy:/etc/ntfy \
  -p 10.255.255.2:8080:80 \
  binwiederhier/ntfy serve \
  --cache-file /etc/ntfy/cache.db \
  --auth-file /etc/ntfy/auth.db \
  --auth-default-access deny-all

# Create admin user and generate access token
docker exec -it ntfy ntfy user add --role=admin admin
docker exec -it ntfy ntfy token add admin
# Save the tk_xxxxx token — goes in ntfy-alert.sh
```

Access the ntfy web UI at `http://10.255.255.2:8080` over WireGuard. Subscribe to your topic in the ntfy mobile app using the same token.

### Install the notification script

```shell
cat > /usr/local/bin/ntfy-alert.sh << 'EOF'
#!/bin/bash
# Central notification dispatcher
# CHANGE THESE TWO VALUES — this is the only place to update them
NTFY_URL="https://ntfy.CHANGEME.example"
NTFY_TOPIC="CHANGEME_server_alerts"
NTFY_TOKEN="tk_CHANGEME"

TITLE="${1:-Alert}"
MESSAGE="${2:-No message provided}"
PRIORITY="${3:-default}"
HOSTNAME="$(hostname -s)"

curl -sf \
  -H "Authorization: Bearer ${NTFY_TOKEN}" \
  -H "Title: [${HOSTNAME}] ${TITLE}" \
  -H "Priority: ${PRIORITY}" \
  -H "Tags: warning" \
  -d "${MESSAGE}" \
  "${NTFY_URL}/${NTFY_TOPIC}" \
  > /dev/null 2>&1

# Exit silently — a failed notification must never break the calling process
exit 0
EOF

chmod +x /usr/local/bin/ntfy-alert.sh
```

### Test the script

```shell
/usr/local/bin/ntfy-alert.sh "Test" "Notification system working" "default"
# Check your phone — should arrive within seconds
```

### How to check things

```shell
# ntfy container running
docker ps | grep ntfy

# ntfy logs — see delivery attempts
docker logs ntfy --tail 20

# Test auth is working
curl -H "Authorization: Bearer tk_YOURTOKEN" \
  http://10.255.255.2:8080/YOURTOPIC/json?poll=1
```

### Keep it happy

```shell
# Rotate token
docker exec -it ntfy ntfy token del <old-token>
docker exec -it ntfy ntfy token add admin
# Update NTFY_TOKEN in /usr/local/bin/ntfy-alert.sh

# ntfy update
docker pull binwiederhier/ntfy
docker stop ntfy && docker rm ntfy
# Re-run the docker run command above
```

---

