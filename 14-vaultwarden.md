## 14. Vaultwarden + Caddy + Coraza

Vaultwarden is the password manager. Caddy handles TLS. Coraza is an open-source WAF implementing the OWASP Core Rule Set — inspects every HTTP request for known attack patterns before they reach Vaultwarden.

```
Internet
  → nftables          network: port scans, bogons, malformed packets
  → WireGuard         unauthenticated access blocked
  → Caddy + Coraza    application: SQLi, XSS, known CVEs
  → Vaultwarden       auth: rate limiting, account lockout
  → AppArmor          MAC: deny list even with code execution
  → Seccomp (default) kernel: ~44 blocked syscalls, no capabilities
```

SQLite is used for simplicity. One fewer container. Migration to Postgres is a documented one-step export/import when needed.

### Directory structure

```shell
mkdir -p /srv/data/vaultwarden/{caddy-data,caddy-config,vw-data}
cd /srv/data/vaultwarden
```

### Build Caddy with Coraza

```dockerfile
# Dockerfile.caddy
FROM caddy:builder AS builder
RUN xcaddy build \
    --with github.com/corazawaf/coraza-caddy/v2

FROM caddy:latest
COPY --from=builder /usr/bin/caddy /usr/bin/caddy
```

```shell
docker build -f Dockerfile.caddy -t caddy-coraza .
```

### Caddyfile

```
{
    admin off
    auto_https disable_redirects
}

ward.lrk.cx {
    bind 10.255.255.2

    coraza_waf {
        load_owasp_crs
        directives `
            SecRuleEngine On
            SecRequestBodyAccess On
            SecResponseBodyAccess Off
            SecRequestBodyLimit 13107200
            SecRuleRemoveById 920420
            SecRuleRemoveById 942440
        `
    }

    header {
        Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
        X-Content-Type-Options "nosniff"
        X-Frame-Options "DENY"
        Referrer-Policy "no-referrer"
        Content-Security-Policy "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self' wss:;"
        -Server
        -X-Powered-By
    }

    reverse_proxy vaultwarden:80 {
        header_up X-Real-IP {remote_host}
        header_up X-Forwarded-For {remote_host}
        header_up X-Forwarded-Proto {scheme}
    }
}
```

### docker-compose.yml

Note: Images pinned by digest. Update digests intentionally after testing — never pull floating `:latest` on a password server.

```yaml
services:

  vaultwarden:
    # Pin by digest — get current digest: docker inspect --format='{{.RepoDigests}}' vaultwarden/server:latest
    image: vaultwarden/server:latest@sha256:REPLACE_WITH_CURRENT_DIGEST
    container_name: vaultwarden
    restart: unless-stopped
    runtime: runsc
    volumes:
      - ./vw-data:/data
    environment:
      DOMAIN: "https://ward.lrk.cx"
      DATABASE_URL: "data/vaultwarden.db"
      SIGNUPS_ALLOWED: "false"
      INVITATIONS_ALLOWED: "false"
      ADMIN_TOKEN: "${ADMIN_TOKEN}"
      LOGIN_RATELIMIT_MAX_BURST: "10"
      LOGIN_RATELIMIT_SECONDS: "60"
      ADMIN_RATELIMIT_MAX_BURST: "5"
      ADMIN_RATELIMIT_SECONDS: "60"
      LOG_LEVEL: "warn"
      EXTENDED_LOGGING: "true"
      LOG_FILE: "/data/vaultwarden.log"
      TZ: America/Phoenix
    networks:
      - internal
    security_opt:
      - no-new-privileges:true
      - apparmor=docker-vaultwarden
    cap_drop:
      - ALL
    read_only: true
    tmpfs:
      - /tmp:size=64m,noexec
      - /run:size=32m
    mem_limit: 256m
    cpus: 0.5

  caddy:
    # Pin by digest
    image: caddy-coraza:latest
    container_name: caddy
    restart: unless-stopped
    runtime: runsc
    ports:
      - "80:80"
      - "10.255.255.2:443:443"
    volumes:
      - ./Caddyfile:/etc/caddy/Caddyfile:ro
      - ./caddy-data:/data
      - ./caddy-config:/config
    networks:
      - internal
    depends_on:
      - vaultwarden
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    cap_add:
      - NET_BIND_SERVICE
    mem_limit: 128m
    cpus: 0.25

networks:
  internal:
    driver: bridge
    ipam:
      config:
        - subnet: 172.21.0.0/24
```

### Environment file

```shell
cat > .env << 'EOF'
ADMIN_TOKEN=CHANGEME_paste_argon2id_hash_here
EOF
chmod 600 .env
```

### Generate admin token

```shell
docker run --rm -it vaultwarden/server /vaultwarden hash --preset owasp
# Enter your chosen admin password
# Output: $argon2id$v=19$m=...
# In .env use single quotes to avoid $ interpolation:
# ADMIN_TOKEN='$argon2id$v=19$m=...'
```

### Deploy

```shell
docker compose up -d
docker compose logs -f
```

### How to check things

```shell
docker compose ps

# Caddy — ACME acquisition and WAF activity
docker compose logs caddy
tail -f ./vw-data/vaultwarden.log

# Returns 403 — never reaches Vaultwarden
curl -sk "https://ward.lrk.cx/?id=1'+OR+'1'='1"

# Security headers
curl -sI https://ward.lrk.cx | grep -E 'Strict|X-Content|X-Frame'

# SQLite health
docker exec vaultwarden sqlite3 /data/vaultwarden.db ".tables"
docker exec vaultwarden sqlite3 /data/vaultwarden.db "PRAGMA integrity_check;"

# Confirm AppArmor is attached
docker inspect vaultwarden | grep -i apparmor

docker stats --no-stream
```

### Keep it happy

```shell
# Update: pull new image, get new digest, update compose, redeploy
docker compose pull && docker compose up -d

# Reload Caddy config
docker compose exec caddy caddy reload --config /etc/caddy/Caddyfile

# Coraza false positive — disable specific rule
# Add to Caddyfile: SecRuleRemoveById <rule-id>

# Validate daemon config after any daemon.json change
dockerd --validate --config-file=/etc/docker/daemon.json
```

---

