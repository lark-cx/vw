## 10. Docker + gVisor

Two isolation layers working together:

**Rootful Docker + userns-remap** — the Docker daemon runs as root but remaps container UIDs. Container root maps to an unprivileged host UID (the `dockremap` user created in Section 4). A container escape lands as a user that owns nothing on the host.

**gVisor** — interposes a user-space kernel between containers and the host kernel. Containers make syscalls to gVisor, not directly to Linux. A kernel exploit in the container hits gVisor's kernel, not the host.

```
Container process
      ↓
gVisor kernel (user-space)
      ↓  filtered syscalls
Docker default seccomp profile (~44 blocked syscalls)
      ↓  approved syscalls only
Linux host kernel
```

We use Docker's default seccomp profile rather than a custom allowlist. The default blocks dangerous syscalls like ptrace, mount, and kexec_load. A custom profile is an advanced exercise for after the baseline is proven stable.

### Install Docker (rootful)

```shell
curl -fsSL https://get.docker.com | sh
systemctl enable docker
```

### Configure daemon.json — userns-remap + logging

The `dockremap` user and its subuid/subgid ranges were created in Section 4. This config tells Docker to use them.

```shell
mkdir -p /etc/docker
cat > /etc/docker/daemon.json << 'EOF'
{
  "userns-remap": "dockremap",
  "no-new-privileges": true,
  "live-restore": true,
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  }
}
EOF

dockerd --validate --config-file=/etc/docker/daemon.json
systemctl restart docker
```

### Verify userns-remap is active

```shell
docker info | grep "Docker Root Dir"
# Path like /var/lib/docker/100000.100000 confirms remapping

# Container root maps to unprivileged host UID
docker run --rm alpine id        # shows uid=0 inside
ps aux | grep alpine             # shows UID 100000 on host
```

### Install gVisor

```shell
curl -fsSL https://gvisor.dev/archive.key | \
  gpg --dearmor -o /usr/share/keyrings/gvisor-archive-keyring.gpg

echo "deb [arch=$(dpkg --print-architecture) \
  signed-by=/usr/share/keyrings/gvisor-archive-keyring.gpg] \
  https://storage.googleapis.com/gvisor/releases release main" | \
  tee /etc/apt/sources.list.d/gvisor.list

apt update && apt install -y runsc
```

### Register gVisor runtime

Add gVisor to the existing daemon.json:

```shell
cat > /etc/docker/daemon.json << 'EOF'
{
  "userns-remap": "dockremap",
  "no-new-privileges": true,
  "live-restore": true,
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  },
  "runtimes": {
    "runsc": { "path": "/usr/bin/runsc" }
  }
}
EOF

dockerd --validate --config-file=/etc/docker/daemon.json
systemctl restart docker
```

Note: gVisor is registered as an available runtime, not the default. We specify `runtime: runsc` per-container in compose files where we want the extra isolation (Caddy, Vaultwarden). System containers like ntfy run on the standard runc runtime.

### How to check things

```shell
docker info | grep -E 'Runtimes|Default Runtime|Security'

# Test gVisor
docker run --rm --runtime=runsc alpine dmesg 2>&1 | head -5
# Should show gVisor kernel messages, not host kernel
```

---

