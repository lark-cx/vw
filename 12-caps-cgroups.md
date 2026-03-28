## 12. Namespace + Capability + Cgroup Restrictions

Capabilities: Linux splits root privileges into discrete units. Instead of all-or-nothing root, a process can have just NET_BIND_SERVICE without SYS_ADMIN.

No new privileges: Prevents a container process from using SUID bits or file capabilities to gain more privileges via execve().

Read-only root filesystem: Container's root filesystem is immutable. An attacker with code execution cannot persist changes or drop tools into standard paths like /usr/bin.

Resource limits: Prevents a compromised container from consuming resources that could trigger the OOM killer and take the system down. On 1GB RAM this matters.

These are applied per-container in docker-compose.yml (see Section 14).

```yaml
security_opt:
  - no-new-privileges:true
  - apparmor=docker-vaultwarden      # must match profile name
cap_drop:
  - ALL
read_only: true
tmpfs:
  - /tmp:size=64m,noexec
  - /run:size=32m
mem_limit: 256m
cpus: 0.5
```

### Verify restrictions are active

```shell
# No capabilities
docker exec vaultwarden capsh --print
# Read-only root filesystem
docker exec vaultwarden touch /test-file
# Can write to data volume
docker exec vaultwarden touch /data/test && echo "data write OK"

# Memory limit enforced
docker stats vaultwarden --no-stream
```

---

