---
id: L08
name: Container escape, privileged container launch or Docker socket abuse
category: endpoint-linux
status: todo
severity: high
language: esql
index: logs-crowdstrike.fdr-*
mitre: [T1611, T1610, T1613]
data_source: CrowdStrike FDR ProcessRollup2 (Linux)
suppression:
  fields: [host.id]
  duration: 1h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
Mounting the host filesystem into a privileged container, creating containers or exec sessions through the Docker socket from a shell, or `nsenter` into PID 1's namespaces are the standard container-escape moves. In a hardened cluster these do not come from application workloads.

Not matched, because monitoring and infrastructure agents use them by design: `--net=host`, `--device=/dev/...`, mounting `docker.sock` into a container (cAdvisor, Portainer, CI agents), and read-only Docker API calls such as `/containers/json` or `/_ping`.

## Query
```esql
FROM logs-crowdstrike.fdr-* METADATA _id, _index, _version
| WHERE event.action == "ProcessRollup2" AND host.os.type == "linux"
| EVAL cmd = TO_LOWER(process.command_line), pname = TO_LOWER(process.name)
| WHERE (pname IN ("docker", "podman", "nerdctl") AND cmd LIKE "*run*"
         AND (cmd LIKE "*--privileged*" OR cmd LIKE "*--pid=host*" OR cmd LIKE "* -v /:/*" OR cmd LIKE "*--volume /:/*" OR cmd LIKE "*--volume=/:/*"
              OR cmd LIKE "*--cap-add=sys_admin*" OR cmd LIKE "*--cap-add=all*" OR cmd LIKE "*--security-opt*apparmor=unconfined*"))
   OR (pname == "nsenter" AND (cmd LIKE "*-t 1 *" OR cmd LIKE "*--target 1 *" OR cmd LIKE "*--target=1 *") AND (cmd LIKE "*-m*" OR cmd LIKE "*--mount*"))
   OR (cmd LIKE "*docker.sock*" AND (cmd LIKE "*/containers/create*" OR cmd LIKE "*/exec*"))
   OR cmd LIKE "*/proc/1/root*"
   OR cmd LIKE "*>*/proc/sys/kernel/core_pattern*"
   OR (cmd LIKE "*release_agent*" OR cmd LIKE "*cgroup*notify_on_release*")
| KEEP @timestamp, host.id, host.name, user.name, process.parent.name, pname, process.command_line, _id, _version, _index
```

## Suppression
Suppress by `host.id` for 1h. Alerts missing a key field are not suppressed. Escape attempts are retried. `host.id` is the Falcon agent ID and is always present; `host.name` is filled only when the integration's host metadata enrichment is on.

## Known false positives / exclusions
- CI/CD building images with `--privileged` DinD. Exclude by the build-runner host or user.
- Cluster operators using `nsenter` for legitimate debugging. Exclude the operator jump host.

## Triage
- A `--privileged` container started outside your CI runners, or a Docker API `create` call from a shell, is a compromise until proven otherwise. Check what the container did next (L02, L05).

## Test
On a lab host, start a throwaway container with the host root filesystem bind-mounted, read one harmless file, then remove the container.
