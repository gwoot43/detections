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
---
## Why this is high fidelity
Mounting the host filesystem into a privileged container, writing to the Docker socket from inside a workload, or `nsenter` into the host namespaces are the standard container-escape moves. In a hardened cluster these do not come from application workloads.

## Query
```esql
FROM logs-crowdstrike.fdr-* METADATA _id, _index, _version
| WHERE event.action == "ProcessRollup2" AND host.os.type == "linux"
| EVAL cmd = TO_LOWER(process.command_line), pname = TO_LOWER(process.name)
| WHERE (pname IN ("docker", "podman", "nerdctl") AND cmd LIKE "*run*" AND (cmd LIKE "*--privileged*" OR cmd LIKE "*--pid=host*" OR cmd LIKE "*--net=host*" OR cmd LIKE "* -v /:/*" OR cmd LIKE "*-v /var/run/docker.sock*" OR cmd LIKE "*--cap-add=sys_admin*" OR cmd LIKE "*--cap-add=all*" OR cmd LIKE "*--security-opt*apparmor=unconfined*" OR cmd LIKE "*--device=/dev/*"))
   OR (pname == "nsenter" AND (cmd LIKE "*-t 1*" OR cmd LIKE "*--target 1*") AND (cmd LIKE "*-m*" OR cmd LIKE "*--mount*"))
   OR (cmd LIKE "*docker.sock*" AND (cmd LIKE "*curl*" OR cmd LIKE "*/containers/create*" OR cmd LIKE "*/exec*"))
   OR (cmd LIKE "*/proc/1/root*" OR cmd LIKE "*/proc/sys/kernel/core_pattern*")
   OR (cmd LIKE "*mount*" AND cmd LIKE "*-o bind*" AND cmd LIKE "*/host*")
   OR (pname IN ("kubectl", "crictl") AND (cmd LIKE "*exec*" AND cmd LIKE "*-it*" AND cmd LIKE "*/bin/*") AND cmd LIKE "*--privileged*")
   OR (cmd LIKE "*release_agent*" OR cmd LIKE "*cgroup*notify_on_release*")
| KEEP @timestamp, host.name, user.name, process.parent.name, pname, process.command_line
```

## Known false positives / exclusions
- CI/CD building images with `--privileged` DinD. Exclude by the build-runner host or user.
- Cluster operators using `nsenter` for legitimate debugging. Exclude the operator jump host.

## Triage
- A `--privileged` container from an application namespace or a metadata token fetch inside a pod is a compromise. Check what the container did next (L02, L05).

## Test
`docker run --rm -v /:/host alpine cat /host/etc/hostname` on a lab host.
