---
id: L10
name: Rapid mass file modification consistent with encryption or wiping
category: endpoint-linux
status: todo
severity: critical
language: esql
index: logs-crowdstrike.fdr-*
mitre: [T1486, T1485, T1490]
data_source: CrowdStrike FDR (Linux) file-write telemetry
suppression:
  fields: [host.id]
  duration: 1h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
Linux ransomware (ESXi and NAS variants especially) rewrites hundreds of files in seconds and drops a ransom note. A single process touching a large number of distinct files across many directories in a short window, or bulk crypto tooling run over a directory tree, is the encryption event itself.

A single `openssl enc` or `gpg --encrypt` is how backup scripts protect their archives, so branch A only counts encryption driven across a tree by `find -exec`. Overwriting a block device from `/dev/urandom` is a wipe; writing it to `/dev/null` is a benchmark and is excluded.

## Query
```esql
FROM logs-crowdstrike.fdr-* METADATA _id, _index, _version
| WHERE event.action == "ProcessRollup2" AND host.os.type == "linux"
// Branch A: bulk crypto/wipe command shapes
| EVAL cmd = TO_LOWER(COALESCE(process.command_line, "")), pname = TO_LOWER(COALESCE(process.name, ""))
| WHERE (pname == "find" AND cmd LIKE "*-exec*" AND (cmd LIKE "*openssl*enc*" OR cmd LIKE "*gpg*"))
   OR (pname == "dd" AND cmd LIKE "*if=/dev/urandom*" AND cmd LIKE "*of=/dev/*" AND NOT cmd LIKE "*of=/dev/null*")
   OR (cmd LIKE "*.vmdk*" AND cmd LIKE "*encrypt*")
   OR cmd LIKE "*esxcli*vm process kill*"
| KEEP @timestamp, host.id, host.name, user.name, process.parent.name, pname, process.command_line
```
Branch B (volume-based) needs file-write events. Run it as a second rule once you confirm which `*FileWritten` and `FileRenameInfo` events your Linux sensors send and that they carry the writing process name (newer sensors set `process.name` from `ContextBaseFileName`):
```esql
FROM logs-crowdstrike.fdr-*
| WHERE host.os.type == "linux" AND (event.action LIKE "*FileWritten" OR event.action == "FileRenameInfo")
| EVAL pname = TO_LOWER(COALESCE(process.name, "unknown")), ext = TO_LOWER(file.extension)
// package managers, archivers and sync tools write thousands of files by design
| WHERE pname NOT IN ("dpkg", "rpm", "dnf", "yum", "apt", "apt-get", "unattended-upgr", "packagekitd", "pip", "pip3", "npm", "rsync", "tar", "unzip", "cp", "git")
| STATS files = COUNT_DISTINCT(file.path), dirs = COUNT_DISTINCT(file.directory), new_exts = VALUES(ext), host.name = VALUES(host.name)
    BY host.id, process.entity_id, pname, BUCKET(@timestamp, 5 minutes)
| WHERE files >= 200 AND dirs >= 5
```

## Suppression
Suppress by `host.id` for 1h. Alerts missing a key field are not suppressed. Encryption produces thousands of events. One alert per host, and every new host still alerts. `host.id` is the Falcon agent ID and is always present; `host.name` is filled only when the integration's host metadata enrichment is on.

## Known false positives / exclusions
- Large `dd` disk wipes during decommissioning. Exclude known imaging and decommissioning hosts.
- Branch B: package managers, archivers and sync tools are excluded by name above. Exclude build hosts and backup restore jobs by host.
- `esxcli vm process kill` is also an admin command for hung VMs, but it only appears where a sensor runs on the hypervisor shell.

## Triage
- Isolate every host showing branch B. Identify the ransom note filename from VALUES and sweep the fleet for it. Check W05/W06 equivalents and initial access.

## Test
Branch A: on a lab host, use `find -exec` to encrypt the files in a disposable test directory with `openssl enc`, then delete the directory.
