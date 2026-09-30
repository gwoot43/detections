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
  fields: [host.name]
  duration: 1h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
Linux ransomware (ESXi and NAS variants especially) rewrites hundreds of files in seconds and drops a ransom note. A single process touching a large number of distinct files across many directories in a short window, or invoking bulk crypto tooling, is the encryption event itself.

## Query
```esql
FROM logs-crowdstrike.fdr-* METADATA _id, _index, _version
| WHERE host.os.type == "linux"
// Branch A: bulk crypto/wipe command shapes
| EVAL cmd = TO_LOWER(COALESCE(process.command_line, "")), pname = TO_LOWER(COALESCE(process.name, ""))
| EVAL crypto_cmd = CASE(
     (pname == "openssl" AND cmd LIKE "*enc*" AND (cmd LIKE "*-aes*" OR cmd LIKE "*-e *")) OR cmd LIKE "*gpg*--encrypt*--recipient*"
     OR (pname IN ("find") AND cmd LIKE "*-exec*" AND (cmd LIKE "*openssl*enc*" OR cmd LIKE "*gpg*"))
     OR (pname == "dd" AND cmd LIKE "*of=/dev/*" AND cmd LIKE "*if=/dev/urandom*")
     OR (cmd LIKE "*.vmdk*" AND cmd LIKE "*encrypt*") OR cmd LIKE "*vim-cmd*vmsvc/power.off*"
     OR cmd LIKE "*esxcli*vm process kill*", 1, 0)
| WHERE event.action == "ProcessRollup2" AND crypto_cmd == 1
| KEEP @timestamp, host.name, user.name, process.parent.name, pname, process.command_line
```
Branch B (volume-based) needs file-write events. Run it as a second rule once you confirm the file-write event name in your feed (Falcon Linux emits generic file events; confirm the `event.action` value):
```esql
FROM logs-crowdstrike.fdr-*
| WHERE host.os.type == "linux" AND event.action IN ("NewFileWritten", "FileRenameInfo", "GenericFileWritten")
| EVAL ext = TO_LOWER(file.extension)
| STATS files = COUNT_DISTINCT(file.path), dirs = COUNT_DISTINCT(file.directory), new_exts = VALUES(ext)
    BY process.entity_id, host.name, process.name, BUCKET(@timestamp, 5 minutes)
| WHERE files >= 200 AND dirs >= 5
```

## Suppression
Suppress by `host.name` for 1h. Alerts missing a key field are not suppressed. Encryption produces thousands of events. One alert per host, and every new host still alerts.

## Known false positives / exclusions
- Legitimate backup encryption and large `dd` disk clones. Exclude the backup service account and known imaging hosts.
- Developer builds writing many files. Exclude build hosts on branch B.

## Triage
- Isolate every host showing branch B. Identify the ransom note filename from VALUES and sweep the fleet for it. Check W05/W06 equivalents and initial access.

## Test
Branch A: `find /labdir -type f -exec openssl enc -aes-256-cbc -k test -in {} -out {}.enc \;` on a disposable lab directory.
