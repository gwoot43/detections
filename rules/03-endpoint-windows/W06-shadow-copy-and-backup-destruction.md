---
id: W06
name: Shadow copy deletion, backup catalog wipe or boot recovery disabled
category: endpoint-windows
status: todo
severity: critical
language: esql
index: logs-crowdstrike.fdr-*
mitre: [T1490, T1485]
data_source: CrowdStrike FDR ProcessRollup2
suppression:
  fields: [host.name]
  duration: 1h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
These commands appear in nearly every ransomware playbook and in almost no admin runbook. Volume is near zero outside an attack.

## Query
```esql
FROM logs-crowdstrike.fdr-* METADATA _id, _index, _version
| WHERE event.action == "ProcessRollup2" AND host.os.type == "windows"
| EVAL pname = TO_LOWER(process.name), cmd = TO_LOWER(process.command_line)
| WHERE (pname == "vssadmin.exe" AND (cmd LIKE "*delete shadows*" OR cmd LIKE "*resize shadowstorage*"))
   OR (pname == "wmic.exe"     AND cmd LIKE "*shadowcopy*" AND cmd LIKE "*delete*")
   OR (pname IN ("powershell.exe", "pwsh.exe") AND cmd LIKE "*win32_shadowcopy*" AND (cmd LIKE "*delete*" OR cmd LIKE "*remove*"))
   // routine rotation ("delete systemstatebackup -keepversions:N", N >= 1) is excluded; keepversions:0 deletes everything
   OR (pname == "wbadmin.exe"  AND (cmd LIKE "*delete catalog*" OR cmd LIKE "*-keepversions:0*" OR (cmd LIKE "*delete*backup*" AND NOT cmd LIKE "*-keepversions:*")))
   OR (pname == "bcdedit.exe"  AND (cmd LIKE "*recoveryenabled no*" OR cmd LIKE "*bootstatuspolicy ignoreallfailures*"))
   OR (pname == "diskshadow.exe" AND cmd LIKE "*delete shadows*")
   OR (pname == "fsutil.exe" AND cmd LIKE "*usn deletejournal*")
| KEEP @timestamp, host.name, user.name, process.parent.name, pname, process.command_line
```

## Suppression
Suppress by `host.name` for 1h. Alerts missing a key field are not suppressed. Ransomware runs several backup-destruction commands in a burst. Every other host still alerts.

## Known false positives / exclusions
- Backup software resizing shadow storage under its own service parent. Exclude by parent name and exact command line.
- Scheduled system-state backup rotation on domain controllers (`wbadmin delete systemstatebackup -keepversions:N`) is already excluded unless N is 0.

## Triage
- Isolate. Determine blast radius: which other hosts had the same user or the same parent binary in the last hour.

## Test
Run the Atomic Red Team T1490 test on a disposable lab host.
