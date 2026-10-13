---
id: W06
name: Shadow copies, backups or boot recovery destroyed
category: endpoint-windows
status: todo
severity: critical
language: esql
index: logs-crowdstrike.fdr-*
mitre: [T1490, T1485]
data_source: CrowdStrike FDR ProcessRollup2
suppression:
  fields: [host.id]
  duration: 1h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
Deleting the ways a host can be restored is in nearly every ransomware playbook and almost no admin runbook. The rule matches what is being destroyed, not which tool does it:
- **Shadow copies** deleted or shrunk, whether by `vssadmin`, `wmic`, `diskshadow` or PowerShell.
- **Windows Server Backup** deleted, except routine rotation that keeps at least one version (`-keepversions:1` or more).
- **Boot recovery** turned off with `bcdedit` (`recoveryenabled no`, `ignoreallfailures`).
- **The NTFS change journal** deleted with `fsutil usn deletejournal`, which removes file-change history.

## Query
```esql
FROM logs-crowdstrike.fdr-* METADATA _id, _index, _version
| WHERE event.action == "ProcessRollup2" AND host.os.type == "windows"
| EVAL cmd = TO_LOWER(process.command_line)
| WHERE (cmd LIKE "*shadow*" AND (cmd LIKE "*delete*" OR cmd LIKE "*resize*" OR cmd LIKE "*remove*"))
     OR (cmd LIKE "*wbadmin*delete*" AND NOT cmd RLIKE """.*keepversions:[1-9].*""")
     OR cmd LIKE "*recoveryenabled no*" OR cmd LIKE "*ignoreallfailures*"
     OR cmd LIKE "*deletejournal*"
| KEEP @timestamp, host.id, host.name, user.name, process.parent.name, process.name, process.command_line,
       _id, _version, _index
```

This rule doesn't use rarity. Backups destroyed on many hosts at once is the attack at its worst.

## Suppression
Suppress by `host.id` for 1h. Alerts missing a key field are not suppressed. Ransomware runs several of these commands in a burst. Every other host still alerts. `host.id` is the Falcon agent ID and is always present.

## Known false positives / exclusions
- Backup software resizing shadow storage under its own service. Exclude by exact command line.
- Scheduled system-state backup rotation on domain controllers (`wbadmin delete systemstatebackup -keepversions:3`) doesn't match.

## Triage
- Isolate. Work out the blast radius: which other hosts saw the same user or the same parent program in the last hour.

## Test
Run the Atomic Red Team T1490 test on a disposable lab host.
