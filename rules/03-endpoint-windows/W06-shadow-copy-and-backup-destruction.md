---
id: W06
name: Shadow copy deletion, backup catalog wipe or boot recovery disabled
category: endpoint-windows
status: todo
language: esql
index: logs-yourorg-crowdstrike-data-default*
mitre: [T1490, T1485]
data_source: CrowdStrike FDR ProcessRollup2
suppression:
  fields: [host.id]
  duration: 1h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
These commands appear in nearly every ransomware playbook and in almost no admin runbook. Volume is near zero outside an attack.

## Query
```esql
FROM logs-yourorg-crowdstrike-data-default* METADATA _id, _index, _version
| WHERE event.action == "processrollup2" AND host.os.type == "windows"
| EVAL pname = TO_LOWER(process.name), cmd = TO_LOWER(process.command_line)
| WHERE (pname == "vssadmin.exe" AND (cmd LIKE "*delete shadows*" OR cmd LIKE "*resize shadowstorage*"))
   OR (pname == "wmic.exe"     AND cmd LIKE "*shadowcopy*" AND cmd LIKE "*delete*")
   OR (pname IN ("powershell.exe", "pwsh.exe") AND cmd LIKE "*win32_shadowcopy*" AND (cmd LIKE "*delete*" OR cmd LIKE "*remove*"))
   // routine rotation ("delete systemstatebackup -keepversions:N", N >= 1) is excluded; keepversions:0 deletes everything
   OR (pname == "wbadmin.exe"  AND (cmd LIKE "*delete catalog*" OR cmd LIKE "*-keepversions:0*" OR (cmd LIKE "*delete*backup*" AND NOT cmd LIKE "*-keepversions:*")))
   OR (pname == "bcdedit.exe"  AND (cmd LIKE "*recoveryenabled no*" OR cmd LIKE "*bootstatuspolicy ignoreallfailures*"))
   OR (pname == "diskshadow.exe" AND cmd LIKE "*delete shadows*")
   OR (pname == "fsutil.exe" AND cmd LIKE "*usn deletejournal*")
| KEEP @timestamp, host.id, host.name, user.name, process.parent.name, pname, process.command_line, _id, _version, _index
```

**CrowdStrike (Falcon LogScale / Advanced Event Search)**
```logscale
#event_simpleName=/^(ProcessRollup2|SyntheticProcessRollup2)$/ event_platform=Win
| case {
    FileName=/^vssadmin\.exe$/i CommandLine=/delete shadows|resize shadowstorage/i;
    FileName=/^wmic\.exe$/i CommandLine=/shadowcopy/i CommandLine=/delete/i;
    FileName=/^(powershell|pwsh)\.exe$/i CommandLine=/win32_shadowcopy/i CommandLine=/delete|remove/i;
    // routine rotation ("delete systemstatebackup -keepversions:N", N >= 1) is excluded; keepversions:0 deletes everything
    FileName=/^wbadmin\.exe$/i CommandLine=/delete catalog|-keepversions:0/i;
    FileName=/^wbadmin\.exe$/i CommandLine=/delete.*backup/i CommandLine!=/-keepversions:/i;
    FileName=/^bcdedit\.exe$/i CommandLine=/recoveryenabled no|bootstatuspolicy ignoreallfailures/i;
    FileName=/^diskshadow\.exe$/i CommandLine=/delete shadows/i;
    FileName=/^fsutil\.exe$/i CommandLine=/usn deletejournal/i;
  }
| select([@timestamp, aid, ComputerName, UserName, ParentBaseFileName, FileName, CommandLine])
```

## Suppression
Suppress by `host.id` for 1h. Alerts missing a key field are not suppressed. Ransomware runs several backup-destruction commands in a burst. Every other host still alerts. `host.id` is the Falcon agent ID and is always present; `host.name` is filled only when the integration's host metadata enrichment is on.

## Known false positives / exclusions
- Backup software resizing shadow storage under its own service parent. Exclude by parent name and exact command line.
- Scheduled system-state backup rotation on domain controllers (`wbadmin delete systemstatebackup -keepversions:N`) is already excluded unless N is 0.

## Triage
- Isolate. Determine blast radius: which other hosts had the same user or the same parent binary in the last hour.

## Test
Run the Atomic Red Team T1490 test on a disposable lab host.
