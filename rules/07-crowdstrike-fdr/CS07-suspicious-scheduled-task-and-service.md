---
id: CS07
name: Scheduled task or service created pointing at a suspicious payload
category: crowdstrike-fdr
status: todo
severity: high
language: esql
index: logs-crowdstrike.fdr-*
mitre: [T1053.005, T1543.003]
data_source: CrowdStrike FDR ScheduledTaskRegistered / ServiceStarted events
---
## Why this is high fidelity
Falcon has dedicated events for task and service registration, which is cleaner than parsing `schtasks.exe` command lines. The payload path and command decide fidelity: a task or service running from a user-writable path, a script host, or an encoded command is persistence.

## Query
```esql
FROM logs-crowdstrike.fdr-*
| WHERE event.action IN ("ScheduledTaskRegistered", "ScheduledTaskModified", "ServiceStarted", "ServiceCreated", "NewServiceCreated")
| EVAL payload = TO_LOWER(TO_STRING(COALESCE(process.command_line, registry.data.strings, file.path)))
| WHERE payload LIKE "*\\temp\\*" OR payload LIKE "*\\appdata\\*" OR payload LIKE "*\\programdata\\*" OR payload LIKE "*\\users\\public\\*" OR payload LIKE "*\\downloads\\*"
     OR payload LIKE "*powershell*" OR payload LIKE "*mshta*" OR payload LIKE "*rundll32*" OR payload LIKE "*regsvr32*" OR payload LIKE "*wscript*" OR payload LIKE "*cscript*" OR payload LIKE "*bitsadmin*"
     OR payload LIKE "*-enc*" OR payload LIKE "*frombase64*" OR payload LIKE "*http*" OR payload LIKE "*.hta*" OR payload LIKE "*cmd /c*"
| KEEP @timestamp, host.name, user.name, event.action, payload, process.parent.name
```

## Known false positives / exclusions
- Software updaters that register tasks in `Program Files`. The payload filter targets user-writable and script paths, excluding most. Exclude specific vendor tasks by name.

## Triage
- Read the task/service action, find the payload, remove it, and check for the same payload on other hosts (fleet sweep).

## Test
`schtasks /create /tn t /tr "powershell -w hidden -enc ..." /sc minute` on a lab host.
