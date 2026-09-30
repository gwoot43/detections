---
id: CS02
name: Persistence written to Run keys, services or other ASEPs
category: crowdstrike-fdr
status: todo
severity: high
language: esql
index: logs-crowdstrike.fdr-*
mitre: [T1547.001, T1543.003, T1546]
data_source: CrowdStrike FDR AsepValueUpdate / registry events
---
## Why this is high fidelity
Falcon's `AsepValueUpdate` fires specifically for auto-start extensibility points, so it is pre-filtered to the registry locations attackers use for persistence. The signal sharpens when the value data points at a user-writable path, a script host, or an encoded command.

## Query
```esql
FROM logs-crowdstrike.fdr-* METADATA _id, _index, _version
| WHERE event.action IN ("AsepValueUpdate", "RegistryOperationDetectInfo") AND host.os.type == "windows"
| EVAL k = TO_LOWER(TO_STRING(COALESCE(registry.path, registry.key))),
       v = TO_LOWER(TO_STRING(COALESCE(registry.data.strings, registry.value)))
| WHERE (k LIKE "*currentversion\\run*" OR k LIKE "*currentversion\\runonce*" OR k LIKE "*\\services\\*"
        OR k LIKE "*winlogon*" OR k LIKE "*userinit*" OR k LIKE "*shell*" OR k LIKE "*image file execution options*"
        OR k LIKE "*currentversion\\policies\\explorer\\run*" OR k LIKE "*appinit_dlls*" OR k LIKE "*\\ctrl+*")
  AND (v LIKE "*\\temp\\*" OR v LIKE "*\\appdata\\*" OR v LIKE "*\\programdata\\*" OR v LIKE "*\\users\\public\\*" OR v LIKE "*\\downloads\\*"
        OR v LIKE "*powershell*" OR v LIKE "*mshta*" OR v LIKE "*rundll32*" OR v LIKE "*regsvr32*" OR v LIKE "*wscript*" OR v LIKE "*cscript*"
        OR v LIKE "*-enc*" OR v LIKE "*frombase64*" OR v LIKE "*http*" OR v LIKE "*cmd /c*" OR v LIKE "*.hta*")
| KEEP @timestamp, host.name, user.name, k, v, process.name, process.command_line
```
`image file execution options` with a `debugger` value is the accessibility-tool backdoor (sethc/utilman); keep it high.

## Known false positives / exclusions
- Software installers writing Run keys pointing at `Program Files`. The value filter targets user-writable and script paths, which excludes most. Exclude specific known-good vendor values by hash of the writing process.

## Triage
- Read the value data, find the referenced file, check whether it has run (ProcessRollup2 with that path), and remove the persistence.

## Test
Write a Run key on a lab host pointing at a PowerShell one-liner in `%TEMP%`.
