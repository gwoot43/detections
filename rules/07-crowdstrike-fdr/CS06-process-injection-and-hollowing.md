---
id: CS06
name: Process injection, hollowing or suspicious remote thread
category: crowdstrike-fdr
status: todo
severity: high
language: esql
index: logs-crowdstrike.fdr-*
mitre: [T1055, T1055.012, T1620]
data_source: CrowdStrike FDR injection / thread-creation detect events
---
## Why this is high fidelity
Falcon emits dedicated telemetry for cross-process injection and suspicious remote thread creation. The high-fidelity slice is injection where the source is an unsigned or user-path binary and the target is a trusted process (explorer, svchost, a browser), which is classic hollowing and defense evasion.

## Query
```esql
FROM logs-crowdstrike.fdr-*
| WHERE event.action IN ("SuspiciousCreateThread", "CreateRemoteThread", "InjectedThread", "ProcessInjection", "ReflectiveDotnetModuleLoad")
| EVAL src = TO_LOWER(TO_STRING(COALESCE(process.executable, process.name))),
       tgt = TO_LOWER(TO_STRING(COALESCE(process.target.name, registry.value)))
| WHERE (src LIKE "*\\temp\\*" OR src LIKE "*\\appdata\\*" OR src LIKE "*\\programdata\\*" OR src LIKE "*\\users\\public\\*" OR src LIKE "*\\downloads\\*")
     OR tgt IN ("explorer.exe", "svchost.exe", "rundll32.exe", "notepad.exe", "werfault.exe", "dllhost.exe", "regsvr32.exe", "spoolsv.exe", "msbuild.exe")
| KEEP @timestamp, host.name, user.name, src, tgt, process.command_line
```
Event names vary by FDR schema version; run `STATS COUNT(*) BY event.action` filtered to injection-related actions and map the ones your feed produces.

## Known false positives / exclusions
- Legitimate software using injection (some AV, accessibility tools, screen recorders, EDR itself). Baseline and exclude by the signed source binary's hash.

## Triage
- Correlate with W01 (if the target is lsass), network callbacks and the source binary's origin. An unsigned source injecting into svchost is malware.

## Test
Atomic Red Team T1055.012 (process hollowing) on a lab host.
