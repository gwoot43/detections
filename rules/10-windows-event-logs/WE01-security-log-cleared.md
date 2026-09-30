---
id: WE01
name: Security or System event log cleared
category: windows-events
status: todo
severity: critical
language: esql
index: logs-windows.security-*, logs-system.system-*
mitre: [T1070.001]
data_source: Windows Security event 1102, System event 104
---
## Why this is high fidelity
Event 1102 is written only when someone clears the Security log; 104 is the same for other logs. There is no automated process that does this on a healthy domain. The event records who did it, and Elastic already holds the copy they were trying to destroy.

## Query
```esql
FROM logs-windows.security-*, logs-system.system-* METADATA _id, _index, _version
| WHERE (event.code == "1102" AND winlog.channel == "Security")
     OR (event.code == "104" AND winlog.provider_name == "Microsoft-Windows-Eventlog")
| KEEP @timestamp, host.name, event.code, winlog.event_data.SubjectUserName, winlog.event_data.SubjectDomainName, winlog.event_data.Channel, winlog.channel
```

## Known false positives / exclusions
- Log-management scripts on build images that clear logs before sysprep. Exclude the imaging host list only.

## Triage
- Everything the actor did before the clear is still in Elastic. Rebuild the timeline for that host and user for the previous 24 hours, and treat the host as compromised.

## Test
`wevtutil cl Application` on a lab host produces a 104; clearing Security produces 1102.
