---
id: WE01
name: Security or System event log cleared
category: windows-events
status: todo
severity: critical
language: esql
index: logs-system.security*, logs-windows.forwarded*, logs-system.system-*
mitre: [T1070.001]
data_source: Windows Security event 1102, System event 104
suppression:
  fields: [host_key]
  duration: 1h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
Event 1102 is written only when someone clears the Security log; 104 is the same for other logs. There is no automated process that does this on a healthy domain. The event records who did it, and Elastic already holds the copy they were trying to destroy.

## Query
```esql
FROM logs-system.security*, logs-windows.forwarded*, logs-system.system-* METADATA _id, _index, _version
| WHERE (event.code == "1102" AND winlog.channel == "Security")
     OR (event.code == "104" AND winlog.provider_name == "Microsoft-Windows-Eventlog")
// both events carry the actor in user_data (LogFileCleared), not event_data; 104 also names the cleared log
| EVAL host_key = TO_LOWER(MV_FIRST(SPLIT(winlog.computer_name, "."))),
       actor = TO_LOWER(COALESCE(winlog.user_data.SubjectUserName, user.name, "")),
       cleared_log = COALESCE(winlog.user_data.Channel, winlog.channel)
| KEEP @timestamp, host_key, winlog.computer_name, event.code, actor, winlog.user_data.SubjectDomainName, cleared_log
```
`METADATA _id, _index, _version` is required plumbing for the detection engine, not detection logic. See docs/ESQL-CONVENTIONS.md. Hosts are keyed on `winlog.computer_name`, because with event forwarding `host.name` is the collector.

## Suppression
Suppress by `host_key` for 1h. Alerts missing a key field are not suppressed. Clearing several logs at once writes one event per log.

## Known false positives / exclusions
- Build and imaging pipelines (MDT, Autopilot, SCCM task sequences) that clear logs before sysprep. Log-clear volume is tiny, so prefer reading the alert over a filter. Only on a sealed build network you control, exclude the build hosts inline, for example `| WHERE NOT (host_key LIKE "img-*")`, because a host name is something an attacker can influence.

## Triage
- Everything the actor did before the clear is still in Elastic. Rebuild the timeline for that host and user for the previous 24 hours, and treat the host as compromised.

## Test
`wevtutil cl Application` on a lab host produces a 104; clearing Security produces 1102.
