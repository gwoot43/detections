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
suppression:
  fields: [host.name]
  duration: 1h
  missing_fields: do_not_suppress
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
`METADATA _id, _index, _version` is required plumbing for the detection engine, not detection logic. See docs/ESQL-CONVENTIONS.md.

## Suppressing the imaging / sysprep false positive
The one benign cause is a build/imaging pipeline clearing logs (a cleanup step such as `wevtutil cl security`, usually alongside but not by sysprep.exe itself). ES|QL has no SQL-style subqueries; correlate with `LOOKUP JOIN` or `ENRICH` (both join on a key, not a time window). See docs/ESQL-CONVENTIONS.md for how these commands and their prerequisites work.

Prefer enriching for analyst context over a hard filter: `host.name` and a process name are attacker-influenceable, and log-clear volume is tiny, so a one-line "likely imaging" tag beats a silent drop. Reserve a hard filter for sealed build networks you control.

### Option A - LOOKUP JOIN against a maintained imaging-host list (Elastic 9.x GA; tech preview in late 8.x)
Keep an index in `lookup` index mode, e.g. `imaging_hosts`, with `host.name` and `build_state`, populated by your provisioning pipeline (MDT / Autopilot / SCCM task sequence).
```esql
FROM logs-windows.security-*, logs-system.system-* METADATA _id, _index, _version
| WHERE (event.code == "1102" AND winlog.channel == "Security")
     OR (event.code == "104" AND winlog.provider_name == "Microsoft-Windows-Eventlog")
| LOOKUP JOIN imaging_hosts ON host.name
// hard filter (sealed build network): drop hosts currently in a build window
| WHERE build_state IS NULL
// OR, preferred, keep the alert and tag it for the analyst instead of the WHERE above:
// | EVAL context = CASE(build_state IS NOT NULL, "likely imaging", "not an imaging host")
| KEEP @timestamp, host.name, event.code, winlog.event_data.SubjectUserName, build_state
```

### Option B - ENRICH (works on older versions; no LOOKUP JOIN needed)
Create and execute an enrich policy `imaging_policy` keyed on `host.name` over your imaging-host source index, then re-execute it on a schedule (the policy is a point-in-time snapshot).
```esql
FROM logs-windows.security-*, logs-system.system-* METADATA _id, _index, _version
| WHERE (event.code == "1102" AND winlog.channel == "Security")
     OR (event.code == "104" AND winlog.provider_name == "Microsoft-Windows-Eventlog")
| ENRICH imaging_policy ON host.name WITH build_state
| WHERE build_state IS NULL
// preferred alternative: | EVAL context = CASE(build_state IS NOT NULL, "likely imaging", "not an imaging host")
| KEEP @timestamp, host.name, event.code, winlog.event_data.SubjectUserName, build_state
```

For validating against actual sysprep.exe execution (CrowdStrike ProcessRollup2 or Windows 4688), materialise "recent sysprep by host" with an Elastic transform into a lookup index and join it the same way; ES|QL cannot do the time-windowed correlation inline. See docs/ESQL-CONVENTIONS.md.

## Suppression
Suppress by `host.name` for 1h. Alerts missing a key field are not suppressed. Clearing several logs at once writes one event per log.

## Known false positives / exclusions
- Log-management scripts on build images that clear logs before sysprep. Handle with Option A or B above.

## Triage
- Everything the actor did before the clear is still in Elastic. Rebuild the timeline for that host and user for the previous 24 hours, and treat the host as compromised.

## Test
`wevtutil cl Application` on a lab host produces a 104; clearing Security produces 1102.
