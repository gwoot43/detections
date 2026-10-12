---
id: WE12
name: New-credentials logon consistent with pass-the-hash
category: windows-events
status: todo
severity: high
language: esql
index: logs-system.security*, logs-windows.forwarded*
mitre: [T1550.002]
data_source: Windows Security event 4624
suppression:
  fields: [host_key, outbound]
  duration: 1h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
A 4624 with logon type 9 (new credentials), logon process `seclogo` and package `Negotiate` is the logon shape that credential-reuse tooling produces on the host where it runs. The only common legitimate source is `runas /netonly`, which admins use from a small set of jump hosts you can exclude.

## Query
```esql
FROM logs-system.security*, logs-windows.forwarded* METADATA _id, _index, _version
| WHERE event.code == "4624"
| EVAL lt = TO_STRING(winlog.event_data.LogonType),
       lp = TO_LOWER(TRIM(TO_STRING(winlog.event_data.LogonProcessName))),
       ap = TO_LOWER(TO_STRING(winlog.event_data.AuthenticationPackageName)),
       outbound = TO_LOWER(COALESCE(winlog.event_data.TargetOutboundUserName, "")),
       acct = TO_LOWER(winlog.event_data.TargetUserName),
       host_key = TO_LOWER(MV_FIRST(SPLIT(winlog.computer_name, ".")))   // with event forwarding, host.name is the collector
| WHERE lt == "9" AND lp == "seclogo" AND ap == "negotiate"
| WHERE host_key NOT IN ("jump01", "paw-01")     // admin jump hosts where runas /netonly is expected
| KEEP @timestamp, host_key, winlog.computer_name, acct, outbound, winlog.event_data.TargetOutboundDomainName, lt, lp, ap, _id, _version, _index
```
`TargetOutboundUserName` and `TargetOutboundDomainName` are not in the integration's predefined fields. Every 4624 from Windows 10 / Server 2016 or later carries them, so they are mapped on any current fleet.

## Suppression
Suppress by `host_key`, `outbound` for 1h. Alerts missing a key field are not suppressed. One session produces several of these logons; a different impersonated account still alerts.

## Known false positives / exclusions
- `runas /netonly` by admins, excluded by jump host. Some management tools use the same logon type; exclude them by host after review.

## Triage
- The outbound account is the one being used. Check where that account authenticates next (4624 type 3 on other hosts) and whether the host shows credential access (W01).

## Test
Atomic Red Team T1550.002 on a lab host.
