---
id: WE12
name: New-credentials logon consistent with pass-the-hash
category: windows-events
status: todo
severity: high
language: esql
index: logs-windows.security-*
mitre: [T1550.002]
data_source: Windows Security event 4624
suppression:
  fields: [host.name, outbound]
  duration: 1h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
A 4624 with logon type 9 (new credentials), logon process `seclogo` and package `Negotiate` is the logon shape that credential-reuse tooling produces on the host where it runs. The only common legitimate source is `runas /netonly`, which admins use from a small set of jump hosts you can exclude.

## Query
```esql
FROM logs-windows.security-* METADATA _id, _index, _version
| WHERE event.code == "4624"
| EVAL lt = TO_STRING(winlog.event_data.LogonType),
       lp = TO_LOWER(TRIM(TO_STRING(winlog.event_data.LogonProcessName))),
       ap = TO_LOWER(TO_STRING(winlog.event_data.AuthenticationPackageName)),
       outbound = TO_LOWER(COALESCE(winlog.event_data.TargetOutboundUserName, "")),
       acct = TO_LOWER(winlog.event_data.TargetUserName)
| WHERE lt == "9" AND lp == "seclogo" AND ap == "negotiate"
| WHERE NOT (TO_LOWER(host.name) IN ("jump01", "paw-01"))     // admin jump hosts where runas /netonly is expected
| KEEP @timestamp, host.name, acct, outbound, winlog.event_data.TargetOutboundDomainName, lt, lp, ap
```

## Suppression
Suppress by `host.name`, `outbound` for 1h. Alerts missing a key field are not suppressed. One session produces several of these logons; a different impersonated account still alerts.

## Known false positives / exclusions
- `runas /netonly` by admins, excluded by jump host. Some management tools use the same logon type; exclude them by host after review.

## Triage
- The outbound account is the one being used. Check where that account authenticates next (4624 type 3 on other hosts) and whether the host shows credential access (W01).

## Test
Atomic Red Team T1550.002 on a lab host.
