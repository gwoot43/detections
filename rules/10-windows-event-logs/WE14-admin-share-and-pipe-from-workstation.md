---
id: WE14
name: Admin share or remote management pipe accessed from a workstation
category: windows-events
status: todo
severity: medium
language: esql
index: logs-windows.security-*
mitre: [T1021.002, T1569.002, T1053.005]
data_source: Windows Security events 5140 and 5145
suppression:
  fields: [source.ip, host.name]
  duration: 1h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
Remote administration reaches a host through `ADMIN$`, `C$`, or the service control, task scheduler and remote registry pipes. On a tiered network those connections come from jump hosts and management servers, not from user workstations. Restricting the source to workstation subnets leaves a small, suspicious set.

## Query
```esql
FROM logs-windows.security-* METADATA _id, _index, _version
| WHERE event.code IN ("5140", "5145")
| EVAL share = TO_LOWER(TO_STRING(winlog.event_data.ShareName)),
       rel = TO_LOWER(COALESCE(TO_STRING(winlog.event_data.RelativeTargetName), "")),
       acct = TO_LOWER(COALESCE(winlog.event_data.SubjectUserName, ""))
| WHERE share LIKE "*\\admin$" OR share LIKE "*\\c$"
     OR (share LIKE "*\\ipc$" AND rel IN ("svcctl", "atsvc", "winreg"))
| WHERE CIDR_MATCH(source.ip, "10.20.0.0/16")          // workstation subnets
  AND NOT (acct LIKE "*$")                              // machine accounts
| KEEP @timestamp, host.name, source.ip, acct, share, rel
```
Needs the "Detailed File Share" audit subcategory, which is high volume. Enable it on servers and domain controllers first.

## Suppression
Suppress by `source.ip`, `host.name` for 1h. Alerts missing a key field are not suppressed. One remote session writes many share events.

## Known false positives / exclusions
- IT support workstations. Move them to an admin subnet or exclude their IPs.

## Triage
- Map the source IP to a host and user, and check the destination for W08 activity at the same time.

## Test
From a lab workstation, open `\\labserver\c$` with an admin account.
