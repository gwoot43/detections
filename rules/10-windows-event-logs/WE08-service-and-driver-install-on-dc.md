---
id: WE08
name: New service or kernel driver installed on a domain controller or server
category: windows-events
status: todo
severity: high
language: esql
index: logs-windows.system-*, logs-windows.security-*
mitre: [T1543.003, T1569.002, T1068]
data_source: Windows System event 7045 (service installed) and Security event 4697
suppression:
  fields: [host.name, svc]
  duration: 24h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
Event 7045 records a new service. On domain controllers and Tier-0 servers, new services are rare and planned, and a service is how PsExec-class lateral movement and many drivers (including BYOVD) install. Scoping 7045/4697 to DCs and critical servers, and to services running from user-writable paths or with encoded commands, makes this precise.

## Query
```esql
FROM logs-windows.system-*, logs-windows.security-* METADATA _id, _index, _version
| WHERE event.code IN ("7045", "4697")
| EVAL svc = TO_LOWER(TO_STRING(COALESCE(winlog.event_data.ServiceName, ""))),
       img = TO_LOWER(TO_STRING(COALESCE(winlog.event_data.ImagePath, winlog.event_data.ServiceFileName, ""))),
       stype = TO_LOWER(TO_STRING(COALESCE(winlog.event_data.ServiceType, "")))
| WHERE
     img LIKE "*\\temp\\*" OR img LIKE "*\\users\\*" OR img LIKE "*\\programdata\\*" OR img LIKE "*\\appdata\\*" OR img LIKE "*\\perflogs\\*" OR img LIKE "*\\windows\\temp\\*"
  OR img LIKE "*powershell*" OR img LIKE "*cmd*/c*" OR img LIKE "*-enc*" OR img LIKE "*rundll32*" OR img LIKE "*mshta*" OR img LIKE "*\\admin$\\*"
  OR svc IN ("psexesvc", "paexec", "remcomsvc", "csexecsvc")
  OR stype LIKE "*kernel*"
  OR (host.name LIKE "dc*" OR host.name LIKE "*-dc*")   // any new service on a DC is worth review
| KEEP @timestamp, host.name, event.code, svc, img, stype, winlog.event_data.SubjectUserName
```
Split into two rules if the DC branch is too broad: one for DCs (any new service) and one fleet-wide (suspicious path/command or kernel driver only).

## Suppression
Suppress by `host.name`, `svc` for 24h. Alerts missing a key field are not suppressed. Events 7045 and 4697 both record the same install.

## Known false positives / exclusions
- Software installers and patch management creating services in `Program Files`. Excluded by the path focus. Vendor agents installing on servers; exclude by known service name and signed image path.

## Triage
- A service from a user-writable path is lateral movement or persistence. A kernel driver pairs with CS01 (BYOVD). Investigate the source and remove the service.

## Test
Install a benign service pointing at a binary in `%TEMP%` on a lab host.
