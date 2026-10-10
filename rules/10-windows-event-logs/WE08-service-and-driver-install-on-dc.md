---
id: WE08
name: New service or kernel driver installed on a domain controller or server
category: windows-events
status: todo
severity: high
language: esql
index: logs-system.system-*, logs-system.security*, logs-windows.forwarded*
mitre: [T1543.003, T1569.002, T1068]
data_source: Windows System event 7045 (service installed) and Security event 4697
suppression:
  fields: [host_key, svc]
  duration: 24h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
Event 7045 records a new service. On domain controllers, new services are rare and planned, and a service is how PsExec-class lateral movement and many drivers (including BYOVD) install. The rule alerts on any new service on a DC, and fleet-wide only on services that run from user-writable paths, run a shell or script host, or carry a known remote-execution service name. Kernel drivers from normal driver paths are left to CS01, because vendor software installs them constantly.

## Query
```esql
FROM logs-system.system-*, logs-system.security*, logs-windows.forwarded* METADATA _id, _index, _version
| WHERE event.code IN ("7045", "4697")
| EVAL svc = TO_LOWER(TO_STRING(COALESCE(winlog.event_data.ServiceName, ""))),
       img = TO_LOWER(TO_STRING(COALESCE(winlog.event_data.ImagePath, winlog.event_data.ServiceFileName, ""))),
       stype = TO_LOWER(TO_STRING(COALESCE(winlog.event_data.ServiceType, ""))),    // 7045: "kernel mode driver"; 4697: "0x1"
       host_key = TO_LOWER(MV_FIRST(SPLIT(winlog.computer_name, ".")))              // with event forwarding, host.name is the collector
| WHERE
     img LIKE """*\\temp\\*""" OR img LIKE """*\\users\\*""" OR img LIKE """*\\programdata\\*""" OR img LIKE """*\\appdata\\*""" OR img LIKE """*\\perflogs\\*"""
  OR img LIKE "*powershell*" OR img LIKE "*cmd.exe*/c*" OR img LIKE "*cmd /c*" OR img LIKE "*%comspec%*" OR img LIKE "*-enc*"
  OR img LIKE "*rundll32*" OR img LIKE "*mshta*" OR img LIKE """*\\admin$\\*"""
  OR svc IN ("psexesvc", "paexec", "remcomsvc", "csexecsvc")
  OR host_key LIKE "dc*" OR host_key LIKE "*-dc*"   // your DC naming: any new service on a DC is worth review
| KEEP @timestamp, host_key, winlog.computer_name, event.code, svc, img, stype, winlog.event_data.SubjectUserName, winlog.event_data.AccountName
```
`ImagePath` (7045) is not in the integration's predefined fields; it exists once a 7045 has been indexed, which happens within hours on any fleet. `%comspec%` is matched literally: `%` is not a wildcard in ES|QL `LIKE`.
Split into two rules if the DC branch is too broad: one for DCs (any new service) and one fleet-wide (suspicious path or command only).

## Suppression
Suppress by `host_key`, `svc` for 24h. Alerts missing a key field are not suppressed. Events 7045 and 4697 both record the same install.

## Known false positives / exclusions
- Software installers and patch management creating services in `Program Files`. Excluded by the path focus. Vendor agents installing on servers; exclude by known service name and signed image path.
- Some installers and updaters run a service from `ProgramData` (package caches, agent self-updaters). Exclude the exact service name after review.

## Triage
- A service from a user-writable path is lateral movement or persistence. A kernel driver on a DC pairs with CS01 (BYOVD). Investigate the source and remove the service.

## Test
Install a benign service pointing at a binary in `%TEMP%` on a lab host.
