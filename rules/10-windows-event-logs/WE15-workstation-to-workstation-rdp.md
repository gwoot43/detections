---
id: WE15
name: RDP logon from one workstation to another
category: windows-events
status: todo
severity: medium
language: esql
index: logs-windows.security-*
mitre: [T1021.001]
data_source: Windows Security event 4624 (logon type 10)
suppression:
  fields: [source.ip, dest]
  duration: 4h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
Users RDP to servers and virtual desktops, not to each other's laptops. A remote-interactive logon where both ends are workstations is lateral movement or an unmanaged support habit worth stopping.

## Query
```esql
FROM logs-windows.security-* METADATA _id, _index, _version
| WHERE event.code == "4624" AND TO_STRING(winlog.event_data.LogonType) == "10"
| EVAL dest = TO_LOWER(host.name), acct = TO_LOWER(winlog.event_data.TargetUserName)
| WHERE CIDR_MATCH(source.ip, "10.20.0.0/16")          // workstation subnets
  AND (dest LIKE "ws-*" OR dest LIKE "lt-*")             // your workstation naming
| KEEP @timestamp, dest, acct, source.ip, winlog.event_data.WorkstationName
```

## Suppression
Suppress by `source.ip`, `dest` for 4h. Alerts missing a key field are not suppressed. RDP sessions reconnect.

## Known false positives / exclusions
- Help desk remote support. Put support staff in their own subnet and exclude it.

## Triage
- Confirm with the account owner. Check the source host for credential access and the destination for new persistence.

## Test
RDP between two lab workstations.
