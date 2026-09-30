---
id: I06
name: Privileged account interactive logon to a workstation or unusual host
category: identity
status: todo
severity: high
language: esql
index: logs-windows.security-*
mitre: [T1078.002, T1021]
data_source: Windows Security event 4624
---
## Why this is high fidelity
Tier-0 accounts should log on only to domain controllers and privileged access workstations. A Domain Admin logging on interactively (type 2, 10 RDP, or with credentials cached type 11) to an ordinary workstation is either a tiering violation or stolen credentials in use. Both need action.

## Query
```esql
FROM logs-windows.security-* METADATA _id, _index, _version
| WHERE event.code == "4624"
| EVAL acct = TO_LOWER(winlog.event_data.TargetUserName),
       logon_type = TO_STRING(winlog.event_data.LogonType),
       dest = TO_LOWER(host.name)
// your Tier-0 account naming convention, e.g. adm-, da-, _admin; adjust to reality
| WHERE (acct LIKE "adm-*" OR acct LIKE "da-*" OR acct LIKE "*-admin" OR acct LIKE "svc-tier0*" OR acct IN ("administrator"))
  AND logon_type IN ("2", "10", "11")
// exclude the sanctioned Tier-0 hosts: DCs and PAWs
| WHERE NOT (dest LIKE "dc*" OR dest LIKE "*-dc*" OR dest LIKE "paw-*" OR dest LIKE "adminws-*")
| KEEP @timestamp, dest, acct, logon_type, source.ip, winlog.event_data.WorkstationName, winlog.event_data.IpAddress
```
Replace the naming conventions with your own. If you maintain a Tier-0 account group, resolve membership into a lookup and match on that instead of name patterns.

## Known false positives / exclusions
- A break-glass account used during an incident, on the incident host. Expect it and document it.
- New PAWs not yet in the naming pattern. Fix the pattern.

## Triage
- Contact the account owner. If unexpected, isolate the destination host (credential exposure) and rotate the account.

## Test
Log on interactively with a lab Tier-0 account to a lab workstation.
