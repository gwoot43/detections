---
id: I04
name: AS-REP roasting or Kerberos pre-authentication disabled
category: identity
status: todo
severity: high
language: esql
index: logs-windows.security-*
mitre: [T1558.004, T1098]
data_source: Windows Security events 4768 and 4738 from domain controllers
---
## Why this is high fidelity
Two linked signals. A burst of AS-REQ (4768) responses with RC4 for accounts that have pre-auth disabled is AS-REP roasting. And an account being modified (4738) to set "do not require pre-authentication" is either the setup for that attack or a legacy misconfiguration you want to know about immediately.

## Query
```esql
FROM logs-windows.security-* METADATA _id, _index, _version
| WHERE event.code == "4738"
| EVAL flags = TO_LOWER(TO_STRING(winlog.event_data.UserAccountControl)),
       target = TO_LOWER(winlog.event_data.TargetUserName),
       actor = TO_LOWER(winlog.event_data.SubjectUserName)
// 0x400000 = DONT_REQ_PREAUTH; the 4738 message renders it as a named flag
| WHERE flags LIKE "*don't require preauth*" OR flags LIKE "*dont_req_preauth*" OR flags LIKE "*0x400000*"
| KEEP @timestamp, host.name, target, actor, flags
```
Companion roasting-burst query:
```esql
FROM logs-windows.security-* METADATA _id, _index, _version
| WHERE event.code == "4768" AND TO_LOWER(TO_STRING(winlog.event_data.TicketEncryptionType)) IN ("0x17", "23")
| STATS accts = COUNT_DISTINCT(winlog.event_data.TargetUserName), src = VALUES(source.ip)
    BY source.ip, BUCKET(@timestamp, 10 minutes)
| WHERE accts >= 8
```

## Known false positives / exclusions
- Genuine legacy accounts with pre-auth off. Inventory them once; any new one is the alert.

## Triage
- Re-enable pre-authentication on the account, rotate its password, and check who set the flag (actor in 4738).

## Test
Set "do not require Kerberos preauthentication" on a lab account.
