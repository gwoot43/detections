---
id: I04
name: AS-REP roasting or Kerberos pre-authentication disabled
category: identity
status: todo
language: esql
index: logs-system.security*, logs-windows.forwarded*
mitre: [T1558.004, T1098]
data_source: Windows Security events 4768 and 4738 from domain controllers
suppression: none
---
## Why this is high fidelity
Two linked signals. An account being modified (4738) to set "do not require pre-authentication" is either the setup for AS-REP roasting or a legacy misconfiguration you want to know about immediately. And one source receiving RC4 tickets issued without pre-authentication (4768, pre-auth type 0) for more than one account is AS-REP roasting.

## Query
```esql
FROM logs-system.security*, logs-windows.forwarded* METADATA _id, _index, _version
| WHERE event.code == "4738"
// UserAccountControl lists only the flags that changed, as message codes (multi-valued).
// 2096 = "'Don't Require Preauth' - Enabled"; 2064 is the matching "Disabled".
| EVAL uac_changes = MV_CONCAT(TO_STRING(winlog.event_data.UserAccountControl), " "),
       target = TO_LOWER(winlog.event_data.TargetUserName),
       actor = TO_LOWER(winlog.event_data.SubjectUserName)
| WHERE uac_changes LIKE "*2096*"
| KEEP @timestamp, winlog.computer_name, target, actor, uac_changes, winlog.event_data.NewUacValue, _id, _version, _index
```
Companion roasting query:
```esql
FROM logs-system.security*, logs-windows.forwarded*
| WHERE event.code == "4768"
| EVAL preauth = TO_STRING(winlog.event_data.PreAuthType),
       status = TO_STRING(winlog.event_data.Status),
       enc = TO_LOWER(TO_STRING(winlog.event_data.TicketEncryptionType)),
       acct = TO_LOWER(winlog.event_data.TargetUserName)
| WHERE preauth == "0" AND status == "0x0" AND enc == "0x17"    // TGT issued without pre-auth, RC4 reply
  AND source.ip IS NOT NULL
| STATS accts = COUNT_DISTINCT(acct), targets = VALUES(acct)
    BY source.ip, BUCKET(@timestamp, 10 minutes)
| WHERE accts >= 2
```
A legitimate client uses its own no-preauth account. Two or more from one source in ten minutes is roasting. If you have no legitimate no-preauth accounts, alert on one.

## Suppression
None. Each pre-auth change weakens a separate account. The companion roasting query suppresses on `source.ip` for 1h.

## Known false positives / exclusions
- Genuine legacy accounts with pre-auth off. Inventory them once; any new one is the alert. They also appear in the companion query when one application server uses two of them; exclude that server's IP.

## Triage
- Re-enable pre-authentication on the account, rotate its password, and check who set the flag (actor in 4738).

## Test
Set "do not require Kerberos preauthentication" on a lab account.
