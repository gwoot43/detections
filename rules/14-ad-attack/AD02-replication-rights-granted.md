---
id: AD02
name: Directory replication (DCSync) rights granted on the domain root
category: ad-attack
status: todo
severity: critical
rank: 2
language: esql
index: logs-system.security*, logs-windows.forwarded*
mitre: [T1098, T1003.006]
data_source: Windows Security event 5136 from domain controllers
suppression:
  fields: [op_id]
  duration: 1h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
I01 catches DCSync being used. This catches the persistence step that makes it repeatable: an access control entry added to the domain root granting Get-Changes-All, the replication right that releases password hashes, to an ordinary domain principal. Once granted, that account can pull every password hash at will, and the grant survives password resets. Common tooling (ntlmrelayx `--escalate-user`, dacledit, bloodyAD) grants Get-Changes and Get-Changes-All only, so the rule does not wait for the third right.

The logged value is the whole new security descriptor, which already includes the default replication entries for domain controllers and administrators. Those use built-in aliases (`BA`, `DD`, `ED`), not raw domain SIDs. The rule removes the entries of accounts that legitimately hold the right, chiefly the Entra Connect sync account, then alerts if any Get-Changes-All entry for a raw domain SID (`S-1-5-21-...`) remains.

## Query
```esql
FROM logs-system.security*, logs-windows.forwarded* METADATA _id, _index, _version
| WHERE event.code == "5136"
| EVAL cls = TO_LOWER(TO_STRING(winlog.event_data.ObjectClass)),
       attr = TO_LOWER(TO_STRING(winlog.event_data.AttributeLDAPDisplayName)),
       optype = TO_LOWER(TO_STRING(winlog.event_data.OperationType)),
       // the .wildcard sub-field keeps descriptors longer than the keyword's 5120-character limit
       sd = TO_LOWER(COALESCE(winlog.event_data.AttributeValue.wildcard, winlog.event_data.AttributeValue)),
       actor = TO_LOWER(COALESCE(winlog.event_data.SubjectUserName, "")),
       op_id = TO_STRING(winlog.event_data.OpCorrelationID)
| WHERE attr == "ntsecuritydescriptor" AND cls == "domaindns"
  AND optype IN ("%%14674", "value added")         // the new descriptor; "value deleted" carries the old one
// drop the Get-Changes-All entries of accounts that should hold it: list your Entra Connect (MSOL_) account SID(s)
| EVAL sd_rest = REPLACE(sd, "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2;;(s-1-5-21-1111111111-2222222222-3333333333-1105)\\)", "")
| WHERE sd_rest LIKE "*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2;;s-1-5-21-*"     // DS-Replication-Get-Changes-All
| KEEP @timestamp, winlog.computer_name, actor, winlog.event_data.ObjectDN, op_id, sd
```
Replace the example SID with your sync account's SID (`Get-ADUser MSOL_xxxx`), and add others with `|` inside the parentheses. The closing `\\)` stops a SID from matching a longer one that starts with the same digits. Until you do, a hybrid domain alerts on every change to the domain root's permissions, which is rare but not never.

## Suppression
Suppress by `op_id` for 1h. Alerts missing a key field are not suppressed. A separate ACL change on the domain root always alerts.

## Known false positives / exclusions
- Identity products that legitimately need full replication rights (some password-sync and auditing tools). Remove the grant if it is not needed; otherwise add the trustee SID to the `REPLACE` list.
- The descriptor carries every entry, so any later permission change on the domain root alerts again while an unlisted grant remains. That is intended.

## Triage
- Find the `1131f6ad-...;;S-1-5-21-...` entry in `sd` and resolve that SID. Remove the replication entries for it, reset that account, and check I01 for DCSync activity by it.
- The actor had rights to change the domain root ACL; review how (I02, I11).

## Test
Grant replication rights to a test account on a lab domain and confirm the alert, then remove them.
