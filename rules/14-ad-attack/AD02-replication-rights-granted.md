---
id: AD02
name: Directory replication (DCSync) rights granted on the domain root
category: ad-attack
status: todo
severity: critical
rank: 2
language: esql
index: logs-windows.security-*
mitre: [T1098, T1003.006]
data_source: Windows Security event 5136 from domain controllers
suppression:
  fields: [op_id]
  duration: 1h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
I01 catches DCSync being used. This catches the persistence step that makes it repeatable: an access control entry added to the domain root granting the three replication rights (Get-Changes, Get-Changes-All and Get-Changes-In-Filtered-Set) to an ordinary domain principal. Once granted, that account can pull every password hash at will, and the grant survives password resets.

The logged value is the whole new security descriptor, which already includes the default replication entries for domain controllers and administrators. Those use built-in aliases, not raw domain SIDs. Requiring all three rights on a raw domain SID (`S-1-5-21-...`) keeps the default entries and the directory sync account, which normally holds only two of the three, from matching.

## Query
```esql
FROM logs-windows.security-* METADATA _id, _index, _version
| WHERE event.code == "5136"
| EVAL cls = TO_LOWER(TO_STRING(winlog.event_data.ObjectClass)),
       attr = TO_LOWER(TO_STRING(winlog.event_data.AttributeLDAPDisplayName)),
       sd = TO_LOWER(TO_STRING(winlog.event_data.AttributeValue)),
       actor = TO_LOWER(COALESCE(winlog.event_data.SubjectUserName, "")),
       op_id = TO_STRING(winlog.event_data.OpCorrelationID)
| WHERE attr == "ntsecuritydescriptor" AND cls == "domaindns"
  AND sd LIKE "*1131f6aa-9c07-11d1-f79f-00c04fc2dcd2;;s-1-5-21-*"
  AND sd LIKE "*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2;;s-1-5-21-*"
  AND sd LIKE "*89e95b76-444d-4c62-991a-0facbeda640c;;s-1-5-21-*"
| KEEP @timestamp, host.name, actor, winlog.event_data.ObjectDN, op_id, sd
```

## Suppression
Suppress by `op_id` for 1h. Alerts missing a key field are not suppressed. A separate ACL change on the domain root always alerts, and keeps alerting while the grant remains, which is intended.

## Known false positives / exclusions
- Identity products that legitimately need full replication rights (some password-sync and auditing tools). Remove the grant if it is not needed; otherwise note the SID and exclude it inline by matching the trustee SID in `sd`.

## Triage
- Extract the trustee SID from the replication entries in `sd` and resolve it. Remove the entries, reset that account, and check I01 for DCSync activity by it.
- The actor had rights to change the domain root ACL; review how (I02, I11).

## Test
Grant replication rights to a test account on a lab domain and confirm the alert, then remove them.
