---
id: I11
name: AdminSDHolder object modified
category: identity
status: todo
language: esql
index: logs-system.security*, logs-windows.forwarded*
mitre: [T1098, T1078.002]
data_source: Windows Security event 5136 (directory object modified) from domain controllers
suppression:
  fields: [op_id]
  duration: 1h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
The permissions on the AdminSDHolder object are copied onto every protected account (Domain Admins, Enterprise Admins, Administrators and the other protected groups) roughly hourly by the SDProp process. An entry added here grants rights over every admin account, and it returns even after removal from an individual account. The object is essentially never changed after the domain is built.

## Query
```esql
FROM logs-system.security*, logs-windows.forwarded* METADATA _id, _index, _version
| WHERE event.code == "5136"
| EVAL dn = TO_LOWER(TO_STRING(winlog.event_data.ObjectDN)),
       attr = TO_LOWER(TO_STRING(winlog.event_data.AttributeLDAPDisplayName)),
       actor = TO_LOWER(COALESCE(winlog.event_data.SubjectUserName, "")),
       optype = TO_LOWER(TO_STRING(winlog.event_data.OperationType)),
       op_id = TO_STRING(winlog.event_data.OpCorrelationID)
| WHERE dn LIKE "cn=adminsdholder,cn=system,*"
  AND optype IN ("%%14674", "value added")         // the new value; the paired "value deleted" event repeats the old one
| KEEP @timestamp, winlog.computer_name, actor, dn, attr, op_id, winlog.event_data.AttributeValue, _id, _version, _index
```
Requires directory-object auditing with a SACL covering the System container. Confirm 5136 events appear for a test change before relying on this.

## Suppression
Suppress by `op_id` for 1h. Alerts missing a key field are not suppressed. The query keeps only the value-added half of each change; suppression folds any repeats in the same operation, and a separate change always alerts.

## Known false positives / exclusions
- Deliberate hardening by the AD team, for example removing a stale entry. Ticket-gated, never excluded.

## Triage
- Read the added access control entry in `AttributeValue`, identify the trustee, remove it, then check every protected account for the same entry because SDProp may already have copied it.
- Treat the actor as compromised and review their other directory changes (I02, WE03, WE06).

## Test
Add a harmless read permission for a test account on AdminSDHolder in a lab domain, confirm the alert, then remove it.
