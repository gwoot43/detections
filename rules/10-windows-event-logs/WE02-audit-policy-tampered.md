---
id: WE02
name: Audit policy changed outside Group Policy processing
category: windows-events
status: todo
severity: high
language: esql
index: logs-windows.security-*
mitre: [T1562.002]
data_source: Windows Security events 4719, 4817, 4912
suppression:
  fields: [host.name, subject]
  duration: 1h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
Audit policy normally changes only when Group Policy applies, which is logged under the SYSTEM or machine account. A 4719 with a human or service account as subject means someone changed the local policy by hand, which removes the logging the rest of this library depends on.

## Query
```esql
FROM logs-windows.security-* METADATA _id, _index, _version
| WHERE event.code IN ("4719", "4817", "4912")
| EVAL subject = TO_LOWER(COALESCE(winlog.event_data.SubjectUserName, ""))
| WHERE subject != "system" AND subject != "" AND NOT (subject LIKE "*$")
| KEEP @timestamp, host.name, event.code, subject, winlog.event_data.SubcategoryGuid, winlog.event_data.AuditPolicyChanges, message
```

## Suppression
Suppress by `host.name`, `subject` for 1h. Alerts missing a key field are not suppressed. Event 4719 is written once per subcategory changed.

## Known false positives / exclusions
- Security engineers deliberately raising audit levels during a rollout. Ticket-gated; keep visible.

## Triage
- Read `AuditPolicyChanges` for what was disabled. Re-apply the policy immediately (gpupdate) and investigate the actor.

## Test
Change a logon audit subcategory to disabled on a lab host, then revert.
