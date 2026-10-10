---
id: AD04
name: Domain DPAPI backup key retrieved from a domain controller
category: ad-attack
status: todo
severity: critical
rank: 4
language: esql
index: logs-windows.security-*
mitre: [T1555, T1003]
data_source: Windows Security event 4662 on domain controllers
suppression:
  fields: [host.name, actor]
  duration: 6h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
The domain DPAPI backup key, stored as an LSA secret on every domain controller, can decrypt every domain user's DPAPI-protected secrets: saved browser passwords, credential manager entries, certificates' private keys. It never rotates, so theft gives permanent access to all of them. Reading the secret directly is never part of normal operations. Domain members back up their keys through a protocol handled inside LSA, which does not open the secret object.

## Prerequisite
4662 for LSA secret objects must be audited on DCs. Confirm the event appears in a lab before relying on this.

## Query
```esql
FROM logs-windows.security-* METADATA _id, _index, _version
| WHERE event.code == "4662"
| EVAL otype = TO_LOWER(TO_STRING(winlog.event_data.ObjectType)),
       oname = TO_LOWER(TO_STRING(winlog.event_data.ObjectName)),
       mask = TO_LOWER(TO_STRING(winlog.event_data.AccessMask)),
       actor = TO_LOWER(COALESCE(winlog.event_data.SubjectUserName, ""))
| WHERE otype == "secretobject" AND oname LIKE "*bckupkey*" AND mask == "0x2"
| KEEP @timestamp, host.name, actor, winlog.event_data.SubjectDomainName, oname, mask
```

## Suppression
Suppress by `host.name`, `actor` for 6h. Alerts missing a key field are not suppressed. One retrieval reads more than one secret; a different actor or DC still alerts.

## Known false positives / exclusions
- None expected in normal operation. A DPAPI backup key rotation or recovery exercise by the identity team is the only planned cause.

## Triage
- Treat as domain-wide credential compromise. Identify the actor's source host, isolate it, and assume all DPAPI-protected secrets for domain users are exposed: rotate saved credentials for privileged and service accounts first.
- Rotating the backup key itself does not protect secrets already protected with the old key; plan with that in mind.

## Test
Validate in a lab by retrieving the backup key with an approved tool and confirming the 4662 event.
