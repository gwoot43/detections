---
id: I12
name: Shadow credentials written to a user or computer (msDS-KeyCredentialLink)
category: identity
status: todo
severity: high
language: esql
index: logs-windows.security-*
mitre: [T1556, T1098]
data_source: Windows Security event 5136 from domain controllers
suppression:
  fields: [op_id]
  duration: 1h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
A key written to an account's `msDS-KeyCredentialLink` lets whoever holds the matching private key sign in as that account with a certificate, and it survives a password reset. Legitimately the attribute is written by Windows Hello for Business provisioning (through the directory sync account) and by a computer registering its own key. Other writers are rare.

## Query
```esql
FROM logs-windows.security-* METADATA _id, _index, _version
| WHERE event.code == "5136"
| EVAL attr = TO_LOWER(TO_STRING(winlog.event_data.AttributeLDAPDisplayName)),
       dn = TO_LOWER(TO_STRING(winlog.event_data.ObjectDN)),
       actor = TO_LOWER(COALESCE(winlog.event_data.SubjectUserName, "")),
       optype = TO_LOWER(TO_STRING(winlog.event_data.OperationType)),
       op_id = TO_STRING(winlog.event_data.OpCorrelationID)
| WHERE attr == "msds-keycredentiallink"
  AND optype IN ("%%14674", "value added")
  AND NOT (actor LIKE "msol_*")          // Windows Hello for Business key sync by the directory sync account
  AND NOT (actor LIKE "*$")              // a computer registering its own key (device registration)
| KEEP @timestamp, host.name, actor, dn, attr, op_id
```
Excluding all computer-account writers is a slight over-exclusion (it also drops a computer writing another object's key). Tighten later by comparing the actor name to the object DN in an ingest field if that precision matters.

Blind spot: in hybrid key-trust deployments, a Windows Hello key that an attacker enrolls in Entra ID is synced into `msDS-KeyCredentialLink` by the directory sync account, which this rule excludes. S16 and S17 catch that path on the cloud side.

## Suppression
Suppress by `op_id` for 1h. Alerts missing a key field are not suppressed. Paired events share the operation ID; each separate target always alerts.

## Known false positives / exclusions
- Windows Hello for Business in key-trust mode, excluded through the sync account. Identity-management products that manage device keys; exclude by service account after review.

## Triage
- Clear the unexpected value from the target, then check certificate-based logons (4768 with certificate information) for that account after the write time.
- Investigate how the actor gained write access (I14 and I11 are common precursors).

## Test
Use the Atomic Red Team shadow-credentials test against a lab account, then remove the key.
