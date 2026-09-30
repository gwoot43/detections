---
id: I13
name: Service principal name added to a user account (targeted Kerberoasting setup)
category: identity
status: todo
severity: high
language: esql
index: logs-windows.security-*
mitre: [T1558.003, T1098]
data_source: Windows Security event 5136 from domain controllers
suppression:
  fields: [op_id]
  duration: 1h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
An attacker with write access to a user can give it an SPN, request its service ticket and crack the password offline. SPNs on user objects change only when a service account is set up, a planned task for a few owners. Computer accounts and managed service accounts change SPNs routinely and are excluded by object class.

## Query
```esql
FROM logs-windows.security-* METADATA _id, _index, _version
| WHERE event.code == "5136"
| EVAL attr = TO_LOWER(TO_STRING(winlog.event_data.AttributeLDAPDisplayName)),
       cls = TO_LOWER(TO_STRING(winlog.event_data.ObjectClass)),
       dn = TO_LOWER(TO_STRING(winlog.event_data.ObjectDN)),
       actor = TO_LOWER(COALESCE(winlog.event_data.SubjectUserName, "")),
       optype = TO_LOWER(TO_STRING(winlog.event_data.OperationType)),
       op_id = TO_STRING(winlog.event_data.OpCorrelationID)
| WHERE attr == "serviceprincipalname" AND cls == "user"
  AND optype IN ("%%14674", "value added")
  AND NOT (actor IN ("svc-identity-provisioning"))    // your service-account provisioning tooling, if any
| KEEP @timestamp, host.name, actor, dn, op_id, winlog.event_data.AttributeValue
```

## Suppression
Suppress by `op_id` for 1h. Alerts missing a key field are not suppressed. Several SPNs added in one operation share the operation ID; a second target account always alerts.

## Known false positives / exclusions
- Planned service account creation. Confirm against change control; prefer group managed service accounts, which do not match this rule.

## Triage
- Remove the SPN if not planned. Check 4769 for service ticket requests for that account after the change (I03); if present, rotate the account's password to a long random value.

## Test
Add a test SPN to a lab user account, then remove it.
