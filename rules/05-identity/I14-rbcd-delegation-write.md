---
id: I14
name: Resource-based constrained delegation configured on a computer object
category: identity
status: todo
severity: high
language: esql
index: logs-windows.security-*
mitre: [T1134.001, T1098]
data_source: Windows Security event 5136 from domain controllers
suppression:
  fields: [op_id]
  duration: 1h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
Writing `msDS-AllowedToActOnBehalfOfOtherIdentity` on a computer lets the listed account request tickets to that computer as any user, which is effectively local admin on it. It is a common escalation step after gaining write access to a computer object, and it is rarely set in normal operations.

## Query
```esql
FROM logs-windows.security-* METADATA _id, _index, _version
| WHERE event.code == "5136"
| EVAL attr = TO_LOWER(TO_STRING(winlog.event_data.AttributeLDAPDisplayName)),
       dn = TO_LOWER(TO_STRING(winlog.event_data.ObjectDN)),
       actor = TO_LOWER(COALESCE(winlog.event_data.SubjectUserName, "")),
       optype = TO_LOWER(TO_STRING(winlog.event_data.OperationType)),
       op_id = TO_STRING(winlog.event_data.OpCorrelationID)
| WHERE attr == "msds-allowedtoactonbehalfofotheridentity"
  AND optype IN ("%%14674", "value added")
| WHERE NOT (actor IN ("svc-cluster", "svc-scvmm"))    // clustering / virtualization tooling that sets RBCD legitimately
| KEEP @timestamp, host.name, actor, dn, op_id, winlog.event_data.AttributeValue
```

## Suppression
Suppress by `op_id` for 1h. Alerts missing a key field are not suppressed. Paired events share the operation ID; a different target computer always alerts.

## Known false positives / exclusions
- Failover clustering and virtualization management set this attribute legitimately. Exclude those service accounts after review.

## Triage
- Clear the attribute on the target computer, identify the account that was granted delegation, and treat it as attacker-controlled. Investigate how the actor gained write access to the computer object.

## Test
Configure RBCD on a lab computer with an approved tool, then clear it.
