---
id: I14
name: Delegation configured on an account (unconstrained, constrained, protocol transition or resource-based)
category: identity
status: todo
severity: high
language: esql
index: logs-system.security*, logs-windows.forwarded*
mitre: [T1134.001, T1098]
data_source: Windows Security event 5136 from domain controllers
suppression:
  fields: [op_id]
  duration: 1h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
Kerberos delegation lets an account act as other users toward services. Each form is an escalation path when configured on the wrong account, and all are rare, planned changes:
- **Resource-based** (`msDS-AllowedToActOnBehalfOfOtherIdentity` on a computer): the listed account can obtain tickets to that computer as any user, which is effectively local admin on it.
- **Constrained** (`msDS-AllowedToDelegateTo`): the account can impersonate users to the listed services.
- **Protocol transition** (`TRUSTED_TO_AUTH_FOR_DELEGATION` in `userAccountControl`): the account can do so without the user ever authenticating to it.
- **Unconstrained** (`TRUSTED_FOR_DELEGATION` in `userAccountControl`): the account receives users' TGTs. Any compromise of it exposes every user who connects, which is the payoff of coercion attacks (WE13). Domain controllers carry this flag by design and are excluded.

One rule covers all four, so this is the single delegation-configuration detection in the library.

## Query
```esql
FROM logs-system.security*, logs-windows.forwarded* METADATA _id, _index, _version
| WHERE event.code == "5136"
| EVAL attr = TO_LOWER(TO_STRING(winlog.event_data.AttributeLDAPDisplayName)),
       dn = TO_LOWER(TO_STRING(winlog.event_data.ObjectDN)),
       actor = TO_LOWER(COALESCE(winlog.event_data.SubjectUserName, "")),
       optype = TO_LOWER(TO_STRING(winlog.event_data.OperationType)),
       op_id = TO_STRING(winlog.event_data.OpCorrelationID),
       uac = CASE(attr == "useraccountcontrol", TO_LONG(winlog.event_data.AttributeValue), NULL)
| WHERE optype IN ("%%14674", "value added")
// userAccountControl bits: 524288 TRUSTED_FOR_DELEGATION, 16777216 TRUSTED_TO_AUTH_FOR_DELEGATION, 8192 SERVER_TRUST_ACCOUNT (a DC)
| EVAL resource_based = attr == "msds-allowedtoactonbehalfofotheridentity",
       constrained = attr == "msds-allowedtodelegateto",
       unconstrained = uac IS NOT NULL AND (uac / 524288) % 2 == 1 AND (uac / 8192) % 2 == 0,
       protocol_transition = uac IS NOT NULL AND (uac / 16777216) % 2 == 1
| WHERE resource_based OR constrained OR unconstrained OR protocol_transition
| WHERE NOT (actor IN ("svc-cluster", "svc-scvmm"))    // clustering / virtualization tooling that sets delegation legitimately
| EVAL delegation = CASE(resource_based, "resource_based", constrained, "constrained",
                         unconstrained, "unconstrained", "protocol_transition")
| KEEP @timestamp, winlog.computer_name, actor, dn, delegation, op_id, winlog.event_data.AttributeValue
```

## Suppression
Suppress by `op_id` for 1h. Alerts missing a key field are not suppressed. Paired events share the operation ID; a different target computer always alerts.

## Known false positives / exclusions
- Failover clustering and virtualization management set resource-based delegation legitimately. Exclude those service accounts after review.
- `userAccountControl` is logged as the whole new value, so any later change to an account that already has unconstrained delegation or protocol transition (disabling it, for example) also matches. Such accounts should be few; reducing them is the real fix.
- Service onboarding that configures constrained delegation. Confirm against change control.

## Triage
- Remove the delegation setting, identify the account that gained it, and treat that account as attacker-controlled. Investigate how the actor gained write access to the object (AD05 for a computer account created just before).
- For unconstrained delegation, check for coerced authentication from DCs toward that host (WE13): a DC's TGT on that host means domain compromise.

## Test
Configure each delegation type on a lab account, confirm the alert and its `delegation` value, then clear it.
