---
id: C03
name: Privileged Entra role assigned or PIM-activated
category: cloud
status: todo
severity: high
language: esql
index: logs-azure.auditlogs-*
mitre: [T1098.003, T1078.004]
data_source: Entra ID audit logs
suppression:
  fields: [azure.auditlogs.properties.target_resources.0.user_principal_name, role]
  duration: 8h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
Global Administrator, Privileged Role Administrator, Privileged Authentication Administrator, Security Administrator and Exchange Administrator are the roles that let an attacker own the tenant. Assignments should be rare, and PIM activations should follow a shift pattern you can baseline.

The rule reads the Core Directory records only. Every path (direct assignment, PIM eligibility, PIM activation) writes one of them with the same shape: the member in the first target and the role name in its modified properties. PIM's own "... in PIM completed" records describe the same change a second time, so they are left out.

## Query
```esql
FROM logs-azure.auditlogs-* METADATA _id, _index, _version
| WHERE azure.auditlogs.properties.category == "RoleManagement"
  AND azure.auditlogs.operation_name IN ("Add member to role", "Add eligible member to role")
  // the integration moves properties.result into event.outcome, so filter on that
  AND event.outcome == "success"
// Role.DisplayName is one of the first modified properties of the member; its position varies.
// Values arrive JSON-quoted ("Global Administrator"), so quotes become delimiters for an exact match.
| EVAL props = REPLACE(TO_LOWER(CONCAT(
         COALESCE(`azure.auditlogs.properties.target_resources.0.modified_properties.0.new_value`, ""), "|",
         COALESCE(`azure.auditlogs.properties.target_resources.0.modified_properties.1.new_value`, ""), "|",
         COALESCE(`azure.auditlogs.properties.target_resources.0.modified_properties.2.new_value`, ""), "|",
         COALESCE(`azure.auditlogs.properties.target_resources.0.modified_properties.3.new_value`, ""))), "\"", "|")
| EVAL role = CASE(
    props LIKE "*|global administrator|*",                    "Global Administrator",
    props LIKE "*|privileged role administrator|*",           "Privileged Role Administrator",
    props LIKE "*|privileged authentication administrator|*", "Privileged Authentication Administrator",
    props LIKE "*|security administrator|*",                  "Security Administrator",
    props LIKE "*|exchange administrator|*",                  "Exchange Administrator",
    props LIKE "*|conditional access administrator|*",        "Conditional Access Administrator",
    props LIKE "*|application administrator|*",               "Application Administrator",
    props LIKE "*|cloud application administrator|*",         "Cloud Application Administrator",
    props LIKE "*|intune administrator|*",                    "Intune Administrator",
    props LIKE "*|authentication administrator|*",            "Authentication Administrator",
    props LIKE "*|hybrid identity administrator|*",           "Hybrid Identity Administrator",
    props LIKE "*|partner tier2 support|*",                   "Partner Tier2 Support",
    NULL)
| WHERE role IS NOT NULL
| KEEP @timestamp, azure.auditlogs.operation_name, role,
       azure.auditlogs.properties.initiated_by.user.userPrincipalName, azure.auditlogs.properties.initiated_by.app.displayName,
       `azure.auditlogs.properties.target_resources.0.user_principal_name`, source.ip
```
A PIM activation is initiated by the `MS-PIM` service principal, so `initiated_by.user` is empty and the member is the person who activated.

## Suppression
Suppress by `azure.auditlogs.properties.target_resources.0.user_principal_name`, `role` for 8h. Alerts missing a key field are not suppressed. PIM activations by on-call staff repeat through a shift. A different person or role still alerts. Role grants to a service principal have no UPN, so each one alerts on its own.

## Known false positives / exclusions
- PIM activations by the on-call identity team. Suppression on member and role covers the shift; do not allowlist.
- Break-glass accounts should never activate. If they do, that is the highest-priority version of this alert.

## Triage
- Who assigned (user, or `MS-PIM` for an activation), who received, active or eligible, from which IP and session.
- Correlate with C02 and C04 in the same hour: role add followed by policy change or credential add is an attack chain.

## Test
PIM-activate a low-impact role in the test tenant, or add a test user as eligible for Security Reader and confirm it does not fire, then Security Administrator and confirm it does.
