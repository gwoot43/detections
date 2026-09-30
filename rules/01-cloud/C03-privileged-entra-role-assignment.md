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
---
## Why this is high fidelity
Global Administrator, Privileged Role Administrator, Privileged Authentication Administrator, Security Administrator and Exchange Administrator are the roles that let an attacker own the tenant. Assignments should be rare, and PIM activations should follow a shift pattern you can baseline.

## Query
```esql
FROM logs-azure.auditlogs-* METADATA _id, _index, _version
| WHERE azure.auditlogs.properties.category == "RoleManagement"
  AND azure.auditlogs.operation_name IN (
    "Add member to role",
    "Add eligible member to role",
    "Add member to role completed (PIM activation)",
    "Add member to role outside of PIM (permanent)",
    "Add member to role in PIM completed (permanent)"
  )
  AND azure.auditlogs.properties.result == "success"
// The role display name sits in target_resources[].modified_properties[].new_value. Position varies;
// copy it to a stable field (entra.role_name) in an ingest pipeline. Fallback: KQL rule, see note.
| EVAL role = TO_LOWER(TO_STRING(entra.role_name))
| WHERE role IN (
    "global administrator", "privileged role administrator", "privileged authentication administrator",
    "security administrator", "exchange administrator", "conditional access administrator",
    "application administrator", "cloud application administrator", "intune administrator",
    "authentication administrator", "hybrid identity administrator", "partner tier2 support"
  )
| KEEP @timestamp, azure.auditlogs.operation_name, role,
       azure.auditlogs.properties.initiated_by.user.userPrincipalName,
       azure.auditlogs.properties.target_resources.0.user_principal_name, source.ip
```

KQL fallback while the pipeline field is not there:
```
event.dataset:azure.auditlogs and azure.auditlogs.operation_name:("Add member to role" or "Add eligible member to role" or "Add member to role completed (PIM activation)")
and azure.auditlogs.properties.target_resources.*.modified_properties.*.new_value:("\"Global Administrator\"" or "\"Privileged Role Administrator\"" or "\"Security Administrator\"" or "\"Exchange Administrator\"")
```

## Known false positives / exclusions
- PIM activations by the on-call identity team. Suppress by (actor, role) for 8 hours after the first alert, do not allowlist.
- Break-glass accounts should never activate. If they do, that is the highest-priority version of this alert.

## Triage
- Who assigned, who received, permanent or eligible, from which IP and session.
- Correlate with C02 and C04 in the same hour: role add followed by policy change or credential add is an attack chain.

## Test
PIM-activate a low-impact role in the test tenant, or add a test user as eligible for Security Reader and confirm it does not fire, then Security Administrator and confirm it does.
