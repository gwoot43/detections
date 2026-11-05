---
id: S25
name: Permanent privileged Entra role assignment, outside PIM
category: entra-signin-extended
status: todo
language: esql
index: logs-azure.auditlogs-*
mitre: [T1098.003, T1078.004]
data_source: Entra ID audit log (role management)
suppression:
  fields: [user.name]
  duration: 24h
  missing_fields: do_not_suppress
---

## Why this is high fidelity

Entra writes two different events for the same visible outcome. A **PIM activation** is temporary, expires, and is
logged as `Add member to role completed (PIM activation)`. A **permanent assignment** is
`Add member to role.` - it does not expire, it survives the session, and it is what an attacker holding
`Privileged Role Administrator` (or a compromised Global Administrator) creates first.

The audit log distinguishes them by operation name, so the rule is precise without a threshold: filter to the
permanent operations and to privileged roles, and everything left is a deliberate act by someone who could already
do it. That is a short list per month in any estate, and each entry has a name attached.

## Query

```esql
FROM logs-azure.auditlogs-*
| WHERE @timestamp >= NOW() - 24 hours
  AND azure.auditlogs.operation_name IN ("Add member to role.", "Add member to role outside PIM.")
| EVAL actor = TO_LOWER(COALESCE(TO_STRING(azure.auditlogs.properties.initiated_by.user.userPrincipalName), "")),
       target = TO_LOWER(COALESCE(TO_STRING(MV_FIRST(azure.auditlogs.properties.target_resources.user_principal_name)), "")),
       // leading wildcard on purpose: the role name sits inside a modified-properties array, not at its start
       role = TO_LOWER(COALESCE(TO_STRING(MV_FIRST(azure.auditlogs.properties.modified_properties.new_value)), "")),
       result = TO_LOWER(COALESCE(TO_STRING(azure.auditlogs.result), ""))
| WHERE role LIKE "*global administrator*" OR role LIKE "*privileged role administrator*"
     OR role LIKE "*privileged authentication administrator*" OR role LIKE "*conditional access administrator*"
     OR role LIKE "*application administrator*" OR role LIKE "*cloud application administrator*"
     OR role LIKE "*hybrid identity administrator*" OR role LIKE "*security administrator*"
     OR role LIKE "*exchange administrator*" OR role LIKE "*sharepoint administrator*"
| STATS assignments = COUNT(*), roles = MV_SLICE(VALUES(role), 0, 5),
        first_seen = MIN(@timestamp), last_seen = MAX(@timestamp),
        results = MV_SLICE(VALUES(result), 0, 3)
    BY actor, target
| SORT first_seen DESC
| LIMIT 50
```

## Reading the alert

- **`actor == target`** - someone granted themselves a privileged role. That is never routine; even a break-glass
  procedure has a second person.
- **`actor` is a service principal or a first-party app** - automation should not be adding Global Administrators.
  `S04` covers non-admin first-party CLI use; this is the write that follows it.
- **A new `actor`** - an account that has never assigned a role before. Worth joining against the 90-day history of
  the same operation rather than against a hard-coded admin list.

## Nearest benign twins

- **PIM activation** - excluded by operation name. If your tenant logs activations as `Add member to role.` as
  well, add `AND NOT ... LIKE "*PIM activation*"` on the operation's description before enabling.
- **Onboarding a new admin** - change-ticketed, performed by a named person, and the target is a new starter.
- **Break-glass account rotation** - rare, documented, and always the same two accounts.

## What it misses

- **Eligible (not permanent) assignments** - `Add eligible member to role.` is a different operation and a weaker
  signal; it only matters when combined with an activation, which is the PIM path.
- **Role changes made through the Graph API by an app** - the actor is a service principal, so the `actor` field
  is a GUID rather than a UPN. The rule still fires, but triage needs the app's display name.
- **Directory role changes in a different tenant** - one rule per tenant.

## Baseline

```esql
FROM logs-azure.auditlogs-*
| WHERE @timestamp >= NOW() - 90 days
  AND azure.auditlogs.operation_name IN ("Add member to role.", "Add member to role outside PIM.")
| EVAL actor = TO_LOWER(COALESCE(TO_STRING(azure.auditlogs.properties.initiated_by.user.userPrincipalName), ""))
| STATS assignments = COUNT(*), days = COUNT_DISTINCT(BUCKET(@timestamp, 1 day))
    BY actor
| SORT assignments DESC
| LIMIT 100
```

The people who assign roles permanently in your tenant are a very short list. Everything outside it is the case.

## Test

```esql
FROM logs-azure.auditlogs-*
| WHERE @timestamp >= NOW() - 7 days
| STATS events = COUNT(*) BY azure.auditlogs.operation_name
| SORT events DESC
| LIMIT 30
```

Confirm `Add member to role.` and the role name field are both present before enabling - field names for the audit
log differ between the Elastic Azure integration and a custom pipeline.
