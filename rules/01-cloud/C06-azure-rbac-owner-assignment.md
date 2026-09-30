---
id: C06
name: Azure RBAC Owner, User Access Administrator or Contributor assigned at subscription or management-group scope
category: cloud
status: todo
severity: high
language: esql
index: logs-azure.activitylogs-*
mitre: [T1098.003]
data_source: Azure Activity log
---
## Why this is high fidelity
Broad-scope role assignments are how an attacker turns one compromised identity into control of all resources. They should only come from your landing-zone pipeline or a named platform team.

## Query
```esql
FROM logs-azure.activitylogs-* METADATA _id, _index, _version
| WHERE TO_UPPER(azure.activitylogs.operation_name) == "MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE"
  AND event.outcome IN ("success", "Success")
| EVAL scope = TO_LOWER(TO_STRING(azure.activitylogs.properties.scope)),
       body  = TO_LOWER(TO_STRING(azure.activitylogs.properties.requestbody))
// subscription- or management-group-wide, not resource-group scoped
| WHERE (scope LIKE "/subscriptions/*" AND NOT (scope LIKE "*/resourcegroups/*"))
    OR scope LIKE "/providers/microsoft.management/managementgroups/*"
// Owner, User Access Administrator, Contributor role definition IDs
| WHERE body LIKE "*8e3af657-a8ff-443c-a75c-2fe8c4bcb635*"
    OR body LIKE "*18d7d88d-d35e-4fb5-a5c3-7773c20a72d9*"
    OR body LIKE "*b24988ac-6180-42a0-ab88-20f7382dd24c*"
| KEEP @timestamp, azure.activitylogs.identity.claims_initiated_by_user.name, scope, body, source.ip, azure.subscription_id
```

## Known false positives / exclusions
- Landing-zone IaC service principal. Exclude by `azure.activitylogs.identity.claims.appid`.

## Triage
- Principal that was granted (principalId in body), by whom, from where.
- Check whether the grantor's Entra sign-in was risky (I05, I07).

## Test
Assign Reader at subscription scope (no fire), then Contributor to a test group (fire), then remove it.
