---
id: C06
name: Azure RBAC Owner, User Access Administrator, RBAC Administrator or Contributor assigned at subscription or wider scope
category: cloud
status: todo
severity: high
language: esql
index: logs-azure.activitylogs-*
mitre: [T1098.003]
data_source: Azure Activity log
suppression: none
---
## Why this is high fidelity
Broad-scope role assignments are how an attacker turns one compromised identity into control of all resources. They should only come from your landing-zone pipeline or a named platform team. Role Based Access Control Administrator is included because it can grant any role, the same as User Access Administrator.

## Query
```esql
FROM logs-azure.activitylogs-* METADATA _id, _index, _version
| WHERE TO_UPPER(azure.activitylogs.operation_name) == "MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE"
  AND event.outcome == "success"
// the scope is the role assignment's resource ID; properties is a flattened field, so read it as one string
| EVAL scope = TO_LOWER(azure.resource.id),
       props = TO_LOWER(TO_STRING(azure.activitylogs.properties)),
       actor = COALESCE(azure.activitylogs.identity.claims_initiated_by_user.name, azure.activitylogs.identity.claims.appid)
// subscription, management-group or root scope; resource-group and resource scopes are out
| WHERE (scope LIKE "/subscriptions/*/providers/microsoft.authorization/roleassignments/*" AND scope NOT LIKE "/subscriptions/*/resourcegroups/*")
    OR scope LIKE "/providers/microsoft.management/managementgroups/*"
    OR scope LIKE "/providers/microsoft.authorization/roleassignments/*"
// built-in role definition IDs, found in the request or response body
| EVAL role = CASE(
    props LIKE "*8e3af657-a8ff-443c-a75c-2fe8c4bcb635*", "Owner",
    props LIKE "*18d7d88d-d35e-4fb5-a5c3-7773c20a72d9*", "User Access Administrator",
    props LIKE "*f58310d9-a9f6-439a-9e8d-f62e7b41a168*", "Role Based Access Control Administrator",
    props LIKE "*b24988ac-6180-42a0-ab88-20f7382dd24c*", "Contributor",
    NULL)
| WHERE role IS NOT NULL
// landing-zone IaC service principal, by app ID
  AND COALESCE(azure.activitylogs.identity.claims.appid, "") NOT IN ("00000000-0000-0000-0000-000000000000")
| KEEP @timestamp, actor, role, scope, source.ip, azure.subscription_id, _id, _version, _index
```
`azure.activitylogs.properties` is mapped as `flattened`, so its sub-keys (`requestbody`, `responseBody`) are not ES|QL columns. The rule reads the whole object with `TO_STRING`, which needs an ES|QL version that supports `flattened`. Management-group and root-scope assignments appear only if you also export the tenant-level activity log.

## Suppression
None. Each broad role assignment is a separate privilege grant. The success filter already drops the start and success duplicate.

## Known false positives / exclusions
- Landing-zone IaC service principal. Exclude by `azure.activitylogs.identity.claims.appid` in the inline list.

## Triage
- Principal that was granted (`principalId` in the body), by whom, from where.
- Check whether the grantor's Entra sign-in was risky (I07).

## Test
Assign Reader at subscription scope (no fire), then Contributor to a test group (fire), then remove it.
