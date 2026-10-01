---
id: S21
name: ROADrecon-style tenant enumeration through Azure AD Graph
category: entra-signin
status: todo
severity: high
language: esql
index: logs-azure.aadgraphactivitylogs-*
mitre: [T1087.004, T1069.003, T1526]
data_source: Azure AD Graph activity logs (Elastic Azure integration)
references: [https://github.com/dirkjanm/ROADtools]
suppression:
  fields: [user.id]
  duration: 1h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
ROADrecon, roadtx's companion in ROADtools, dumps a tenant by walking Azure AD Graph: users, groups, roles, service principals, applications, devices and policies, all within about a minute. It uses the Python `aiohttp` HTTP library, which shows in the user agent. Legitimate clients do not call AAD Graph with `aiohttp`, and do not hit five or more of these directory collections in the same minute.

## Query
```esql
FROM logs-azure.aadgraphactivitylogs-*
| WHERE data_stream.dataset == "azure.aadgraphactivitylogs"
  AND TO_LOWER(user_agent.original) LIKE "*aiohttp*"
| EVAL endpoint = CASE(
    url.path LIKE "*/eligibleRoleAssignments*", "eligibleRoleAssignments",
    url.path LIKE "*/roleAssignments*",         "roleAssignments",
    url.path LIKE "*/users*",                   "users",
    url.path LIKE "*/groups*",                  "groups",
    url.path LIKE "*/servicePrincipals*",       "servicePrincipals",
    url.path LIKE "*/applications*",           "applications",
    url.path LIKE "*/devices*",                 "devices",
    url.path LIKE "*/directoryRoles*",          "directoryRoles",
    url.path LIKE "*/roleDefinitions*",         "roleDefinitions",
    url.path LIKE "*/oauth2PermissionGrants*",  "oauth2PermissionGrants",
    url.path LIKE "*/policies*",                "policies",
    url.path LIKE "*/tenantDetails*",           "tenantDetails",
    "other")
| WHERE endpoint != "other"
| STATS requests = COUNT(*),
        distinct_endpoints = COUNT_DISTINCT(endpoint),
        endpoints = VALUES(endpoint),
        app_ids = VALUES(azure.aadgraphactivitylogs.properties.app_id),
        user_agents = VALUES(user_agent.original),
        ips = VALUES(source.ip),
        asns = VALUES(source.as.organization.name),
        first_seen = MIN(@timestamp)
    BY user.id, BUCKET(@timestamp, 1 minute)
| WHERE distinct_endpoints >= 5
```
This log source is not collected by default. Enable the `AzureADGraphActivityLogs` diagnostic setting on Entra ID and add the dataset to the Azure integration. The same idea applies to Microsoft Graph activity logs if ROADtools moves off AAD Graph.

## Suppression
Suppress by `user.id` for 1h. Alerts missing a key field are not suppressed. Aggregating rule. One dump spans several one-minute buckets.

## Known false positives / exclusions
- Internal scripts built on `aiohttp` that read the directory. Rare against AAD Graph; exclude their service principal by app ID after review.

## Triage
- Enumeration means the account's token is in someone else's hands. Check how it was obtained (I08, S19, S20), then revoke sessions and refresh tokens and reset credentials.
- Assume the attacker now has your role assignments and app inventory. Review privileged roles (C03) and app credentials (C04) for follow-on changes.

## Test
Run `roadrecon gather` against a lab tenant.
