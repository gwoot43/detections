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
ROADrecon, roadtx's companion in ROADtools, dumps a tenant by walking Azure AD Graph: users, groups, roles, service principals, applications, devices and policies, all within about a minute. It uses the Python `aiohttp` HTTP library, which shows in the user agent. Legitimate clients do not call AAD Graph with `aiohttp`, and do not hit five or more of these directory collections within a few minutes.

## Query
Run every 5 minutes with a 10-minute lookback.
```esql
FROM logs-azure.aadgraphactivitylogs-*
| WHERE TO_LOWER(user_agent.original) LIKE "*aiohttp*"
| EVAL p = TO_LOWER(url.path),
       endpoint = CASE(
    p LIKE "*/eligibleroleassignments*", "eligibleRoleAssignments",
    p LIKE "*/roleassignments*",         "roleAssignments",
    p LIKE "*/users*",                   "users",
    p LIKE "*/groups*",                  "groups",
    p LIKE "*/serviceprincipals*",       "servicePrincipals",
    p LIKE "*/applications*",            "applications",
    p LIKE "*/devices*",                 "devices",
    p LIKE "*/directoryroles*",          "directoryRoles",
    p LIKE "*/roledefinitions*",         "roleDefinitions",
    p LIKE "*/oauth2permissiongrants*",  "oauth2PermissionGrants",
    p LIKE "*/policies*",                "policies",
    p LIKE "*/tenantdetails*",           "tenantDetails",
    "other")
| WHERE endpoint != "other"
| STATS requests = COUNT(*),
        distinct_endpoints = COUNT_DISTINCT(endpoint),
        endpoints = VALUES(endpoint),
        app_ids = VALUES(azure.aadgraphactivitylogs.properties.app_id),
        user_agents = VALUES(user_agent.original),
        ips = VALUES(source.ip),
        asns = VALUES(source.as.organization.name),
        first_seen = MIN(@timestamp),
        last_seen = MAX(@timestamp)
    BY user.id
| WHERE distinct_endpoints >= 5
```
The path is lower-cased before matching because `LIKE` is case-sensitive and clients differ in how they case collection names. The rule window replaces a one-minute `BUCKET`: a dump that straddles a minute boundary splits into two buckets of a few collections each and never fires.

This log source is not collected by default. Enable the `AzureADGraphActivityLogs` diagnostic setting on Entra ID and add the dataset to the Azure integration. The same idea applies to Microsoft Graph activity logs if ROADtools moves off AAD Graph.

## Suppression
Suppress by `user.id` for 1h. Alerts missing a key field are not suppressed. Aggregating rule. One dump spans several overlapping runs.

## Known false positives / exclusions
- Internal scripts built on `aiohttp` that read the directory. Rare against AAD Graph; exclude their service principal by app ID after review.

## Triage
- Enumeration means the account's token is in someone else's hands. Check how it was obtained (I08, S19, S20), then revoke sessions and refresh tokens and reset credentials.
- Assume the attacker now has your role assignments and app inventory. Review privileged roles (C03) and app credentials (C04) for follow-on changes.

## Test
Run `roadrecon gather` against a lab tenant.
