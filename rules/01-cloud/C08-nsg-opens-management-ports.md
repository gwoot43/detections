---
id: C08
name: Network security group rule exposes management ports to the internet
category: cloud
status: todo
severity: high
language: esql
index: logs-azure.activitylogs-*
mitre: [T1686.001, T1133]
data_source: Azure Activity log
suppression:
  fields: [actor, azure.resource.name]
  duration: 1h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
An inbound allow from `*`, `0.0.0.0/0` or `Internet` on 22, 3389, 5985, 5986, 1433 or 3306 (or on all ports) is either a mistake that becomes an incident or an attacker opening a door. Either way it needs to be closed within the hour.

## Query
```esql
FROM logs-azure.activitylogs-* METADATA _id, _index, _version
| WHERE TO_UPPER(azure.activitylogs.operation_name) == "MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/SECURITYRULES/WRITE"
  AND event.outcome == "success"
// properties is a flattened field: read it as one string, then drop case, quotes, backslashes and whitespace
// so a rule reads like access:allow,direction:inbound,sourceaddressprefix:*,destinationportrange:3389
| EVAL body = REPLACE(REPLACE(REPLACE(TO_LOWER(TO_STRING(azure.activitylogs.properties)), "\"", ""), """\\""", ""), """\s""", ""),
       actor = COALESCE(azure.activitylogs.identity.claims_initiated_by_user.name, azure.activitylogs.identity.claims.appid)
| WHERE body LIKE "*access:allow*" AND body LIKE "*direction:inbound*"
  // source is any, 0.0.0.0/0 or Internet, as a single prefix or inside a prefix list
  AND body RLIKE """.*sourceaddressprefix(es)?:\[?([^\]:]*,)?(\*|0\.0\.0\.0/0|internet|any)[,\]}].*"""
  // destination is a management or database port, or every port, as a single range or inside a list
  AND body RLIKE """.*destinationportranges?:\[?([^\]:]*,)?(22|3389|5985|5986|1433|3306|\*|0-65535)[,\]}].*"""
| KEEP @timestamp, actor, azure.resource.name, azure.resource.group, azure.resource.id, azure.subscription_id, source.ip
```
Only the security-rule write is matched. A whole-NSG write (`NETWORKSECURITYGROUPS/WRITE`, used by templates) carries every rule in one body, so the allow, direction, source and port could each come from a different rule and the match would be meaningless. Azure Firewall bodies use different keys and never matched the old conditions, so they were removed. Port ranges such as `3000-4000` that only contain a management port are not detected.

## Suppression
Suppress by `actor`, `azure.resource.name` for 1h. Alerts missing a key field are not suppressed. Portal edits can save the same rule several times.

## Known false positives / exclusions
- Jump-host NSGs that are intentionally open with JIT. Prefer Defender for Cloud JIT and exclude that NSG by resource ID.

## Triage
- Close the rule, then find out who and why. Check for a matching VM creation minutes earlier (attacker-built jump box).

## Test
Add an inbound allow-any rule on a test NSG for port 3389 and remove it.
