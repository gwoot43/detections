---
id: C08
name: Network security group rule exposes management ports to the internet
category: cloud
status: todo
severity: high
language: esql
index: logs-azure.activitylogs-*
mitre: [T1562.007, T1133]
data_source: Azure Activity log
---
## Why this is high fidelity
An inbound allow from `*` or `0.0.0.0/0` on 22, 3389, 5985, 5986, 1433 or 3306 is either a mistake that becomes an incident or an attacker opening a door. Either way it needs to be closed within the hour.

## Query
```esql
FROM logs-azure.activitylogs-* METADATA _id, _index, _version
| EVAL op = TO_UPPER(azure.activitylogs.operation_name)
| WHERE op IN (
    "MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/SECURITYRULES/WRITE",
    "MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/WRITE",
    "MICROSOFT.NETWORK/AZUREFIREWALLS/WRITE",
    "MICROSOFT.NETWORK/FIREWALLPOLICIES/RULECOLLECTIONGROUPS/WRITE"
  )
  AND event.outcome IN ("success", "Success")
| EVAL body = TO_LOWER(TO_STRING(azure.activitylogs.properties.requestbody))
| WHERE body LIKE "*\"access\":\"allow\"*" AND body LIKE "*\"direction\":\"inbound\"*"
  AND (body LIKE "*\"sourceaddressprefix\":\"*\"*" OR body LIKE "*\"sourceaddressprefix\":\"0.0.0.0/0\"*" OR body LIKE "*\"sourceaddressprefix\":\"internet\"*")
  AND (body LIKE "*\"destinationportrange\":\"22\"*" OR body LIKE "*\"destinationportrange\":\"3389\"*"
       OR body LIKE "*\"destinationportrange\":\"5985\"*" OR body LIKE "*\"destinationportrange\":\"5986\"*"
       OR body LIKE "*\"destinationportrange\":\"1433\"*" OR body LIKE "*\"destinationportrange\":\"3306\"*"
       OR body LIKE "*\"destinationportrange\":\"*\"*")
| KEEP @timestamp, op, azure.activitylogs.identity.claims_initiated_by_user.name, azure.resource.name, azure.resource.group, body
```

## Known false positives / exclusions
- Jump-host NSGs that are intentionally open with JIT. Prefer Defender for Cloud JIT and exclude that NSG by resource ID.

## Triage
- Close the rule, then find out who and why. Check for a matching VM creation minutes earlier (attacker-built jump box).

## Test
Add an inbound allow-any rule on a test NSG for port 3389 and remove it.
