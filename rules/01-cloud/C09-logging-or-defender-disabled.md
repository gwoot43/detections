---
id: C09
name: Azure logging, diagnostics or Defender for Cloud disabled
category: cloud
status: todo
severity: critical
language: esql
index: logs-azure.activitylogs-*
mitre: [T1562.008, T1685.002]
data_source: Azure Activity log
suppression: none
---
## Why this is high fidelity
Deleting diagnostic settings, activity-log exports, Log Analytics workspaces or the Event Hub your Elastic export reads from, downgrading a Defender for Cloud plan to Free, or switching off agent auto-provisioning removes your visibility. This is a deliberate act with almost no legitimate ad-hoc use.

## Query
```esql
FROM logs-azure.activitylogs-* METADATA _id, _index, _version
| EVAL op = TO_UPPER(azure.activitylogs.operation_name)
| WHERE op IN (
    "MICROSOFT.INSIGHTS/DIAGNOSTICSETTINGS/DELETE",
    "MICROSOFT.INSIGHTS/LOGPROFILES/DELETE",
    "MICROSOFT.OPERATIONALINSIGHTS/WORKSPACES/DELETE",
    "MICROSOFT.OPERATIONALINSIGHTS/WORKSPACES/DATASOURCES/DELETE",
    "MICROSOFT.SECURITY/PRICINGS/WRITE",
    "MICROSOFT.SECURITY/AUTOPROVISIONINGSETTINGS/WRITE",
    "MICROSOFT.SECURITYINSIGHTS/DATACONNECTORS/DELETE",
    "MICROSOFT.EVENTHUB/NAMESPACES/DELETE",
    "MICROSOFT.EVENTHUB/NAMESPACES/EVENTHUBS/DELETE"
  )
  AND event.outcome == "success"
// properties is a flattened field: read it as one string without case, quotes, backslashes or whitespace
| EVAL body = REPLACE(REPLACE(REPLACE(TO_LOWER(TO_STRING(azure.activitylogs.properties)), "\"", ""), """\\""", ""), """\s""", ""),
       res = TO_LOWER(COALESCE(azure.resource.id, "")),
       actor = COALESCE(azure.activitylogs.identity.claims_initiated_by_user.name, azure.activitylogs.identity.claims.appid)
// a plan write only when the plan drops to Free; auto-provisioning only when it is switched off
| WHERE (op != "MICROSOFT.SECURITY/PRICINGS/WRITE" OR body LIKE "*pricingtier:free*")
  AND (op != "MICROSOFT.SECURITY/AUTOPROVISIONINGSETTINGS/WRITE" OR body LIKE "*autoprovision:off*")
  // Event Hub deletes only for the namespace that carries your Elastic export (replace the name)
  AND (op NOT LIKE "MICROSOFT.EVENTHUB/*" OR res LIKE "*/namespaces/evhns-elastic-export*")
| KEEP @timestamp, op, actor, azure.resource.name, azure.resource.id, azure.subscription_id, source.ip
```
Activity-log alert deletions were removed: alert rules are edited and deleted routinely by the teams that own them, and losing one alert does not remove the underlying logs.

## Suppression
None. Critical defence impairment. Every logging change should page.

## Known false positives / exclusions
- Subscription decommissioning. Exclude the decommissioning service principal only during a ticketed window.
- Short-lived development workspaces. If a team creates and deletes them routinely, exclude that resource group by name in the `res` condition.

## Triage
- Treat as active defence impairment. Identify what else the actor did in the previous and next 2 hours across all cloud rules.

## Test
Delete a diagnostic setting on a test resource.
