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
Deleting diagnostic settings, activity-log exports, Log Analytics workspaces or downgrading a Defender for Cloud plan removes your visibility. This is a deliberate act with almost no legitimate ad-hoc use.

## Query
```esql
FROM logs-azure.activitylogs-* METADATA _id, _index, _version
| EVAL op = TO_UPPER(azure.activitylogs.operation_name)
| WHERE op IN (
    "MICROSOFT.INSIGHTS/DIAGNOSTICSETTINGS/DELETE",
    "MICROSOFT.INSIGHTS/LOGPROFILES/DELETE",
    "MICROSOFT.INSIGHTS/ACTIVITYLOGALERTS/DELETE",
    "MICROSOFT.OPERATIONALINSIGHTS/WORKSPACES/DELETE",
    "MICROSOFT.OPERATIONALINSIGHTS/WORKSPACES/DATASOURCES/DELETE",
    "MICROSOFT.SECURITY/PRICINGS/WRITE",           // Defender for Cloud plan change, check for "Free"
    "MICROSOFT.SECURITY/AUTOPROVISIONINGSETTINGS/WRITE",
    "MICROSOFT.SECURITYINSIGHTS/DATACONNECTORS/DELETE",
    "MICROSOFT.EVENTHUB/NAMESPACES/DELETE",         // if your Elastic export rides Event Hub
    "MICROSOFT.EVENTHUB/NAMESPACES/EVENTHUBS/DELETE"
  )
  AND event.outcome IN ("success", "Success")
| EVAL body = TO_LOWER(TO_STRING(azure.activitylogs.properties.requestbody))
| WHERE NOT (op == "MICROSOFT.SECURITY/PRICINGS/WRITE") OR body LIKE "*\"pricingtier\":\"free\"*"
| KEEP @timestamp, op, azure.activitylogs.identity.claims_initiated_by_user.name, azure.resource.name, azure.subscription_id, source.ip
```

## Suppression
None. Critical defence impairment. Every logging change should page.

## Known false positives / exclusions
- Subscription decommissioning. Exclude the decommissioning service principal only during a ticketed window.

## Triage
- Treat as active defence impairment. Identify what else the actor did in the previous and next 2 hours across all cloud rules.

## Test
Delete a diagnostic setting on a test resource.
