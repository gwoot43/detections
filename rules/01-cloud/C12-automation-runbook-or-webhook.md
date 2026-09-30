---
id: C12
name: Azure Automation runbook created or modified, or webhook added
category: cloud
status: todo
severity: high
language: esql
index: logs-azure.activitylogs-*
mitre: [T1648, T1098.001, T1053]
data_source: Azure Activity log
suppression:
  fields: [actor, azure.resource.name]
  duration: 1h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
An Automation runbook runs code on a schedule or via a webhook, often under a managed identity with rights in the subscription. It is cloud persistence that keeps running after every user password is reset, and a webhook gives an unauthenticated external trigger. Runbooks are created by a small platform team.

## Query
```esql
FROM logs-azure.activitylogs-* METADATA _id, _index, _version
| EVAL op = TO_UPPER(azure.activitylogs.operation_name),
       actor = TO_LOWER(COALESCE(azure.activitylogs.identity.claims_initiated_by_user.name, TO_STRING(azure.activitylogs.identity.claims.appid), ""))
| WHERE op IN (
    "MICROSOFT.AUTOMATION/AUTOMATIONACCOUNTS/RUNBOOKS/WRITE",
    "MICROSOFT.AUTOMATION/AUTOMATIONACCOUNTS/RUNBOOKS/DRAFT/WRITE",
    "MICROSOFT.AUTOMATION/AUTOMATIONACCOUNTS/RUNBOOKS/PUBLISH/ACTION",
    "MICROSOFT.AUTOMATION/AUTOMATIONACCOUNTS/WEBHOOKS/WRITE",
    "MICROSOFT.AUTOMATION/AUTOMATIONACCOUNTS/WRITE",
    "MICROSOFT.AUTOMATION/AUTOMATIONACCOUNTS/JOBS/WRITE"
  )
  AND event.outcome IN ("success", "Success")
| WHERE NOT (actor IN ("sp-platform-iac"))     // your landing-zone / IaC principal
| KEEP @timestamp, op, actor, azure.resource.name, azure.resource.group, azure.subscription_id, source.ip
```

## Suppression
Suppress by `actor`, `azure.resource.name` for 1h. Alerts missing a key field are not suppressed. Editing and publishing one runbook writes several operations; a different runbook or actor still alerts.

## Known false positives / exclusions
- The platform team's IaC pipeline, excluded by principal. Confirm human changes against change control.

## Triage
- Read the runbook content and its identity's permissions. A runbook or webhook created by an unexpected principal is cloud persistence: disable it, review what its identity can reach, and correlate with role or credential changes (C03, C04).

## Test
Create and delete a benign test runbook in a lab automation account.
