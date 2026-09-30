---
id: W13
name: Endpoint management platform used to deploy a script or app at scale
category: endpoint-windows
status: todo
severity: high
language: esql
index: logs-*
mitre: [T1072]
data_source: Intune audit logs (Graph) and/or SCCM status, or CrowdStrike FDR by management-agent parent
suppression:
  fields: [actor, op]
  duration: 1h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
An attacker who compromises the endpoint management console can push code to every device at once, which is a fast path from one admin account to the whole fleet. New or reassigned scripts and apps in Intune, and new SCCM deployments, are made by a small admin team, so an unexpected one is high value. This complements the endpoint-side view (a management agent spawning a script) with the control-plane action.

## Query (Intune audit via Graph, ingested to Elastic)
```esql
FROM logs-* METADATA _id, _index, _version
| WHERE event.dataset LIKE "*intune*" OR event.provider == "Microsoft.Intune"
| EVAL op = TO_LOWER(TO_STRING(COALESCE(azure.auditlogs.operation_name, event.action, ""))),
       actor = TO_LOWER(TO_STRING(COALESCE(azure.auditlogs.properties.initiated_by.user.userPrincipalName, user.name, "")))
| WHERE op LIKE "*devicemanagementscript*" OR op LIKE "*devicehealthscript*" OR op LIKE "*deviceshellscript*"
     OR (op LIKE "*create*" AND (op LIKE "*mobileapp*" OR op LIKE "*win32lobapp*"))
     OR op LIKE "*assign*" AND (op LIKE "*script*" OR op LIKE "*app*")
| WHERE NOT (actor IN ("svc-intune-automation"))    // your MDM automation account, if any
| KEEP @timestamp, actor, op, event.dataset
```

## Suppression
Suppress by `actor`, `op` for 1h. Alerts missing a key field are not suppressed. Creating and assigning one item writes several audit lines; a different admin or operation still alerts.

## Known false positives / exclusions
- The endpoint management team's routine work. Exclude the automation account, confirm human changes against change control. Consider routing to a lower-priority queue and escalating only when the assignment targets all devices or a large group.

## Triage
- Read the script or app content and the assignment scope. A script assigned to all devices from an unexpected admin is a fleet-wide compromise; disable the assignment immediately and review the admin account (S03, C03).

## Test
Create and unassign a benign platform script in a lab Intune tenant.
