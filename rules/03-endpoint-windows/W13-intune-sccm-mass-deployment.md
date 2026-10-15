---
id: W13
name: Endpoint management platform used to deploy a script or app at scale
category: endpoint-windows
status: todo
severity: high
language: esql
index: logs-azure.platformlogs-*
mitre: [T1072]
data_source: Intune audit logs exported by diagnostic settings to Event Hub (Elastic Azure Logs integration, platformlogs data stream)
suppression:
  fields: [actor, op]
  duration: 1h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
An attacker who compromises the endpoint management console can push code to every device at once, which is a fast path from one admin account to the whole fleet. New or reassigned scripts and apps in Intune are made by a small admin team, so an unexpected one is high value. This complements the endpoint-side view (a management agent spawning a script) with the control-plane action.

## Prerequisite
In Intune, add a diagnostic setting that sends **AuditLogs** to an Event Hub, and collect that hub with the Elastic Azure Logs integration (platform logs). Intune audit records then land in `logs-azure.platformlogs-*` with `azure.resource.provider` set to `MICROSOFT.INTUNE`. No Elastic data stream has "intune" in `event.dataset`, so the rule keys on the provider instead.

## Query
```esql
FROM logs-azure.platformlogs-* METADATA _id, _index, _version
| WHERE TO_LOWER(azure.resource.provider) == "microsoft.intune" AND TO_LOWER(azure.platformlogs.category) == "auditlogs"
| EVAL op = TO_LOWER(COALESCE(azure.platformlogs.operation_name, "")),
       actor = TO_LOWER(COALESCE(azure.platformlogs.identity_name, ""))
// new or changed scripts (platform, remediation, macOS shell), and new or reassigned apps
| WHERE ((op LIKE "*devicemanagementscript*" OR op LIKE "*devicehealthscript*" OR op LIKE "*deviceshellscript*")
         AND (op LIKE "create*" OR op LIKE "patch*" OR op LIKE "assign*"))
     OR ((op LIKE "create*" OR op LIKE "assign*") AND op LIKE "*mobileapp*")
| WHERE actor NOT IN ("svc-intune-automation")    // your MDM automation account, if any
| KEEP @timestamp, actor, op, azure.platformlogs.result_type, azure.tenant_id, _id, _version, _index
```
SCCM has no equivalent cloud audit feed. Its endpoint-side view (a management agent spawning a script) is covered by the FDR rules.

## Suppression
Suppress by `actor`, `op` for 1h. Alerts missing a key field are not suppressed. Creating and assigning one item writes several audit lines; a different admin or operation still alerts.

## Known false positives / exclusions
- The endpoint management team's routine work. Exclude the automation account, confirm human changes against change control. Consider routing to a lower-priority queue and escalating only when the assignment targets all devices or a large group.

## Triage
- Open the change in the Intune portal (the full record is in `azure.platformlogs.properties` in Discover). Read the script or app content and the assignment scope. A script assigned to all devices from an unexpected admin is a fleet-wide compromise; disable the assignment immediately and review the admin account (S03, C03).

## Test
Create, then delete, a benign platform script in a lab Intune tenant and confirm the audit record arrives in `logs-azure.platformlogs-*`.
