---
id: C02
name: Conditional Access policy created, modified or deleted
category: cloud
status: todo
language: esql
index: logs-azure.auditlogs-*
mitre: [T1556.009, T1686.001]
data_source: Entra ID audit logs
suppression:
  fields: [actor, azure.auditlogs.properties.target_resources.0.display_name]
  duration: 1h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
Attackers who land a Global Admin or Security Admin session weaken or delete Conditional Access first. Policy changes are low volume and always attributable to a person or an IaC pipeline.

## Query
```esql
FROM logs-azure.auditlogs-* METADATA _id, _index, _version
| WHERE azure.auditlogs.properties.category == "Policy"
  AND azure.auditlogs.operation_name IN (
    "Add conditional access policy",
    "Update conditional access policy",
    "Delete conditional access policy",
    "Add named location",
    "Update named location",
    "Delete named location"
  )
  // the integration moves properties.result into event.outcome, so filter on that
  AND event.outcome == "success"
| EVAL actor = COALESCE(azure.auditlogs.properties.initiated_by.user.userPrincipalName,
                        azure.auditlogs.properties.initiated_by.app.displayName),
       actor_sp = COALESCE(azure.auditlogs.properties.initiated_by.app.servicePrincipalId, "")
// exclude your IaC / policy-as-code service principal by object ID (display names can be copied)
| WHERE actor_sp NOT IN ("00000000-0000-0000-0000-000000000000")
| KEEP @timestamp, azure.auditlogs.operation_name, actor, `azure.auditlogs.properties.target_resources.0.display_name`, source.ip, _id, _version, _index
```

## Suppression
Suppress by `actor`, `azure.auditlogs.properties.target_resources.0.display_name` for 1h. Alerts missing a key field are not suppressed. An admin editing one policy often saves several times in a session. A different policy or admin still alerts.

## Known false positives / exclusions
- Policy-as-code pipelines. Exclude by service principal object ID (`initiated_by.app.servicePrincipalId`), never by user or display name.
- Microsoft-managed policies, which Microsoft creates and updates in report-only mode. Exclude the Microsoft service principal that appears as the initiator by its object ID once you have seen it.
- Named-location updates during office moves. Keep them in, and score them lower.

## Triage
- Diff the policy: the audit record carries old and new JSON in `modified_properties`. Look for exclusions added, MFA grant removed, state changed to "disabled" or "report-only".
- Check the actor's sign-in for that session (IP, device, MFA, risk).

## Test
Create and delete a report-only policy in a test tenant, or change a named location.
