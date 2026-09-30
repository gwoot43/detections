---
id: C02
name: Conditional Access policy created, modified or deleted
category: cloud
status: todo
severity: high
language: esql
index: logs-azure.auditlogs-*
mitre: [T1556.009, T1562.007]
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
  AND azure.auditlogs.properties.result == "success"
| EVAL actor = COALESCE(azure.auditlogs.properties.initiated_by.user.userPrincipalName,
                        azure.auditlogs.properties.initiated_by.app.displayName)
// exclude your IaC / policy-as-code service principal here
| WHERE NOT (actor IN ("sp-entra-policy-pipeline@yourtenant.onmicrosoft.com"))
| KEEP @timestamp, azure.auditlogs.operation_name, actor, `azure.auditlogs.properties.target_resources.0.display_name`, source.ip
```

## Suppression
Suppress by `actor`, `azure.auditlogs.properties.target_resources.0.display_name` for 1h. Alerts missing a key field are not suppressed. An admin editing one policy often saves several times in a session. A different policy or admin still alerts.

## Known false positives / exclusions
- Policy-as-code pipelines. Exclude by service principal, never by user.
- Named-location updates during office moves. Keep them in but tag lower severity in the rule action.

## Triage
- Diff the policy: the audit record carries old and new JSON in `modified_properties`. Look for exclusions added, MFA grant removed, state changed to "disabled" or "report-only".
- Check the actor's sign-in for that session (IP, device, MFA, risk).

## Test
Create and delete a report-only policy in a test tenant, or change a named location.
