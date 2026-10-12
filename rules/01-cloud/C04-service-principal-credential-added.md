---
id: C04
name: Credential added to an application or service principal
category: cloud
status: todo
severity: high
language: esql
index: logs-azure.auditlogs-*
mitre: [T1098.001, T1550.001]
data_source: Entra ID audit logs
suppression:
  fields: [actor, azure.auditlogs.properties.target_resources.0.display_name]
  duration: 1h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
Adding a secret or certificate to an existing app is the quietest persistence in Entra. It survives password resets and MFA re-registration. Legitimate additions come from a small set of app owners and rotation pipelines.

## Query
```esql
FROM logs-azure.auditlogs-* METADATA _id, _index, _version
| WHERE azure.auditlogs.properties.category == "ApplicationManagement"
  // the app-registration operation name uses an en dash and sometimes a trailing space, so match it loosely
  AND (azure.auditlogs.operation_name == "Add service principal credentials"
       OR azure.auditlogs.operation_name LIKE "Update application*Certificates and secrets management*")
  // the integration moves properties.result into event.outcome, so filter on that
  AND event.outcome == "success"
| EVAL actor = COALESCE(azure.auditlogs.properties.initiated_by.user.userPrincipalName,
                        azure.auditlogs.properties.initiated_by.app.displayName),
       actor_app = COALESCE(azure.auditlogs.properties.initiated_by.app.displayName, ""),
       actor_sp = COALESCE(azure.auditlogs.properties.initiated_by.app.servicePrincipalId, "")
// managed identities rotate their own certificates through "Add service principal credentials"
| WHERE actor_app != "Managed Service Identity"
// secret-rotation pipeline, by service principal object ID
  AND actor_sp NOT IN ("00000000-0000-0000-0000-000000000000")
| KEEP @timestamp, azure.auditlogs.operation_name, actor, `azure.auditlogs.properties.target_resources.0.display_name`, source.ip, _id, _version, _index
```
Owner changes ("Add owner to application", "Add owner to service principal") are not credential adds and are left out. They are frequent in development tenants and the credential add that usually follows is what this rule catches.

## Suppression
Suppress by `actor`, `azure.auditlogs.properties.target_resources.0.display_name` for 1h. Alerts missing a key field are not suppressed. One secret add writes both an application update and a credential add.

## Known false positives / exclusions
- Automated secret rotation (Key Vault rotation, Terraform). Exclude by service principal object ID.
- Managed identity certificate rotation, initiated by "Managed Service Identity". Excluded above by display name; replace it with that service principal's object ID from your tenant so a look-alike app name cannot hide behind it.
- The "Certificates and secrets management" record is also written when a secret is removed. Check `modified_properties` (old versus new key list) before escalating.
- Developers adding secrets to their own dev apps. Raise severity when the target app holds Graph application permissions (see C05) or is a first-party Microsoft app.

## Triage
- Which app, what permissions does it hold (`Get-MgServicePrincipalAppRoleAssignment`), who owns it.
- Was the actor's session risky or from a new location. A credential add minutes after a suspicious sign-in is confirmed persistence.

## Test
Add and remove a client secret on a test app registration.
