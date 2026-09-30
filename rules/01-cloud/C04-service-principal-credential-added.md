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
---
## Why this is high fidelity
Adding a secret or certificate to an existing app is the quietest persistence in Entra. It survives password resets and MFA re-registration. Legitimate additions come from a small set of app owners and rotation pipelines.

## Query
```esql
FROM logs-azure.auditlogs-* METADATA _id, _index, _version
| WHERE azure.auditlogs.properties.category == "ApplicationManagement"
  AND azure.auditlogs.operation_name IN (
    "Add service principal credentials",
    "Update application – Certificates and secrets management",
    "Update application - Certificates and secrets management",
    "Add owner to application",
    "Add owner to service principal"
  )
  AND azure.auditlogs.properties.result == "success"
| EVAL actor = COALESCE(azure.auditlogs.properties.initiated_by.user.userPrincipalName,
                        azure.auditlogs.properties.initiated_by.app.displayName)
| WHERE NOT (actor IN ("sp-secret-rotation@yourtenant.onmicrosoft.com"))
| KEEP @timestamp, azure.auditlogs.operation_name, actor, azure.auditlogs.properties.target_resources.0.display_name, source.ip
```

## Known false positives / exclusions
- Automated secret rotation (Key Vault rotation, Terraform). Exclude by service principal.
- Developers adding secrets to their own dev apps. Raise severity when the target app holds Graph application permissions (see C05) or is a first-party Microsoft app.

## Triage
- Which app, what permissions does it hold (`Get-MgServicePrincipalAppRoleAssignment`), who owns it.
- Was the actor's session risky or from a new location. A credential add minutes after a suspicious sign-in is confirmed persistence.

## Test
Add and remove a client secret on a test app registration.
