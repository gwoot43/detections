---
id: C05
name: Admin consent or high-privilege Graph permission granted to an application
category: cloud
status: todo
severity: high
language: esql
index: logs-azure.auditlogs-*
mitre: [T1528, T1098.001]
data_source: Entra ID audit logs
suppression:
  fields: [azure.auditlogs.properties.initiated_by.user.userPrincipalName, azure.auditlogs.properties.target_resources.0.display_name]
  duration: 1h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
OAuth consent phishing and rogue app registrations (the technique behind the 2025 to 2026 Salesloft, ConsentFix and EvilTokens campaigns) end with a consent grant or an app role assignment for Mail.Read, Mail.ReadWrite, Files.ReadWrite.All, Directory.ReadWrite.All or RoleManagement.ReadWrite.Directory. Those grants are rare and reviewable.

## Query
```esql
FROM logs-azure.auditlogs-* METADATA _id, _index, _version
| WHERE azure.auditlogs.properties.category == "ApplicationManagement"
  AND azure.auditlogs.operation_name IN (
    "Consent to application",
    "Add app role assignment to service principal",
    "Add delegated permission grant",
    "Add OAuth2PermissionGrant"
  )
  AND azure.auditlogs.properties.result == "success"
// Copy the granted scope string to entra.consent_scopes in the pipeline (from modified_properties "ConsentAction.Permissions")
| EVAL scopes = TO_LOWER(TO_STRING(entra.consent_scopes))
| WHERE scopes LIKE "*mail.read*" OR scopes LIKE "*mail.send*" OR scopes LIKE "*mailboxsettings*"
   OR scopes LIKE "*files.read*"  OR scopes LIKE "*sites.read*"
   OR scopes LIKE "*directory.readwrite*" OR scopes LIKE "*rolemanagement*"
   OR scopes LIKE "*application.readwrite*" OR scopes LIKE "*user.readwrite.all*"
   OR scopes LIKE "*offline_access*"
| KEEP @timestamp, azure.auditlogs.operation_name, azure.auditlogs.properties.initiated_by.user.userPrincipalName,
       `azure.auditlogs.properties.target_resources.0.display_name`, scopes, source.ip
```

## Suppression
Suppress by `azure.auditlogs.properties.initiated_by.user.userPrincipalName`, `azure.auditlogs.properties.target_resources.0.display_name` for 1h. Alerts missing a key field are not suppressed. One consent writes several records: consent, delegated grant and app role assignment.

## Known false positives / exclusions
- Approved SaaS integrations. Maintain a list of approved app IDs and exclude on `target_resources.0.id`, not on display name (display names are attacker-controlled).
- Admin consent workflow approvals by the app governance team. Keep, lower severity.

## Triage
- Is the app multi-tenant and owned by an external tenant? Publisher verified?
- Which user consented, and did that user receive a phishing mail (E01) in the previous hour?
- Revoke the grant, disable the service principal, revoke the user's refresh tokens.

## Test
Consent a test app to `User.Read` (should not fire), then `Mail.Read` (should fire).
