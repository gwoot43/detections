---
id: C05
name: Admin consent or high-privilege Graph permission granted to an application
category: cloud
status: todo
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
OAuth consent phishing and rogue app registrations (the technique behind the 2025 to 2026 Salesloft, ConsentFix and EvilTokens campaigns) end with a consent grant or an app role assignment for Mail.Read, Mail.ReadWrite, Files.ReadWrite.All, Directory.ReadWrite.All or RoleManagement.ReadWrite.Directory. Those grants are rare and reviewable. Scopes that nearly every app requests (`offline_access`, `User.Read`, a user's own `Files.Read`) are not matched.

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
  // the integration moves properties.result into event.outcome, so filter on that
  AND event.outcome == "success"
// the granted scope sits in the target's modified properties (ConsentAction.Permissions,
// AppRole.Value or DelegatedPermissionGrant.Scope); its position varies, so search the first seven
| EVAL scopes = TO_LOWER(CONCAT(
         COALESCE(`azure.auditlogs.properties.target_resources.0.modified_properties.0.new_value`, ""), "|",
         COALESCE(`azure.auditlogs.properties.target_resources.0.modified_properties.1.new_value`, ""), "|",
         COALESCE(`azure.auditlogs.properties.target_resources.0.modified_properties.2.new_value`, ""), "|",
         COALESCE(`azure.auditlogs.properties.target_resources.0.modified_properties.3.new_value`, ""), "|",
         COALESCE(`azure.auditlogs.properties.target_resources.0.modified_properties.4.new_value`, ""), "|",
         COALESCE(`azure.auditlogs.properties.target_resources.0.modified_properties.5.new_value`, ""), "|",
         COALESCE(`azure.auditlogs.properties.target_resources.0.modified_properties.6.new_value`, "")))
| WHERE scopes LIKE "*mail.read*" OR scopes LIKE "*mail.send*" OR scopes LIKE "*mailboxsettings.readwrite*"
   OR scopes LIKE "*files.read.all*" OR scopes LIKE "*files.readwrite.all*" OR scopes LIKE "*sites.read*"
   OR scopes LIKE "*directory.readwrite*" OR scopes LIKE "*rolemanagement.readwrite*"
   OR scopes LIKE "*application.readwrite*" OR scopes LIKE "*approleassignment.readwrite*"
   OR scopes LIKE "*user.readwrite.all*" OR scopes LIKE "*full_access_as_app*"
// approved SaaS apps: service principal object IDs, never display names
| WHERE COALESCE(`azure.auditlogs.properties.target_resources.0.id`, "") NOT IN ("00000000-0000-0000-0000-000000000000")
| KEEP @timestamp, azure.auditlogs.operation_name, azure.auditlogs.properties.initiated_by.user.userPrincipalName,
       `azure.auditlogs.properties.target_resources.0.display_name`, `azure.auditlogs.properties.target_resources.0.id`, scopes, source.ip, _id, _version, _index
```

## Suppression
Suppress by `azure.auditlogs.properties.initiated_by.user.userPrincipalName`, `azure.auditlogs.properties.target_resources.0.display_name` for 1h. Alerts missing a key field are not suppressed. One consent writes several records: consent, delegated grant and app role assignment.

## Known false positives / exclusions
- Approved SaaS integrations. Keep the approved service principal object IDs in the inline list above (`target_resources.0.id`), not display names (display names are attacker-controlled).
- Admin consent workflow approvals by the app governance team. Keep them, scored lower.

## Triage
- Is the app multi-tenant and owned by an external tenant? Publisher verified?
- Which user consented, and did that user receive a phishing mail (E01) in the previous hour?
- Revoke the grant, disable the service principal, revoke the user's refresh tokens.

## Test
Consent a test app to `User.Read` (should not fire), then `Mail.Read` (should fire).
