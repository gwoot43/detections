---
id: C01
name: Entra domain federation or authentication settings changed
category: cloud
status: todo
severity: critical
language: esql
index: logs-azure.auditlogs-*
mitre: [T1484.002]
data_source: Entra ID audit logs (Elastic Azure integration)
---
## Why this is high fidelity
Changing a domain from managed to federated, or swapping the federation signing certificate, is the "Golden SAML" persistence path. It happens a handful of times a year in a healthy tenant and only by identity engineers during planned work. Every hit is worth a call.

## Query
```esql
FROM logs-azure.auditlogs-* METADATA _id, _index, _version
| WHERE azure.auditlogs.operation_name IN (
    "Set domain authentication",
    "Set federation settings on domain",
    "Set DirSyncEnabled flag on domain",
    "Update domain",
    "Add unverified domain",
    "Verify domain",
    "Set Company Information"        // Entra Connect / federation config changes land here too
  )
  AND azure.auditlogs.properties.result == "success"
| KEEP @timestamp, azure.auditlogs.operation_name, azure.auditlogs.properties.initiated_by.user.userPrincipalName,
       azure.auditlogs.properties.initiated_by.app.displayName, azure.auditlogs.properties.target_resources.0.display_name,
       source.ip, azure.tenant_id
```

## Known false positives / exclusions
- Planned domain onboarding or Entra Connect rebuilds. Require a change ticket rather than an allowlist.
- The Entra Connect service principal will appear as the initiator for `Set DirSyncEnabled flag on domain`. Keep it in the rule but triage against the AADC server maintenance window.

## Triage
- Confirm the initiator, their sign-in location and whether MFA was used on that session.
- Pull the target domain's current federation config (`Get-MgDomainFederationConfiguration`) and compare issuer URI and signing cert thumbprint to the known-good record.
- Any unexpected federation change is a tenant-compromise incident. Revoke refresh tokens for the initiator and start IR.

## Test
Add and remove a test domain in a non-production tenant, or convert a test domain to federated and back.
