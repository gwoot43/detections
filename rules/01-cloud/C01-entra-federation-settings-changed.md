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
suppression: none
---
## Why this is high fidelity
Changing a domain from managed to federated, or swapping the federation signing certificate, is the "Golden SAML" persistence path. Adding and verifying a new domain is the usual first step, because the attacker then federates a domain they control. Turning directory sync on or off changes which identities Entra trusts on-premises. All of these happen a handful of times a year in a healthy tenant and only by identity engineers during planned work. Every hit is worth a call.

## Query
```esql
FROM logs-azure.auditlogs-* METADATA _id, _index, _version
| WHERE azure.auditlogs.operation_name IN (
    "Set domain authentication",
    "Set federation settings on domain",
    "Add unverified domain",
    "Verify domain",
    "Set DirSyncEnabled flag"
  )
  // the integration moves properties.result into event.outcome, so filter on that
  AND event.outcome == "success"
| KEEP @timestamp, azure.auditlogs.operation_name, azure.auditlogs.properties.initiated_by.user.userPrincipalName,
       azure.auditlogs.properties.initiated_by.app.displayName, `azure.auditlogs.properties.target_resources.0.display_name`,
       source.ip, azure.tenant_id
```
"Update domain" and "Set Company Information" are left out on purpose. They fire for routine domain and tenant property edits, including Microsoft's own background processes, and carry no federation signal on their own.

## Suppression
None. Each federation change is a separate critical event, and Entra writes one audit record per change. Nothing to collapse.

## Known false positives / exclusions
- Planned domain onboarding or Entra Connect rebuilds. Require a change ticket rather than an allowlist.
- The Entra Connect service principal will appear as the initiator for `Set DirSyncEnabled flag`. Keep it in the rule but triage against the Entra Connect server maintenance window.

## Triage
- Confirm the initiator, their sign-in location and whether MFA was used on that session.
- Pull the target domain's current federation config (`Get-MgDomainFederationConfiguration`) and compare issuer URI and signing cert thumbprint to the known-good record.
- Any unexpected federation change is a tenant-compromise incident. Revoke refresh tokens for the initiator and start IR.

## Test
Add and remove a test domain in a non-production tenant, or convert a test domain to federated and back.
