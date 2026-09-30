---
id: S04
name: Microsoft first-party CLI or PowerShell app used by a non-administrator
category: entra-signin
status: todo
severity: high
language: esql
index: logs-azure.signinlogs-*
mitre: [T1087.004, T1526, T1078.004]
data_source: Entra ID sign-in logs
---
## Why this is high fidelity
Azure AD PowerShell, Microsoft Graph Command Line Tools, Azure CLI and Azure PowerShell are the client IDs that AzureHound, ROADtools, AADInternals and manual attacker recon authenticate as, because they carry broad delegated Graph scopes. Ordinary users have no reason to use them. A standard user authenticating through these app IDs is either a developer you can name or an attacker enumerating the tenant with a stolen token.

## Query
```esql
FROM logs-azure.signinlogs-* METADATA _id, _index, _version
| WHERE TO_STRING(azure.signinlogs.properties.status.error_code) == "0"
| EVAL app_id = TO_LOWER(TO_STRING(azure.signinlogs.properties.app_id)), usr = TO_LOWER(user.name)
| WHERE app_id IN (
    "1b730954-1685-4b74-9bfd-dac224a7b894",   // Azure Active Directory PowerShell
    "14d82eec-204b-4c2f-b7e8-296a70dab67e",   // Microsoft Graph Command Line Tools
    "04b07795-8ddb-461a-bbee-02f9e1bf7b46",   // Microsoft Azure CLI
    "1950a258-227b-4e31-a9cf-717495945fc2",   // Microsoft Azure PowerShell
    "fb78d390-0c51-40cd-8e17-fdbfab77341b",   // Microsoft Exchange REST API Based PowerShell
    "a0c73c16-a7e3-4564-9a95-2bdf47383716"    // Microsoft Exchange Online Remote PowerShell
  )
  AND NOT (usr LIKE "adm-*" OR usr LIKE "*-admin@*" OR usr LIKE "svc-*")   // your admin / automation naming, or a lookup
| STATS n = COUNT(*), apps = VALUES(azure.signinlogs.properties.app_display_name), ips = VALUES(source.ip), asns = VALUES(source.as.organization.name), where_from = VALUES(source.geo.country_iso_code)
    BY usr, BUCKET(@timestamp, 1 hour)
```

## Known false positives / exclusions
- Developers and cloud engineers using Azure CLI. Exclude the engineering group via lookup, not by wildcard. Keep the Azure AD PowerShell and Graph CLI branches even for developers; those are the ones the recon tooling prefers.

## Triage
- Check the user's role: if not an admin or developer, the token was stolen. Look at the same user's earlier sign-ins (I07/I08/C11) for how the token was obtained, then revoke.

## Test
Run `Connect-MgGraph` as a standard test user.
