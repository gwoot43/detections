---
id: S01
name: Break-glass (emergency access) account sign-in
category: entra-signin
status: todo
severity: critical
language: esql
index: logs-azure.signinlogs-*
mitre: [T1078.004]
data_source: Entra ID sign-in logs (interactive and non-interactive)
---
## Why this is high fidelity
Emergency access accounts are excluded from Conditional Access by design and never used outside a declared emergency. Any sign-in, successful or failed, interactive or not, is either a declared incident you already know about or an attacker who found the one account that bypasses your controls. Zero legitimate background volume.

## Query
```esql
FROM logs-azure.signinlogs-* METADATA _id, _index, _version
| WHERE TO_LOWER(user.name) IN ("breakglass1@yourtenant.onmicrosoft.com", "breakglass2@yourtenant.onmicrosoft.com")
   OR TO_LOWER(azure.signinlogs.properties.user_principal_name) LIKE "*breakglass*"
   OR TO_LOWER(azure.signinlogs.properties.user_principal_name) LIKE "*emergency*"
| KEEP @timestamp, user.name, event.outcome, azure.signinlogs.properties.status.error_code, source.ip, source.geo.country_iso_code,
       source.as.organization.name, azure.signinlogs.properties.app_display_name, azure.signinlogs.category, user_agent.original
```
Replace the UPNs with the exact break-glass accounts. Do not rely on the name patterns alone.

## Known false positives / exclusions
- Quarterly break-glass validation tests. Schedule them and expect the alert; that is the test.

## Triage
- Phone the identity lead. If no declared emergency, this is a tenant-compromise incident: rotate the break-glass credentials, review everything that account did (C-series), and find how the credential leaked.

## Test
Sign in with a break-glass account during a scheduled validation window.
