---
id: S06
name: On-premises directory synchronization account used outside the Entra Connect server
category: entra-signin
status: todo
severity: critical
language: esql
index: logs-azure.signinlogs-*
mitre: [T1078.004, T1003.006, T1098]
data_source: Entra ID sign-in logs
suppression:
  fields: [usr, source.ip]
  duration: 24h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
The `Sync_<server>_<id>@tenant.onmicrosoft.com` account (and the on-prem `MSOL_` counterpart) can set passwords on any synced user and holds directory-write rights. AADInternals-style attacks extract it from the Entra Connect server and use it from elsewhere. It should sign in from exactly one IP: the Entra Connect server's egress.

## Query
```esql
FROM logs-azure.signinlogs-* METADATA _id, _index, _version
| EVAL usr = TO_LOWER(user.name)
| WHERE (usr LIKE "sync_*@*.onmicrosoft.com" OR usr LIKE "*directory synchronization*" OR usr LIKE "aad_*")
  AND NOT CIDR_MATCH(source.ip, "203.0.113.10/32", "203.0.113.11/32")    // Entra Connect server egress IPs
| KEEP @timestamp, usr, event.outcome, azure.signinlogs.properties.status.error_code, source.ip, source.geo.country_iso_code, source.as.organization.name, azure.signinlogs.properties.app_display_name, user_agent.original
```
Pair with I06 for the on-prem side: the `MSOL_` account logging on (4624) to any host other than the Entra Connect server.

## Suppression
Suppress by `usr`, `source.ip` for 24h. Alerts missing a key field are not suppressed. A stolen sync account is used repeatedly. A new IP still alerts.

## Known false positives / exclusions
- Entra Connect server IP change or a staging-mode second server. Update the CIDR list, do not widen it.

## Triage
- Treat as full hybrid-identity compromise. Reset the sync account (through Entra Connect, not manually), rotate `MSOL_`, review password resets and directory writes in the audit log, and check the Entra Connect server itself for W01/W09.

## Test
Not testable without moving the sync account. Validate that normal sync sign-ins appear only from the expected IPs and would fire from any other.
