---
id: S09
name: Sign-in attempts against disabled or leaver accounts
category: entra-signin
status: todo
severity: medium
language: esql
index: logs-azure.signinlogs-*
mitre: [T1078.004, T1110]
data_source: Entra ID sign-in logs
suppression:
  fields: [source.ip]
  duration: 24h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
Nobody legitimately signs in as a disabled account. Repeated attempts against one, or one source trying several, means a credential from a breach dump or a departed employee is being tested. It is also your earliest sign that a leaver's password is circulating, before it is tried against their new identity elsewhere.

## Query
```esql
FROM logs-azure.signinlogs-*
| EVAL ec = TO_STRING(azure.signinlogs.properties.status.error_code), usr = TO_LOWER(user.name)
| WHERE ec == "50057"                                   // user account is disabled
| STATS attempts = COUNT(*), disabled_users = COUNT_DISTINCT(usr), users = VALUES(usr), asns = VALUES(source.as.organization.name), where_from = VALUES(source.geo.country_iso_code)
    BY source.ip, BUCKET(@timestamp, 1 hour)
| WHERE attempts >= 5 OR disabled_users >= 3
```
Companion (per-account view): `STATS ... BY usr` with `attempts >= 5` catches a single leaver account being hammered from rotating IPs.

## Suppression
Suppress by `source.ip` for 24h. Alerts missing a key field are not suppressed. Aggregating rule. Credential testing runs for hours.

## Known false positives / exclusions
- Mobile devices and mail clients of a just-offboarded user retrying cached credentials for a day or two. Exclude attempts within 48 hours of the disable date using the audit log, or accept them as expected noise.

## Triage
- Confirm the account is a leaver; if the attempts come from outside the leaver's known devices, treat the password as breached and check the user's other accounts (personal password reuse is the usual story).

## Test
Attempt to sign in as a disabled lab account several times.
