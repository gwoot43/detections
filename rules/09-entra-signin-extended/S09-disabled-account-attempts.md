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
Nobody legitimately signs in as a disabled account. One source trying several disabled accounts means a credential list from a breach dump or a former employee's records is being tested. It is also your earliest sign that leavers' passwords are circulating, before they are tried against their new identities elsewhere.

A single disabled account retrying from one IP is not counted: that is almost always the leaver's own phone or mail client with a cached password.

## Query
Run hourly with a 6-hour lookback.
```esql
FROM logs-azure.signinlogs-*
| WHERE TO_STRING(azure.signinlogs.properties.status.error_code) == "50057"    // user account is disabled
  AND NOT CIDR_MATCH(source.ip, "203.0.113.0/24")                               // corporate egress
| EVAL usr = TO_LOWER(user.name)
| STATS attempts = COUNT(*), disabled_users = COUNT_DISTINCT(usr), users = VALUES(usr), asns = VALUES(source.as.organization.name), where_from = VALUES(source.geo.country_iso_code)
    BY source.ip
| WHERE disabled_users >= 3
```
Corporate egress is excluded because shared office IPs collect cached-credential retries from several recent leavers at once. The rule window replaces a fixed one-hour `BUCKET`, so slow testing across the hour is still grouped.

## Suppression
Suppress by `source.ip` for 24h. Alerts missing a key field are not suppressed. Aggregating rule. Credential testing runs for hours.

## Known false positives / exclusions
- A shared or kiosk device outside the corporate ranges with several leavers' cached credentials. Exclude its IP after review.
- A per-account view (`STATS ... BY usr` with many source IPs) catches one leaver account tested from rotating IPs, but it also fires on every offboarded user whose phone roams between networks. Run it as a hunt, not a rule.

## Triage
- Confirm the account is a leaver; if the attempts come from outside the leaver's known devices, treat the password as breached and check the user's other accounts (personal password reuse is the usual story).

## Test
From one lab machine outside the corporate ranges, attempt to sign in as three different disabled lab accounts.
