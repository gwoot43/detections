---
id: S11
name: Help-desk MFA reset followed by sign-in from a new location
category: entra-signin
status: todo
severity: high
language: esql
index: logs-azure.*
mitre: [T1098.005, T1621, T1078.004]
data_source: Entra ID audit logs (admin MFA reset) + sign-in logs, joined on user
suppression:
  fields: [usr]
  duration: 24h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
The Scattered Spider pattern: call the help desk, impersonate a user, get MFA reset, then sign in from attacker infrastructure. An admin resetting or re-registering a user's MFA method, followed within an hour by that user signing in from a new country or network, is the sequence. Either half alone is routine; together they are account takeover.

## Query (pattern)
```esql
FROM logs-azure.signinlogs-* METADATA _id, _index, _version
| WHERE @timestamp > NOW() - 1 hour
  AND TO_STRING(azure.signinlogs.properties.status.error_code) == "0"
| EVAL usr = TO_LOWER(user.name)
| LOOKUP JOIN mfa_admin_resets_last_2h ON usr
| WHERE reset_at IS NOT NULL AND @timestamp >= reset_at
  AND source.geo.country_iso_code != home_country       // new country vs the user's baseline
| KEEP @timestamp, usr, source.ip, source.geo.country_iso_code, source.as.organization.name, reset_by, reset_at, home_country
```
Build `mfa_admin_resets_last_2h` from the audit log: operations where an admin (not the user) resets or registers MFA for another user (fields `usr`, `reset_at`, `reset_by`). Add `home_country` from the user's usual sign-in country via an enrich policy. If LOOKUP JOIN is unavailable, implement as an Elastic indicator-match rule: indicator = admin MFA resets, events = sign-ins, match on user, 1-hour look-back.

## Suppression
Suppress by `usr` for 24h. Alerts missing a key field are not suppressed. Correlation rule; suppression stops repeated matches for the same reset.

## Known false positives / exclusions
- A genuine user who had MFA reset and then travelled. Rare within an hour. Requiring a new country plus a hosting or unfamiliar ASN reduces it further.

## Triage
- Call the user on a known number. If they did not request the reset, revoke sessions and tokens, reset credentials, remove attacker MFA methods (I10), and review the help-desk verification process.

## Test
On a lab account, have an admin reset MFA, then sign in from a different country via VPN within the hour.
