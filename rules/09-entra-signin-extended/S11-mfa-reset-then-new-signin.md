---
id: S11
name: Help-desk MFA reset followed by sign-in from a new location
category: entra-signin
status: todo
severity: high
language: esql
index: logs-azure.signinlogs-*, logs-azure.auditlogs-*
mitre: [T1098.005, T1621, T1078.004]
data_source: Entra ID audit logs (admin MFA method change) + interactive sign-in logs, joined on user object ID
suppression:
  fields: [uid]
  duration: 24h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
The Scattered Spider pattern: call the help desk, impersonate a user, get MFA reset or a Temporary Access Pass issued, then sign in from attacker infrastructure. An admin registering, changing or deleting a user's authentication method, followed within about two hours by that user signing in from a country they have not signed in from all week, is the sequence. Either half alone is routine; together they are account takeover.

## Query
Run every 15 minutes with a 7-day lookback.
```esql
FROM logs-azure.signinlogs-*, logs-azure.auditlogs-*
| WHERE (data_stream.dataset == "azure.auditlogs"
         AND azure.auditlogs.operation_name IN ("Admin registered security info", "Admin updated security info", "Admin deleted security info")
         AND event.outcome == "success")
     OR (data_stream.dataset == "azure.signinlogs"
         AND azure.signinlogs.category == "SignInLogs"
         AND TO_STRING(azure.signinlogs.properties.status.error_code) == "0")
| EVAL is_reset = data_stream.dataset == "azure.auditlogs",
       uid = CASE(is_reset, `azure.auditlogs.properties.target_resources.0.id`, azure.signinlogs.properties.user_id),
       upn = TO_LOWER(CASE(is_reset, `azure.auditlogs.properties.target_resources.0.user_principal_name`, azure.signinlogs.properties.user_principal_name)),
       ctry = CASE(is_reset, "reset", source.geo.country_iso_code)
| WHERE uid IS NOT NULL AND ctry IS NOT NULL
// stage 1: per user and country; a country's first_seen is its first sign-in in the 7-day lookback
| STATS first_seen = MIN(@timestamp), last_seen = MAX(@timestamp),
        ips = VALUES(source.ip), asns = VALUES(source.as.organization.name), u = VALUES(upn),
        admin = VALUES(azure.auditlogs.properties.initiated_by.user.userPrincipalName),
        ops = VALUES(azure.auditlogs.operation_name)
    BY uid, ctry
// stage 2: per user
| STATS reset_at = MAX(CASE(ctry == "reset", last_seen, NULL)),
        newest_country_at = MAX(CASE(ctry != "reset", first_seen, NULL)),
        countries_seen = COUNT(CASE(ctry != "reset", ctry, NULL)),
        countries = VALUES(CASE(ctry != "reset", ctry, NULL)),
        signin_ips = VALUES(CASE(ctry != "reset", ips, NULL)),
        signin_asns = VALUES(CASE(ctry != "reset", asns, NULL)),
        reset_by = VALUES(admin), reset_ops = VALUES(ops), upns = VALUES(u)
    BY uid
// a recent admin change, a country first seen after it, and at least one other country as the baseline
| WHERE reset_at >= NOW() - 2 hours
  AND newest_country_at >= reset_at
  AND countries_seen >= 2
| EVAL reset_to_signin_min = DATE_DIFF("minute", reset_at, newest_country_at)
```
The 7-day lookback is the user's baseline: a country counts as new only if the user has not signed in from it interactively all week. `countries_seen >= 2` keeps out a user with no other sign-ins in the week (back from leave, phone lost, reset by the help desk), where every country would look new. The join uses the user's object ID, which is the first target of the audit record and the `user_id` of the sign-in. Only interactive sign-ins are read, which keeps the 7-day read manageable; check the query time on your tenant.

## Suppression
Suppress by `uid` for 24h. Alerts missing a key field are not suppressed. Correlation rule; suppression stops repeated matches for the same reset.

## Known false positives / exclusions
- A genuine user who had MFA reset and then travelled. Rare within two hours. Check `signin_asns`: a hosting or VPN provider makes it an attack.
- Help-desk staff who register methods for users in bulk during a rollout. Exclude the rollout window, not the help-desk accounts.

## Triage
- Call the user on a known number. If they did not request the reset, revoke sessions and tokens, reset credentials, remove attacker MFA methods (I10), and review the help-desk verification process.

## Test
On a lab account with a week of sign-in history from one country, have an admin register a new method for it, then sign in from a different country via VPN within the hour.
