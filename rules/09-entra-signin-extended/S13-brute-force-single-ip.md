---
id: S13
name: Brute force against one account from a single IP
category: entra-signin
status: todo
severity: high
language: esql
index: logs-azure.signinlogs-*
mitre: [T1110.001]
data_source: Entra ID interactive sign-in logs
suppression:
  fields: [usr, source.ip, landed]
  duration: 4h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
I05 catches one IP trying many users. This rule catches the opposite: one IP trying one user many times. Failures are only counted from unregistered devices. That removes the most common benign cause, a stale saved password in an app on a managed laptop or phone. Smart Lockout returns 50053 once it starts blocking, so lockout responses are counted as failures too.

## Query
Run every 15 minutes with a 1-hour lookback.
```esql
FROM logs-azure.signinlogs-*
| WHERE event.dataset == "azure.signinlogs" AND azure.signinlogs.category == "SignInLogs"
| EVAL ec = TO_STRING(azure.signinlogs.properties.status.error_code),
       usr = TO_LOWER(user.name),
       trust = COALESCE(TO_STRING(azure.signinlogs.properties.device_detail.trust_type), "")
| EVAL failed = CASE(ec IN ("50126", "50053", "50055", "50056") AND trust == "", 1, 0),
       ok = CASE(ec == "0", 1, 0)
| WHERE failed == 1 OR ok == 1
| STATS failures = SUM(failed), successes = SUM(ok),
        lockouts = SUM(CASE(ec == "50053", 1, 0)),
        first_fail = MIN(CASE(failed == 1, @timestamp, NULL)),
        last_success = MAX(CASE(ok == 1, @timestamp, NULL)),
        country = VALUES(source.geo.country_iso_code),
        asn = VALUES(source.as.organization.name),
        apps = VALUES(azure.signinlogs.properties.app_display_name),
        uas = VALUES(user_agent.original)
    BY usr, source.ip
| WHERE failures >= 15
| EVAL landed = successes > 0 AND last_success >= first_fail
```
`landed` is true when a sign-in succeeds from the same IP after the failures began. That is the case to act on first.

## Suppression
Suppress by `usr`, `source.ip`, `landed` for 4h. Alerts missing a key field are not suppressed. Aggregating rule. `landed` is in the key so a later success raises a new alert.

## Known false positives / exclusions
- A user with an old password saved in an app on an unregistered personal device at home. It shows as steady failures from the user's own home IP, often followed by a success from a browser on the same IP, which also sets `landed`. To remove it, exclude IPs where the user signed in successfully from a registered or compliant device in the past 14 days. Build that as a lookup of familiar user-and-IP pairs and join on it.
- Shared NAT or VPN egress IPs, where many users share one IP. The per-user grouping keeps them apart, but exclude your own egress ranges if a broken app causes floods.

## Triage
- Check the IP's ASN and country against the user's usual locations. A hosting provider or a new country is an attack.
- If `landed` is true and the IP is not familiar, revoke sessions and refresh tokens, reset the password, and check for persistence (I10, E06, C05).
- If `landed` is false, the account held. Confirm the user's password is strong and that MFA is registered.

## Test
From a lab VM, fail sign-in to a lab account 15 times, then sign in successfully.
