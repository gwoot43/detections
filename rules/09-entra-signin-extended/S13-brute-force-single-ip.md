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
I05 (on-premises) and S15 (Entra) catch sprays across many users. This rule catches the opposite: one IP trying one user many times. Failures are only counted from unregistered devices. That removes the most common benign cause, a stale saved password in an app on a managed laptop or phone. If the same user also signs in successfully from a registered device on that IP in the window, the IP is the user's own network and the row is dropped. Smart Lockout returns 50053 once it starts blocking, so lockout responses are counted as failures too. A response that proves the password was right is never a failure: 50055 (password expired), 50074, 50076 and 50079 (MFA required or registration interrupted) and 53003 (Conditional Access block) all come after a correct password, so they count as a landing alongside a full success (0).

## Query
Run every 15 minutes with a 1-hour lookback.
```esql
FROM logs-azure.signinlogs-*
| WHERE event.dataset == "azure.signinlogs" AND azure.signinlogs.category == "SignInLogs"
| EVAL ec = TO_STRING(azure.signinlogs.properties.status.error_code),
       usr = TO_LOWER(user.name),
       trust = COALESCE(TO_STRING(azure.signinlogs.properties.device_detail.trust_type), "")
// failed: wrong password, locked, null password. ok: the password was right, even if expiry, MFA
// or Conditional Access then stopped the sign-in (0, 50055, 50074, 50076, 50079, 53003)
| EVAL failed = CASE(ec IN ("50126", "50053", "50056") AND trust == "", 1, 0),
       ok = CASE(ec IN ("0", "50055", "50074", "50076", "50079", "53003"), 1, 0)
| WHERE failed == 1 OR ok == 1
| STATS failures = SUM(failed), successes = SUM(ok),
        managed_successes = SUM(CASE(ok == 1 AND trust != "", 1, 0)),
        lockouts = SUM(CASE(ec == "50053", 1, 0)),
        first_fail = MIN(CASE(failed == 1, @timestamp, NULL)),
        last_success = MAX(CASE(ok == 1, @timestamp, NULL)),
        country = VALUES(source.geo.country_iso_code),
        asn = VALUES(source.as.organization.name),
        apps = VALUES(azure.signinlogs.properties.app_display_name),
        uas = VALUES(user_agent.original)
    BY usr, source.ip
| WHERE failures >= 15 AND managed_successes == 0
| EVAL landed = successes > 0 AND last_success >= first_fail
```
`landed` is true when the password is accepted from the same IP after the failures began, whether the sign-in then completed or was stopped by password expiry, MFA or Conditional Access. That is the case to act on first: the attacker has the password.

## Suppression
Suppress by `usr`, `source.ip`, `landed` for 4h. Alerts missing a key field are not suppressed. Aggregating rule. `landed` is in the key so a later success raises a new alert.

## Known false positives / exclusions
- A user with an old password saved in an app on an unregistered personal device at home. When their managed laptop or phone signs in from the same home IP in the window, the row is dropped. If they only use unregistered devices at home, it shows as steady failures from the user's own home IP, often followed by a success from a browser on the same IP, which also sets `landed`. Check the IP's history in Discover before acting.
- Shared NAT or VPN egress IPs, where many users share one IP. The per-user grouping keeps them apart, but exclude your own egress ranges if a broken app causes floods.

## Triage
- Check the IP's ASN and country against the user's usual locations. A hosting provider or a new country is an attack.
- If `landed` is true and the IP is not familiar, revoke sessions and refresh tokens, reset the password, and check for persistence (I10, E06, C05). If the landing was an MFA or Conditional Access interrupt, the password is still known to the attacker; reset it and watch for MFA fatigue (S12).
- If `landed` is false, the account held. Confirm the user's password is strong and that MFA is registered.

## Test
From a lab VM, fail sign-in to a lab account 15 times, then sign in successfully.
