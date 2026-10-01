---
id: S14
name: Distributed brute force against one account from many IPs
category: entra-signin
status: todo
severity: high
language: esql
index: logs-azure.signinlogs-*
mitre: [T1110.001, T1090.002]
data_source: Entra ID interactive sign-in logs
suppression:
  fields: [usr, landed]
  duration: 4h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
Attackers route guesses against one account through residential proxy networks so that each IP makes only one or two attempts. Per-IP rules such as S13 never see enough from one address. Grouping by the account instead shows the real pattern: many failures from many unrelated IPs and networks in a few hours. A real user does not fail from ten different networks in one afternoon.

## Query
Run every 30 minutes with a 4-hour lookback.
```esql
FROM logs-azure.signinlogs-*
| WHERE event.dataset == "azure.signinlogs" AND azure.signinlogs.category == "SignInLogs"
| EVAL ec = TO_STRING(azure.signinlogs.properties.status.error_code),
       usr = TO_LOWER(user.name),
       trust = COALESCE(TO_STRING(azure.signinlogs.properties.device_detail.trust_type), "")
| EVAL failed = CASE(ec IN ("50126", "50053", "50055", "50056") AND trust == "", 1, 0),
       ok_unreg = CASE(ec == "0" AND trust == "", 1, 0)
| WHERE failed == 1 OR ok_unreg == 1
| STATS failures = SUM(failed),
        fail_ips = COUNT_DISTINCT(CASE(failed == 1, source.ip, NULL)),
        fail_asns = COUNT_DISTINCT(CASE(failed == 1, source.as.organization.name, NULL)),
        fail_countries = COUNT_DISTINCT(CASE(failed == 1, source.geo.country_iso_code, NULL)),
        successes = SUM(ok_unreg),
        first_fail = MIN(CASE(failed == 1, @timestamp, NULL)),
        last_success = MAX(CASE(ok_unreg == 1, @timestamp, NULL)),
        sample_ips = VALUES(CASE(failed == 1, source.ip, NULL)),
        uas = VALUES(CASE(failed == 1, user_agent.original, NULL))
    BY usr
| WHERE failures >= 20 AND fail_ips >= 10
| EVAL landed = successes > 0 AND last_success >= first_fail,
       sample_ips = MV_SLICE(sample_ips, 0, 19)
```
`landed` only counts successes from unregistered devices, so the real user signing in normally from a managed laptop during the attack does not set it.

## Suppression
Suppress by `usr`, `landed` for 4h. Alerts missing a key field are not suppressed. Aggregating rule. A slow attack spans several runs, and `landed` is in the key so a success raises a new alert.

## Known false positives / exclusions
- A user travelling with a phone that has a stale password, failing across mobile networks and hotel Wi-Fi. It rarely reaches ten distinct IPs in four hours, and the ASN list shows carriers rather than hosting and proxy providers.

## Triage
- Look at `fail_asns` and `sample_ips`. A spread of residential and hosting networks with one or two attempts each is a proxy network.
- If `landed` is true, revoke sessions and refresh tokens, reset the password, and check for persistence (I10, E06, C05).
- If not, the account held. Make sure it has strong MFA, and consider forcing a password change, since targeted accounts are often on a breach list.

## Test
Validate on historical data. Simulating ten or more source networks needs a proxy service you control.
