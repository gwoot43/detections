---
id: S15
name: Distributed password spray across many accounts and many IPs (client fingerprint)
category: entra-signin
status: todo
severity: high
language: esql
index: logs-azure.signinlogs-*
mitre: [T1110.003, T1090.002]
data_source: Entra ID interactive sign-in logs
suppression:
  fields: [ua, app, landed]
  duration: 4h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
Low-and-slow sprays rotate through thousands of proxy IPs, so no single IP (I05) or single account (S14) stands out. What stays constant is the tool: the same user agent and the same target application on every attempt. Grouping by that client fingerprint lets the spray show up as one pattern: many accounts that fail and never succeed, from many IPs, with only a few attempts per IP.

Ordinary typo failures look different. Users who mistype usually succeed from the same IP minutes later, so they are not counted as failed-only.

## Query
Run every 30 minutes with a 4-hour lookback.
```esql
FROM logs-azure.signinlogs-*
| WHERE event.dataset == "azure.signinlogs" AND azure.signinlogs.category == "SignInLogs"
| EVAL ec = TO_STRING(azure.signinlogs.properties.status.error_code),
       usr = TO_LOWER(user.name),
       trust = COALESCE(TO_STRING(azure.signinlogs.properties.device_detail.trust_type), ""),
       ua = COALESCE(TO_STRING(user_agent.original), "(none)"),
       app = COALESCE(TO_STRING(azure.signinlogs.properties.app_display_name), "(none)")
// 50034 = account does not exist; sprays from username lists hit these often
| EVAL failed = CASE(ec IN ("50126", "50053", "50055", "50056", "50034") AND trust == "", 1, 0),
       ok_unreg = CASE(ec == "0" AND trust == "", 1, 0)
| WHERE failed == 1 OR ok_unreg == 1
// stage 1: per user and IP
| STATS f = SUM(failed), s = SUM(ok_unreg) BY usr, source.ip, ua, app
// stage 2: per IP. failed-only users never succeeded from this IP; success users are possible landings
| STATS ip_failed_users = COUNT_DISTINCT(CASE(f > 0 AND s == 0, usr, NULL)),
        ip_attempts = SUM(f),
        ip_success_users = VALUES(CASE(s > 0, usr, NULL))
    BY source.ip, ua, app
| EVAL spray_ip = CASE(ip_failed_users > 0, 1, 0)
// stage 3: per client fingerprint
| STATS spray_ips = SUM(spray_ip),
        sprayed_users = SUM(ip_failed_users),
        attempts = SUM(ip_attempts),
        landed_users = VALUES(CASE(spray_ip == 1, ip_success_users, NULL))
    BY ua, app
| WHERE spray_ips >= 20 AND sprayed_users >= 30
| EVAL attempts_per_ip = TO_DOUBLE(attempts) / spray_ips
| WHERE attempts_per_ip <= 5
| EVAL landed = COALESCE(MV_COUNT(landed_users), 0) > 0
```
`landed_users` lists accounts that signed in successfully, from an unregistered device, from an IP that was also spraying. Those accounts need immediate response.

Tune `spray_ips`, `sprayed_users` and `attempts_per_ip` on two weeks of history. If the spray tool randomises its user agent, group by `app` alone. The rule stays useful but is noisier.

## Suppression
Suppress by `ua`, `app`, `landed` for 4h. Alerts missing a key field are not suppressed. Aggregating rule. A slow spray spans many runs, and `landed` is in the key so the first success raises a new alert.

## Known false positives / exclusions
- A broken line-of-business app or a password-policy rollout causing many users to fail from many IPs with the same client. Those users usually succeed soon after, which the failed-only logic filters. Check the `app` value before escalating.
- A very common browser user agent combined with the default app. The failed-only and attempts-per-IP conditions are what keep this clean. Do not lower them without checking history.

## Triage
- For each account in `landed_users`, revoke sessions and refresh tokens, reset the password, and check for persistence (I10, E06, C05).
- Block the user agent with Conditional Access if it is not one your users have. Force password resets for sprayed accounts that appear on known breach lists.
- Compare with I07: Identity Protection's password spray detection often fires on the same campaign.

## Test
Validate on historical data. Do not run a spray against production accounts.
