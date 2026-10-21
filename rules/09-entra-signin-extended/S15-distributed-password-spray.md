---
id: S15
name: Password spray across many accounts, from many IPs (client fingerprint) or from one IP
category: entra-signin
status: todo
language: esql
index: logs-azure.signinlogs-*
mitre: [T1110.003, T1090.002]
data_source: Entra ID interactive sign-in logs
suppression:
  fields: [ua, app, tier, landed]
  duration: 4h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
Low-and-slow sprays rotate through thousands of proxy IPs, so no single IP or single account (S13, S14) stands out. What stays constant is the tool: the same user agent and the same target application on every attempt. Grouping by that client fingerprint lets the spray show up as one pattern: many accounts that fail and never succeed, from many IPs, with only a few attempts per IP.

The same query also catches the simple version: one IP failing against many accounts (the `single_ip` tier). It used to sit in I05; it lives here now so one rule owns Entra spraying.

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
// ok_unreg: the password was right, even if expiry, MFA or Conditional Access then stopped the sign-in
| EVAL failed = CASE(ec IN ("50126", "50053", "50056", "50034") AND trust == "", 1, 0),
       ok_unreg = CASE(ec IN ("0", "50055", "50074", "50076", "50079", "53003") AND trust == "", 1, 0)
| WHERE failed == 1 OR ok_unreg == 1
// stage 1: per user and IP
| STATS f = SUM(failed), s = SUM(ok_unreg) BY usr, source.ip, ua, app
// stage 2: per IP. failed-only users never succeeded from this IP; success users are possible landings
| STATS ip_failed_users = VALUES(CASE(f > 0 AND s == 0, usr, NULL)),
        ip_attempts = SUM(f),
        ip_success_users = VALUES(CASE(s > 0, usr, NULL))
    BY source.ip, ua, app
| EVAL spray_ip = CASE(ip_failed_users IS NOT NULL, 1, 0),
       ip_user_count = COALESCE(MV_COUNT(ip_failed_users), 0)
// stage 3: per client fingerprint. COUNT_DISTINCT over the per-IP user lists counts each account once
| STATS spray_ips = SUM(spray_ip),
        sprayed_users = COUNT_DISTINCT(ip_failed_users),
        attempts = SUM(ip_attempts * spray_ip),
        landed_users = VALUES(CASE(spray_ip == 1, ip_success_users, NULL)),
        max_users_one_ip = MAX(ip_user_count),
        single_spray_ips = VALUES(CASE(ip_user_count >= 15, TO_STRING(source.ip), NULL))
    BY ua, app
| EVAL attempts_per_ip = CASE(spray_ips > 0, TO_DOUBLE(attempts) / spray_ips, NULL),
       tier = CASE(spray_ips >= 20 AND sprayed_users >= 30 AND attempts_per_ip <= 5, "distributed",
                   max_users_one_ip >= 15, "single_ip",
                   NULL)
| WHERE tier IS NOT NULL
| EVAL landed = COALESCE(MV_COUNT(landed_users), 0) > 0
```
`landed_users` lists accounts whose password was accepted, from an unregistered device, from an IP that was also spraying. Accepted means a full success (0) or a response that only comes after a correct password: expired (50055), MFA required or interrupted (50074, 50076, 50079) or a Conditional Access block (53003). Those are never counted as failures. Those accounts need immediate response.

`single_spray_ips` lists the IPs that each failed against 15 or more accounts that never signed in from them. Tune `spray_ips`, `sprayed_users`, `attempts_per_ip` and the single-IP threshold of 15 on two weeks of history. If the spray tool randomises its user agent, group by `app` alone. The rule stays useful but is noisier.

## Suppression
Suppress by `ua`, `app`, `tier`, `landed` for 4h. Alerts missing a key field are not suppressed. Aggregating rule. A slow spray spans many runs. `landed` is in the key, so the first success raises a new alert, and `tier` keeps a single-IP spray and a distributed one from hiding each other.

## Known false positives / exclusions
- Single-IP tier: a shared egress (office NAT, VDI or a partner's proxy) where a password change has left many devices retrying an old password. Those users usually succeed from the same IP soon after, which the failed-only logic filters. If one egress keeps appearing, exclude it with `NOT CIDR_MATCH(source.ip, ...)` before the first `STATS`.
- A broken line-of-business app or a password-policy rollout causing many users to fail from many IPs with the same client. Those users usually succeed soon after, which the failed-only logic filters. Check the `app` value before escalating.
- A very common browser user agent combined with the default app. The failed-only and attempts-per-IP conditions are what keep this clean. Do not lower them without checking history.

## Triage
- For each account in `landed_users`, revoke sessions and refresh tokens, reset the password, and check for persistence (I10, E06, C05).
- Block the user agent with Conditional Access if it is not one your users have. Force password resets for sprayed accounts that appear on known breach lists.
- Compare with I07: Identity Protection's password spray detection often fires on the same campaign.

## Test
Validate on historical data. Do not run a spray against production accounts.
