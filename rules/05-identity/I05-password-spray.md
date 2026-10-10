---
id: I05
name: Password spray across Active Directory or Entra sign-ins
category: identity
status: todo
severity: high
language: esql
index: logs-azure.signinlogs-*, logs-system.security*, logs-windows.forwarded*
mitre: [T1110.003]
data_source: Windows Security event 4625 (on-prem) and Entra sign-in logs (cloud)
suppression:
  fields: [source.ip, landed]
  duration: 4h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
Spray is defined by breadth, not depth: one source failing against many distinct accounts with few attempts each, so it stays under per-account lockout. Alerting on the breadth, and especially on a spray that finds a valid password, is far higher fidelity than per-account failure counting.

## Query (Entra)
```esql
FROM logs-azure.signinlogs-*
| WHERE event.dataset == "azure.signinlogs" AND azure.signinlogs.category == "SignInLogs"
| EVAL err = TO_STRING(azure.signinlogs.properties.status.error_code),
       usr = TO_LOWER(user.name),
       trust = COALESCE(TO_STRING(azure.signinlogs.properties.device_detail.trust_type), "")
// failed: bad password, locked, null password. valid: the password was right, even if MFA,
// Conditional Access or password expiry then stopped the sign-in (0, 50055, 50074, 50076, 50079, 53003).
// Both count only from devices that are not Entra-joined or registered, as in S13-S15.
| EVAL failed = CASE(err IN ("50126", "50053", "50056") AND trust == "", 1, 0),
       valid = CASE(err IN ("0", "50055", "50074", "50076", "50079", "53003") AND trust == "", 1, 0)
| STATS failed_users = COUNT_DISTINCT(CASE(failed == 1, usr, NULL)),
        valid_password_users = VALUES(CASE(valid == 1, usr, NULL)),
        total_fail = SUM(failed), total_valid = SUM(valid)
    BY source.ip, BUCKET(@timestamp, 30 minutes)
| WHERE failed_users >= 10
| EVAL landed = total_valid > 0     // part of the suppression key, so a spray that later lands re-alerts
```
Related Entra rules: S13 (one account from one IP), S14 (one account from many IPs), S15 (many accounts from many IPs) and S12 (MFA fatigue, which often follows a successful guess).

Escalate to critical when `valid_password_users` is non-empty in the same bucket: the spray found a working password, whether or not MFA stopped the sign-in.

## Query (on-prem 4625)
```esql
FROM logs-system.security*, logs-windows.forwarded*
| WHERE event.code == "4625" AND source.ip IS NOT NULL
  AND NOT CIDR_MATCH(source.ip, "127.0.0.0/8", "::1/128")       // local logons (IIS, Exchange) carry no remote source
| EVAL acct = TO_LOWER(winlog.event_data.TargetUserName)
| WHERE acct != "" AND acct != "-" AND NOT ENDS_WITH(acct, "$")
| STATS failed_users = COUNT_DISTINCT(acct), dest_hosts = VALUES(winlog.computer_name)
    BY source.ip, BUCKET(@timestamp, 30 minutes)
| WHERE failed_users >= 10
```

## Suppression
Suppress by `source.ip`, `landed` for 4h. Alerts missing a key field are not suppressed. Aggregating rule. The landed flag is in the key so a spray that later finds a valid password raises a new alert. The on-prem query has no `landed` column; suppress it on `source.ip` alone.

## Known false positives / exclusions
- A misconfigured application or a shared kiosk retrying stale credentials against many accounts. Exclude by source IP after confirming.
- Corporate NAT egress making many users look like one IP for the Entra query. Failures from Entra-joined and registered devices are already ignored; exclude any remaining egress IPs inline.
- On-prem: a Citrix, RDS or VPN gateway that relays many users' logons appears as one `source.ip`. Exclude the gateway IPs inline.

## Triage
- If `valid_password_users` is non-empty, treat those accounts as compromised: revoke sessions, reset passwords, check for E06 inbox rules and C05 consent.

## Test
Validate on historical sign-in data or run a controlled spray against lab accounts.
