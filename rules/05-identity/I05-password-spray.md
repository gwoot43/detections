---
id: I05
name: Password spray across Active Directory or Entra sign-ins
category: identity
status: todo
severity: high
language: esql
index: logs-*
mitre: [T1110.003]
data_source: Windows Security event 4625 (on-prem) and Entra sign-in logs (cloud)
---
## Why this is high fidelity
Spray is defined by breadth, not depth: one source failing against many distinct accounts with few attempts each, so it stays under per-account lockout. Alerting on the breadth, and especially on a spray that is followed by a success, is far higher fidelity than per-account failure counting.

## Query (Entra)
```esql
FROM logs-azure.signinlogs-* METADATA _id, _index, _version
| EVAL err = TO_STRING(azure.signinlogs.properties.status.error_code), usr = TO_LOWER(user.name)
| WHERE event.dataset == "azure.signinlogs"
| EVAL failed = CASE(err == "50126" OR err == "50053" OR err == "50055" OR err == "50056", 1, 0),   // bad password / locked / expired
       success = CASE(err == "0", 1, 0)
| STATS failed_users = COUNT_DISTINCT(CASE(failed == 1, usr, NULL)),
        succeeded_users = VALUES(CASE(success == 1, usr, NULL)),
        total_fail = SUM(failed), total_success = SUM(success)
    BY source.ip, BUCKET(@timestamp, 30 minutes)
| WHERE failed_users >= 10
```
Escalate to critical when `succeeded_users` is non-empty in the same bucket: that is a spray that landed.

## Query (on-prem 4625)
```esql
FROM logs-windows.security-*
| WHERE event.code == "4625"
| STATS failed_users = COUNT_DISTINCT(TO_LOWER(winlog.event_data.TargetUserName))
    BY source.ip, BUCKET(@timestamp, 30 minutes)
| WHERE failed_users >= 10
```

## Known false positives / exclusions
- A misconfigured application or a shared kiosk retrying stale credentials against many accounts. Exclude by source IP after confirming.
- Corporate NAT egress making many users look like one IP for the Entra query. Prefer `source.ip` after Entra's proxy stripping, or pivot on `autonomous_system` for hosting ranges.

## Triage
- If a success is in the bucket, treat that account as compromised: revoke sessions, reset password, check for E06 inbox rules and C05 consent.

## Test
Validate on historical sign-in data or run a controlled spray against lab accounts.
