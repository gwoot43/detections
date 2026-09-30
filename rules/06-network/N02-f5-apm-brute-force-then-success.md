---
id: N02
name: F5 APM VPN brute force or spray followed by success
category: network
status: todo
severity: high
language: esql
index: logs-f5.apm-*
mitre: [T1110, T1133]
data_source: F5 APM access logs
---
## Why this is high fidelity
Internet-facing VPN portals are sprayed constantly. The alert is not the failures, it is a source or a targeted account that fails repeatedly and then succeeds, or one source failing against many accounts (spray) with any success in the window.

## Query
```esql
FROM logs-f5.apm-*
| EVAL usr = TO_LOWER(COALESCE(user.name, f5.apm.username)),
       ok = CASE(TO_LOWER(COALESCE(f5.apm.result, "")) IN ("allow", "successful", "success") OR event.outcome == "success", 1, 0),
       fail = CASE(TO_LOWER(COALESCE(f5.apm.result, "")) IN ("deny", "failed", "failure") OR event.outcome == "failure", 1, 0)
| STATS fails = SUM(fail), successes = SUM(ok),
        failed_users = COUNT_DISTINCT(CASE(fail == 1, usr, NULL)),
        succeeded_users = VALUES(CASE(ok == 1, usr, NULL)),
        first_success = MIN(CASE(ok == 1, @timestamp, NULL)),
        last_fail = MAX(CASE(fail == 1, @timestamp, NULL))
    BY source.ip, BUCKET(@timestamp, 30 minutes)
| WHERE (fails >= 10 AND successes >= 1) OR (failed_users >= 8 AND successes >= 1)
```

## Known false positives / exclusions
- A user with a stale saved password retrying then fixing it. The multi-user (spray) branch avoids this. For the single-source branch, require the success account to be one of the failed accounts.

## Triage
- Treat the succeeded account as compromised until confirmed. Terminate the session, reset, and correlate with I05 (same spray may hit Entra too).

## Test
Fail the VPN logon several times then succeed with a lab account from one source.
