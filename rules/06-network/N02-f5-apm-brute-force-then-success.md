---
id: N02
name: F5 APM VPN brute force or spray followed by success
category: network
status: todo
language: esql
index: logs-f5.apm-*
mitre: [T1110, T1133]
data_source: F5 APM access logs
suppression:
  fields: [source.ip]
  duration: 4h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
Internet-facing VPN portals are sprayed constantly. The alert is not the failures, it is a source or a targeted account that fails repeatedly and then succeeds, or one source failing against many accounts (spray) with any success in the window.

## Prerequisite
The stock Elastic F5 BIG-IP integration (`f5_bigip`, data stream `logs-f5_bigip.log-*`) cannot feed this query as written:
- It parses APM only from F5 Telemetry Streaming JSON (`telemetryEventCategory: APM`). APM syslog lines such as "Access policy result: Network_Access" are not parsed. They fail the JSON step, so the document gets `event.kind: pipeline_error` and the raw line is kept only in `event.original`. There is no `message` field.
- APM events have no username field.
- The client IP and the policy result are on separate records. Request records carry the client IP (`source.ip`, with GeoIP in `source.geo` and `source.as`). Session records carry `f5_bigip.log.session.id`, `f5_bigip.log.access.profile` and the result in `f5_bigip.log.access.policy_result` (for example `Logon_Deny`).
- The integration never sets `event.outcome` on APM events.

This rule needs a custom ingest pipeline (`logs-f5_bigip.log@custom`, which can parse `event.original`) or a custom syslog integration. That parser has to put the session ID, user, client IP and policy result on each APM event. The index and field names in the query are the target names for that parser: `logs-f5.apm-*`, `f5.apm.result`, `f5.apm.username`/`user.name`, `event.outcome` and `source.ip`. If you use the `@custom` pipeline, the data stays in `logs-f5_bigip.log-*`, so change the `FROM` line to match.

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

## Suppression
Suppress by `source.ip` for 4h. Alerts missing a key field are not suppressed. Aggregating rule. Spray campaigns run for hours.

## Known false positives / exclusions
- A user with a stale saved password retrying then fixing it. The multi-user (spray) branch avoids this. For the single-source branch, require the success account to be one of the failed accounts.

## Triage
- Treat the succeeded account as compromised until confirmed. Terminate the session, reset, and correlate with S13-S15 (same spray may hit Entra too) and I05 (on-premises AD).

## Test
Fail the VPN logon several times then succeed with a lab account from one source.
