---
id: WE04
name: Account lockout storm, or credentials used to run as another user at scale
category: windows-events
status: todo
severity: medium
language: esql
index: logs-windows.security-*
mitre: [T1110, T1078, T1550.002]
data_source: Windows Security events 4740 (lockout) and 4648 (explicit credentials)
suppression:
  fields: [host.name]
  duration: 1h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
Two signals. A burst of 4740 lockouts across many accounts is a spray hitting the lockout threshold. Event 4648 (a logon using explicitly supplied credentials, the RunAs pattern) at volume from one host, especially to many targets, is credential testing or pass-the-hash tooling that supplies creds per connection.

## Query
```esql
FROM logs-windows.security-* METADATA _id, _index, _version
| WHERE event.code IN ("4740", "4648")
| EVAL locked = TO_LOWER(COALESCE(winlog.event_data.TargetUserName, "")),
       actor = TO_LOWER(COALESCE(winlog.event_data.SubjectUserName, "")),
       target_acct = TO_LOWER(COALESCE(winlog.event_data.TargetUserName, "")),
       target_host = TO_LOWER(COALESCE(winlog.event_data.TargetServerName, winlog.event_data.TargetInfo, ""))
| STATS lockouts = COUNT(CASE(event.code == "4740", 1, NULL)),
        locked_accounts = COUNT_DISTINCT(CASE(event.code == "4740", locked, NULL)),
        explicit_cred_events = COUNT(CASE(event.code == "4648", 1, NULL)),
        explicit_targets = COUNT_DISTINCT(CASE(event.code == "4648", target_host, NULL)),
        accounts_used = VALUES(CASE(event.code == "4648", target_acct, NULL))
    BY host.name, BUCKET(@timestamp, 15 minutes)
| WHERE locked_accounts >= 5 OR (explicit_cred_events >= 20 AND explicit_targets >= 5)
```

## Suppression
Suppress by `host.name` for 1h. Alerts missing a key field are not suppressed. Aggregating rule. Overlapping lookbacks would re-alert.

## Known false positives / exclusions
- A service account with a stale password causing repeated lockouts of itself. Single-account lockouts are excluded by the distinct-account threshold. Scheduled tasks and scripts that legitimately use 4648 (RunAs) from an admin jump host; exclude that host.

## Triage
- Lockout storm: identify the source (the 4740 caller computer) and the accounts, and correlate with I05. Explicit-credential fan-out: treat the source host as compromised and check W08.

## Test
Trigger several lockouts against lab accounts, or run a RunAs loop from a lab host.
