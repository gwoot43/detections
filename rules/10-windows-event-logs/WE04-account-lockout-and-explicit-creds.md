---
id: WE04
name: Account lockout storm, or credentials used to run as another user at scale
category: windows-events
status: todo
severity: medium
language: esql
index: logs-system.security*, logs-windows.forwarded*
mitre: [T1110, T1078, T1550.002]
data_source: Windows Security events 4740 (lockout) and 4648 (explicit credentials)
suppression:
  fields: [src_host]
  duration: 1h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
Two signals, both keyed on the machine the activity comes from. A burst of 4740 lockouts across many accounts from one caller computer is a spray hitting the lockout threshold. The lockout is logged on the domain controller, so the caller computer recorded in the event is the key, not the DC. Event 4648 (a logon using explicitly supplied credentials, the RunAs pattern) at volume from one host, with someone else's credentials, to many remote targets, is credential testing or lateral movement tooling that supplies creds per connection.

## Query
```esql
FROM logs-system.security*, logs-windows.forwarded* METADATA _id, _index, _version
| WHERE event.code IN ("4740", "4648")
| EVAL actor = TO_LOWER(COALESCE(winlog.event_data.SubjectUserName, "")),
       target_acct = TO_LOWER(COALESCE(winlog.event_data.TargetUserName, "")),
       target_host = TO_LOWER(COALESCE(winlog.event_data.TargetServerName, winlog.event_data.TargetInfo, "")),
       // 4740: TargetDomainName is the caller computer; 4648: the host the event came from
       src_host = TO_LOWER(MV_FIRST(SPLIT(CASE(event.code == "4740", winlog.event_data.TargetDomainName, winlog.computer_name), ".")))
// 4648 noise: machine accounts, local targets, and users supplying their own credentials
| WHERE event.code == "4740"
   OR (NOT ENDS_WITH(actor, "$") AND target_acct != actor
       AND target_host NOT IN ("", "-", "localhost", "127.0.0.1", "::1"))
| STATS lockouts = COUNT(CASE(event.code == "4740", 1, NULL)),
        locked_accounts = COUNT_DISTINCT(CASE(event.code == "4740", target_acct, NULL)),
        explicit_cred_events = COUNT(CASE(event.code == "4648", 1, NULL)),
        explicit_targets = COUNT_DISTINCT(CASE(event.code == "4648", target_host, NULL)),
        accounts_used = VALUES(CASE(event.code == "4648", target_acct, NULL))
    BY src_host, BUCKET(@timestamp, 15 minutes)
| WHERE locked_accounts >= 5 OR (explicit_cred_events >= 20 AND explicit_targets >= 5)
```

## Suppression
Suppress by `src_host` for 1h. Alerts missing a key field are not suppressed. Aggregating rule. Overlapping lookbacks would re-alert.

## Known false positives / exclusions
- A service account with a stale password causing repeated lockouts of itself. Single-account lockouts are excluded by the distinct-account threshold.
- A mail or web front end (Exchange, ADFS) that relays many users' stale-password lockouts appears as one caller computer. Exclude it inline only after confirming the lockouts are ordinary users.
- Admin scripts that run with `-Credential` against many servers from a jump host. Exclude that `src_host`.

## Triage
- Lockout storm: `src_host` is the caller computer; find who was logged on to it and correlate with I05. Explicit-credential fan-out: treat `src_host` as compromised and check W08.

## Test
Trigger several lockouts against lab accounts, or run a RunAs loop from a lab host.
