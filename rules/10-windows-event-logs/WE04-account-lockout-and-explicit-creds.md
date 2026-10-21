---
id: WE04
name: Explicit credentials used to log on to many remote hosts from one machine (RunAs / per-connection credential fan-out)
category: windows-events
status: todo
language: esql
index: logs-system.security*, logs-windows.forwarded*
mitre: [T1110, T1078, T1550.002]
data_source: Windows Security event 4648 (logon with explicit credentials)
suppression:
  fields: [host_key]
  duration: 1h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
Event 4648 (a logon using explicitly supplied credentials, the RunAs pattern) at volume from one host, with someone else's credentials, to many remote targets, is credential testing or lateral movement tooling that supplies credentials per connection. The event is logged on the machine the activity comes from, so that machine is the key. Machine accounts, local targets and users supplying their own credentials are dropped.

Account lockout storms (4740) are not used. A spray is caught earlier, and with the source address, by I05's on-premises query on failed logons (4625), before accounts reach the lockout threshold.

## Query
```esql
FROM logs-system.security*, logs-windows.forwarded* METADATA _id, _index, _version
| WHERE event.code == "4648"
| EVAL actor = TO_LOWER(COALESCE(winlog.event_data.SubjectUserName, "")),
       target_acct = TO_LOWER(COALESCE(winlog.event_data.TargetUserName, "")),
       target_host = TO_LOWER(COALESCE(winlog.event_data.TargetServerName, winlog.event_data.TargetInfo, "")),
       host_key = TO_LOWER(MV_FIRST(SPLIT(winlog.computer_name, ".")))   // the host the event came from; with event forwarding, host.name is the collector
// noise: machine accounts, local targets, and users supplying their own credentials
| WHERE NOT ENDS_WITH(actor, "$") AND target_acct != actor
  AND target_host NOT IN ("", "-", "localhost", "127.0.0.1", "::1")
| STATS explicit_cred_events = COUNT(*),
        explicit_targets = COUNT_DISTINCT(target_host),
        accounts_used = VALUES(target_acct)
    BY host_key, BUCKET(@timestamp, 15 minutes)
| WHERE explicit_cred_events >= 20 AND explicit_targets >= 5
```

## Suppression
Suppress by `host_key` for 1h. Alerts missing a key field are not suppressed. Aggregating rule. Overlapping lookbacks would re-alert.

## Known false positives / exclusions
- Admin scripts that run with `-Credential` against many servers from a jump host. Exclude that `host_key`.

## Triage
- Treat `host_key` as compromised until explained: find who was logged on to it, which accounts were supplied (`accounts_used`), and check the targets for remote execution (W08).

## Test
Run a RunAs or `-Credential` loop against five or more lab hosts from a lab host.
