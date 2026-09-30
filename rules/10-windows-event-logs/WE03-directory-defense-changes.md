---
id: WE03
name: Domain trust, SID History or DSRM password change
category: windows-events
status: todo
severity: critical
language: esql
index: logs-windows.security-*
mitre: [T1484.001, T1134.005, T1098]
data_source: Windows Security events 4706/4716 (trusts), 4765/4766 (SID History), 4794 (DSRM)
suppression: none
---
## Why this is high fidelity
Each of these is a rare, high-impact directory change with no routine business cause: a new or modified domain trust widens the attack surface across forests; SID History added to an account grants inherited privilege silently; the Directory Services Restore Mode password reset (4794) gives an attacker a local admin path on a domain controller. All are attacker persistence and escalation moves.

## Query
```esql
FROM logs-windows.security-* METADATA _id, _index, _version
| WHERE event.code IN ("4706", "4707", "4716", "4765", "4766", "4794")
| EVAL actor = TO_LOWER(COALESCE(winlog.event_data.SubjectUserName, user.name)),
       target = TO_LOWER(COALESCE(winlog.event_data.TargetUserName, ""))
| KEEP @timestamp, host.name, event.code, actor, target, winlog.event_data.TargetDomainName, message
```

## Suppression
None. Trust, SID History and DSRM changes are each rare, distinct actions.

## Known false positives / exclusions
- A planned forest trust during a merger. Ticket-gated. SID History added by an authorised migration tool (ADMT) during a migration window; exclude the migration service account only inside that window.

## Triage
- 4794 (DSRM) on a DC is investigated as a domain-controller compromise. A new trust is confirmed with the directory team and removed if unplanned. SID History on a normal account is stripped and the account treated as compromised.

## Test
Add SID History to a lab account with a migration tool in a lab forest.
