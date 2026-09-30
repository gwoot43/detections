---
id: WE06
name: Group Policy object modified in a sensitive OU or default policy
category: windows-events
status: todo
severity: high
language: esql
index: logs-windows.security-*
mitre: [T1484.001, T1078.002]
data_source: Windows Security event 5136 (directory object modified) from domain controllers
suppression:
  fields: [actor, dn]
  duration: 1h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
GPO is a domain-wide code-execution and configuration channel. Attackers edit a GPO linked high in the tree to push a scheduled task or a script to every machine, or edit the Default Domain / Default Domain Controllers policy to weaken security. Event 5136 on a `groupPolicyContainer` object captures the change and the actor, and GPO edits are made by a small, named team.

## Query
```esql
FROM logs-windows.security-* METADATA _id, _index, _version
| WHERE event.code == "5136"
| EVAL cls = TO_LOWER(TO_STRING(winlog.event_data.ObjectClass)),
       dn = TO_LOWER(TO_STRING(winlog.event_data.ObjectDN)),
       actor = TO_LOWER(COALESCE(winlog.event_data.SubjectUserName, ""))
| WHERE cls == "grouppolicycontainer" OR dn LIKE "*cn=policies,cn=system*"
| WHERE NOT (actor IN ("svc-gpo-automation"))   // your sanctioned GPO tooling account, if any
| KEEP @timestamp, host.name, actor, dn, winlog.event_data.AttributeLDAPDisplayName, winlog.event_data.AttributeValue, message
```
5136 needs directory-object auditing with the right SACL on the Policies container. Confirm these events are present before relying on this. The GPT side (SYSVOL file changes to `GptTmpl.inf`, `ScheduledTasks.xml`) is a useful companion via file-integrity monitoring on the DCs.

## Suppression
Suppress by `actor`, `dn` for 1h. Alerts missing a key field are not suppressed. One GPO edit writes many 5136 events.

## Known false positives / exclusions
- The AD engineering team's routine GPO work. Exclude by actor via a lookup of authorised GPO admins, and confirm against change control.

## Triage
- Read what changed. A scheduled task or startup script added to a broadly linked GPO is mass code execution; a security-setting change to a default policy is defense impairment. Roll back and investigate the actor.

## Test
Edit a benign setting in a lab GPO and confirm the 5136 events appear.
