---
id: WE06
name: Default domain GPO modified, or a GPO given a scheduled task, script or software install
category: windows-events
status: todo
language: esql
index: logs-system.security*, logs-windows.forwarded*
mitre: [T1484.001, T1078.002]
data_source: Windows Security event 5136 (directory object modified) from domain controllers
suppression:
  fields: [actor, dn]
  duration: 1h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
GPO is a domain-wide code-execution and configuration channel. Attackers edit a GPO to push a scheduled task or a script to every machine it applies to (SharpGPOAbuse, pyGPOAbuse), or edit the Default Domain / Default Domain Controllers policy to weaken security. Event 5136 on a `groupPolicyContainer` object captures the change and the actor.

Ordinary GPO edits are frequent and only change the version number in AD; the settings themselves live in SYSVOL, which 5136 cannot see. So the rule keeps two precise cases: any change to the two default policies, and a GPO whose client-side extension list newly includes scheduled tasks, startup or logon scripts, or software installation, which is how code execution is added to a GPO.

## Query
```esql
FROM logs-system.security*, logs-windows.forwarded* METADATA _id, _index, _version
| WHERE event.code == "5136"
| EVAL cls = TO_LOWER(TO_STRING(winlog.event_data.ObjectClass)),
       dn = TO_LOWER(TO_STRING(winlog.event_data.ObjectDN)),
       attr = TO_LOWER(TO_STRING(winlog.event_data.AttributeLDAPDisplayName)),
       val = TO_LOWER(TO_STRING(winlog.event_data.AttributeValue)),
       actor = TO_LOWER(COALESCE(winlog.event_data.SubjectUserName, "")),
       optype = TO_LOWER(TO_STRING(winlog.event_data.OperationType))
| WHERE cls == "grouppolicycontainer"
  AND optype IN ("%%14674", "value added")         // the new value; the paired "value deleted" event repeats the old one
| EVAL default_policy = dn LIKE "cn={31b2f340-016d-11d2-945f-00c04fb984f9},*"    // Default Domain Policy
                     OR dn LIKE "cn={6ac1786c-016f-11d2-945f-00c04fb984f9},*",   // Default Domain Controllers Policy
       exec_extension = attr IN ("gpcmachineextensionnames", "gpcuserextensionnames")
                     AND (val LIKE "*aadced64-746c-4633-a97c-d61349046527*"       // scheduled tasks (preferences)
                          OR val LIKE "*42b5faae-6536-11d2-ae5a-0000f87571e3*"    // startup, shutdown, logon scripts
                          OR val LIKE "*c6dc5466-785a-11d2-84d0-00c04fb169f7*")   // software installation
| WHERE default_policy OR exec_extension
| WHERE NOT (actor IN ("svc-gpo-automation"))   // your sanctioned GPO tooling account, if any
| KEEP @timestamp, winlog.computer_name, actor, dn, attr, val, default_policy, exec_extension, _id, _version, _index
```
5136 needs directory-object auditing with the right SACL on the Policies container. Confirm these events are present before relying on this. The extension list is rewritten only when the set of extensions in a GPO changes, so a GPO that already had scheduled tasks alerts again when another extension is added. The GPT side (SYSVOL file changes to `GptTmpl.inf`, `ScheduledTasks.xml`) is a useful companion via file-integrity monitoring on the DCs.

## Suppression
Suppress by `actor`, `dn` for 1h. Alerts missing a key field are not suppressed. One GPO edit writes many 5136 events.

## Known false positives / exclusions
- The AD engineering team adding a scheduled task, script or software package to a GPO, or editing a default policy. Confirm against change control. Exclude a GPO automation account by name only if all its changes are ticketed.

## Triage
- Read what changed in SYSVOL for that GPO GUID (`ScheduledTasks.xml`, `scripts.ini`, `GptTmpl.inf`); the event only shows that it changed. A scheduled task or startup script added to a broadly linked GPO is mass code execution; a security-setting change to a default policy is defense impairment. Roll back and investigate the actor.

## Test
In a lab, add a benign scheduled task (Group Policy Preferences) to a test GPO, or change a setting in the Default Domain Policy, and confirm the alert.
