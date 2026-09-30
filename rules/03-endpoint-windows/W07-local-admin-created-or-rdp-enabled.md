---
id: W07
name: Local account created, added to Administrators, or RDP enabled by command line
category: endpoint-windows
status: todo
severity: high
language: esql
index: logs-crowdstrike.fdr-*
mitre: [T1136.001, T1098, T1021.001, T1562.004]
data_source: CrowdStrike FDR ProcessRollup2
suppression:
  fields: [host.name, user.name]
  duration: 1h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
Hands-on-keyboard intruders create a local backdoor admin and turn on RDP on the hosts they land on. On a managed estate these actions come from Intune, LAPS or the imaging pipeline, all of which have a recognisable parent.

## Query
```esql
FROM logs-crowdstrike.fdr-* METADATA _id, _index, _version
| WHERE event.action == "ProcessRollup2" AND host.os.type == "windows"
| EVAL pname = TO_LOWER(process.name), cmd = TO_LOWER(process.command_line), parent = TO_LOWER(process.parent.name)
| WHERE (pname IN ("net.exe", "net1.exe") AND ((cmd LIKE "*user*" AND cmd LIKE "*/add*") OR (cmd LIKE "*localgroup*" AND cmd LIKE "*/add*" AND (cmd LIKE "*administrators*" OR cmd LIKE "*remote desktop users*"))))
   OR (pname IN ("powershell.exe", "pwsh.exe") AND (cmd LIKE "*new-localuser*" OR (cmd LIKE "*add-localgroupmember*" AND cmd LIKE "*administrators*")))
   OR (pname == "reg.exe" AND cmd LIKE "*fdenytsconnections*")
   OR (pname == "netsh.exe" AND cmd LIKE "*advfirewall*" AND cmd LIKE "*off*")
   OR (pname IN ("powershell.exe", "pwsh.exe") AND cmd LIKE "*set-netfirewallprofile*" AND cmd LIKE "*enabled false*")
   OR (pname == "reg.exe" AND cmd LIKE "*specialaccounts\\userlist*")
| WHERE NOT (parent IN ("ccmexec.exe", "intunemanagementextension.exe", "agentexecutor.exe"))
| KEEP @timestamp, host.name, user.name, parent, pname, process.command_line
```

## Suppression
Suppress by `host.name`, `user.name` for 1h. Alerts missing a key field are not suppressed. Account creation, group add and RDP enable usually come together.

## Known false positives / exclusions
- Imaging and onboarding scripts. Exclude by parent (deployment agent) plus SYSTEM.
- Helpdesk enabling RDP for remote support. Ticket-gated.

## Triage
- Confirm the account exists, disable it, check 4624 for its use, check W08 for lateral movement from the host.

## Test
Atomic Red Team T1136.001 on a lab host.
