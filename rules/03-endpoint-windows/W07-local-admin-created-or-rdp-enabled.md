---
id: W07
name: Local account created, added to Administrators, or RDP enabled by command line
category: endpoint-windows
status: todo
severity: high
language: esql
index: logs-yourorg-crowdstrike-data-default*
mitre: [T1136.001, T1098, T1021.001, T1686.003]
data_source: CrowdStrike FDR ProcessRollup2
suppression:
  fields: [host.id, user.name]
  duration: 1h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
Hands-on-keyboard intruders create a local backdoor admin and turn on RDP on the hosts they land on. On a managed estate these actions come from Intune, LAPS or the imaging pipeline, all of which have a recognisable parent.

## Query
```esql
FROM logs-yourorg-crowdstrike-data-default* METADATA _id, _index, _version
| WHERE event.action == "processrollup2" AND host.os.type == "windows"
| EVAL pname = TO_LOWER(process.name), cmd = TO_LOWER(process.command_line), parent = TO_LOWER(COALESCE(process.parent.name, ""))
| WHERE (pname IN ("net.exe", "net1.exe") AND ((cmd LIKE "* user *" AND cmd LIKE "*/add*") OR (cmd LIKE "*localgroup*" AND cmd LIKE "*/add*" AND (cmd LIKE "*administrators*" OR cmd LIKE "*remote desktop users*"))))
   OR (pname IN ("powershell.exe", "pwsh.exe") AND (cmd LIKE "*new-localuser*" OR (cmd LIKE "*add-localgroupmember*" AND cmd LIKE "*administrators*")))
   // writes only: inventory scripts query these values constantly
   OR (pname == "reg.exe" AND cmd LIKE "* add *" AND cmd LIKE "*fdenytsconnections*" AND cmd LIKE "*/d 0*")
   OR (pname == "netsh.exe" AND cmd LIKE "*advfirewall*" AND cmd LIKE "*state off*")
   OR (pname IN ("powershell.exe", "pwsh.exe") AND cmd LIKE "*set-netfirewallprofile*" AND cmd LIKE "*enabled false*")
   OR (pname == "reg.exe" AND cmd LIKE "* add *" AND cmd LIKE """*specialaccounts\\userlist*""")
// net.exe re-launches itself as net1.exe; keep only the net.exe event
| WHERE NOT (pname == "net1.exe" AND parent == "net.exe")
| WHERE parent NOT IN ("ccmexec.exe", "intunemanagementextension.exe", "agentexecutor.exe")
| EVAL user.name = TO_LOWER(MV_LAST(SPLIT(user.name, "\\")))
| KEEP @timestamp, host.id, host.name, user.name, parent, pname, process.command_line, _id, _version, _index
```

**CrowdStrike (Falcon LogScale / Advanced Event Search)**
```logscale
#event_simpleName=/^(ProcessRollup2|SyntheticProcessRollup2)$/ event_platform=Win
| case {
    FileName=/^(net|net1)\.exe$/i CommandLine=/ user /i CommandLine=/\/add/i;
    FileName=/^(net|net1)\.exe$/i CommandLine=/localgroup/i CommandLine=/\/add/i CommandLine=/administrators|remote desktop users/i;
    FileName=/^(powershell|pwsh)\.exe$/i CommandLine=/new-localuser/i;
    FileName=/^(powershell|pwsh)\.exe$/i CommandLine=/add-localgroupmember/i CommandLine=/administrators/i;
    // writes only: inventory scripts query these values constantly
    FileName=/^reg\.exe$/i CommandLine=/ add /i CommandLine=/fdenytsconnections/i CommandLine=/\/d 0/i;
    FileName=/^netsh\.exe$/i CommandLine=/advfirewall/i CommandLine=/state off/i;
    FileName=/^(powershell|pwsh)\.exe$/i CommandLine=/set-netfirewallprofile/i CommandLine=/enabled false/i;
    FileName=/^reg\.exe$/i CommandLine=/ add /i CommandLine=/specialaccounts\\userlist/i;
  }
// net.exe re-launches itself as net1.exe; keep only the net.exe event
| NOT (FileName=/^net1\.exe$/i AND ParentBaseFileName=/^net\.exe$/i)
| !in(field="ParentBaseFileName", ignoreCase=true, values=["ccmexec.exe", "intunemanagementextension.exe", "agentexecutor.exe"])
| table([@timestamp, aid, ComputerName, UserName, ParentBaseFileName, FileName, CommandLine])
```

## Suppression
Suppress by `host.id`, `user.name` for 1h. Alerts missing a key field are not suppressed. Account creation, group add and RDP enable usually come together. `host.id` is the Falcon agent ID and is always present; `host.name` is filled only when the integration's host metadata enrichment is on. `user.name` is reduced to the bare, lowercased account name, since enrichment writes either `DOMAIN\user` or `user`.

## Known false positives / exclusions
- Imaging and onboarding scripts. SCCM and Intune agents are excluded by parent; add your imaging tool's parent the same way.
- Helpdesk enabling RDP for remote support. Ticket-gated.
- `reg query` of the RDP and hidden-account values is not matched; only writes are.

## Triage
- Confirm the account exists, disable it, check 4624 for its use, check W08 for lateral movement from the host.

## Test
Run the Atomic Red Team T1136.001 test on a lab host, then remove the account.
