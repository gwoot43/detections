---
id: W07
name: Local account created, added to Administrators or Remote Desktop Users, hidden, or RDP turned on
category: endpoint-windows
status: todo
severity: high
language: esql
index: logs-crowdstrike.fdr-*
mitre: [T1136.001, T1098, T1021.001, T1564.002]
data_source: CrowdStrike FDR ProcessRollup2
suppression:
  fields: [host.id, user.name]
  duration: 1h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
Hands-on-keyboard intruders give themselves a way back in: a local account, added to Administrators or Remote Desktop Users, sometimes hidden from the logon screen, with RDP switched on. The command lines are distinctive whichever tool runs them (`net user ... /add`, `net localgroup administrators ... /add`, `New-LocalUser`, `Add-LocalGroupMember`, the `fDenyTSConnections` value set to 0, the `SpecialAccounts\UserList` key).

On a managed fleet these changes come from Intune, SCCM or imaging, which are excluded by parent. `net.exe` starts `net1.exe` to do the work, so the `net1.exe` copy is skipped to alert once.

Turning the firewall off moved to W05 with the other protection changes.

## Query
```esql
FROM logs-crowdstrike.fdr-* METADATA _id, _index, _version
| WHERE event.action == "ProcessRollup2" AND host.os.type == "windows"
| EVAL cmd = TO_LOWER(process.command_line), parent = TO_LOWER(COALESCE(process.parent.name, ""))
| WHERE (cmd LIKE "*/add*" AND (cmd LIKE "* user *" OR cmd LIKE "*localgroup*administrators*"
                                OR cmd LIKE "*localgroup*remote desktop users*"))
     OR cmd LIKE "*new-localuser*" OR cmd LIKE "*add-localgroupmember*administrators*"
     OR (cmd LIKE "*fdenytsconnections*" AND cmd LIKE "*/d 0*")
     OR cmd LIKE "*specialaccounts*userlist*"
| WHERE parent NOT IN ("net.exe", "ccmexec.exe", "intunemanagementextension.exe", "agentexecutor.exe")
| KEEP @timestamp, host.id, host.name, user.name, parent, process.name, process.command_line, _id, _version, _index
```

## Suppression
Suppress by `host.id`, `user.name` for 1h. Alerts missing a key field are not suppressed. Account creation, group add and RDP enable usually come together. `host.id` is the Falcon agent ID and is always present.

## Known false positives / exclusions
- Imaging and onboarding scripts. Add your imaging tool's parent to the exclusion.
- Helpdesk enabling RDP for remote support. Ticket-gated.
- Reading these values (`reg query`) doesn't match; only writes do.

## Triage
- Confirm the account exists, disable it, check 4624 for its use, and check W08 for remote execution from or to the host.

## Test
Run the Atomic Red Team T1136.001 test on a lab host, then remove the account.
