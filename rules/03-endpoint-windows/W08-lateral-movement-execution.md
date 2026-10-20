---
id: W08
name: Remote execution landing on a host via service, WMI, WinRM, DCOM or remote scheduled task
category: endpoint-windows
status: todo
severity: high
language: esql
index: logs-yourorg-crowdstrike-data-default*
mitre: [T1021.002, T1047, T1021.006, T1021.003, T1053.005, T1569.002]
data_source: CrowdStrike FDR ProcessRollup2
suppression:
  fields: [host.id, user.name]
  duration: 1h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
The parent tells the story. `services.exe` spawning a shell is a service binary that is a shell (PsExec-class tools), and the PsExec-style service binaries themselves (PSEXESVC, PAExec, RemCom, CSExec) starting on a host are matched by name. Service installs from user-writable paths are WE08. `wmiprvse.exe` spawning a shell is remote WMI. `wsmprovhost.exe` is WinRM. `mmc.exe` spawning shells is DCOM (MMC20.Application). Admins use these too, from a small number of jump hosts you can exclude.

The source-side branches (`wmic /node`, `schtasks /s`, `sc \\host`) catch the same moves from the machine that launches them. `dllhost.exe` and PowerShell `Invoke-Command`/`Enter-PSSession` are not matched: both are everyday admin and COM activity, and WinRM execution is already seen on the destination through `wsmprovhost.exe`.

## Query
```esql
FROM logs-yourorg-crowdstrike-data-default* METADATA _id, _index, _version
| WHERE event.action == "processrollup2" AND host.os.type == "windows"
| EVAL parent = TO_LOWER(process.parent.name), child = TO_LOWER(process.name), cmd = TO_LOWER(process.command_line)
| WHERE (parent IN ("wmiprvse.exe", "wsmprovhost.exe", "mmc.exe", "psexesvc.exe", "paexec.exe", "winrshost.exe")
        AND child IN ("cmd.exe", "powershell.exe", "pwsh.exe", "rundll32.exe", "regsvr32.exe", "mshta.exe", "wscript.exe", "cscript.exe", "certutil.exe", "net.exe", "whoami.exe", "reg.exe"))
   OR (parent == "services.exe" AND child IN ("cmd.exe", "powershell.exe", "pwsh.exe", "rundll32.exe"))
   OR child IN ("psexesvc.exe", "paexec.exe", "remcomsvc.exe", "csexecsvc.exe")
   OR (child == "wmic.exe" AND cmd LIKE "*/node:*" AND cmd LIKE "*process call create*")
   OR (child == "schtasks.exe" AND cmd LIKE "*/s *" AND cmd LIKE "*/create*")
   OR (child == "sc.exe" AND cmd LIKE """*\\\\*""" AND (cmd LIKE "*create*" OR cmd LIKE "*start*"))
| EVAL user.name = TO_LOWER(MV_LAST(SPLIT(user.name, "\\")))
| KEEP @timestamp, host.id, host.name, user.name, parent, child, process.command_line, process.parent.entity_id, _id, _version, _index
```

**CrowdStrike (Falcon LogScale / Advanced Event Search)**
```logscale
#event_simpleName=/^(ProcessRollup2|SyntheticProcessRollup2)$/ event_platform=Win
| case {
    in(field="ParentBaseFileName", ignoreCase=true, values=["wmiprvse.exe", "wsmprovhost.exe", "mmc.exe", "psexesvc.exe", "paexec.exe", "winrshost.exe"])
      | in(field="FileName", ignoreCase=true, values=["cmd.exe", "powershell.exe", "pwsh.exe", "rundll32.exe", "regsvr32.exe", "mshta.exe",
                                                     "wscript.exe", "cscript.exe", "certutil.exe", "net.exe", "whoami.exe", "reg.exe"]);
    ParentBaseFileName=/^services\.exe$/i FileName=/^(cmd|powershell|pwsh|rundll32)\.exe$/i;
    in(field="FileName", ignoreCase=true, values=["psexesvc.exe", "paexec.exe", "remcomsvc.exe", "csexecsvc.exe"]);
    FileName=/^wmic\.exe$/i CommandLine=/\/node:/i CommandLine=/process call create/i;
    FileName=/^schtasks\.exe$/i CommandLine=/\/s /i CommandLine=/\/create/i;
    FileName=/^sc\.exe$/i CommandLine=/\\\\/ CommandLine=/create|start/i;
  }
| select([@timestamp, aid, ComputerName, UserName, ParentBaseFileName, FileName, CommandLine, ParentProcessId])
```

## Suppression
Suppress by `host.id`, `user.name` for 1h. Alerts missing a key field are not suppressed. Remote execution tools spawn many processes per session on the destination. `host.id` is the Falcon agent ID and is always present; `host.name` is filled only when the integration's host metadata enrichment is on. `user.name` is reduced to the bare, lowercased account name, since enrichment writes either `DOMAIN\user` or `user`.

## Known false positives / exclusions
- Configuration management and monitoring agents using WMI, and Ansible or other WinRM-driven tooling under `wsmprovhost.exe`. Exclude by the child's exact command line or the service account, not by parent.
- Admin jump hosts as the source. Exclude by `user.name` being an approved admin only when the destination is a server. Workstation-to-workstation is never excluded.

## Triage
- Identify the source (4624 logon type 3 on the destination just before, or the source host's fan-out in B04). Check the source host for W01 and the account for I05.

## Test
Run Sysinternals PsExec against a lab host from a lab admin host.
