---
id: W08
name: Remote execution landing on a host via service, WMI, WinRM, DCOM or remote scheduled task
category: endpoint-windows
status: todo
severity: high
language: esql
index: logs-crowdstrike.fdr-*
mitre: [T1021.002, T1047, T1021.006, T1021.003, T1053.005, T1569.002]
data_source: CrowdStrike FDR ProcessRollup2
---
## Why this is high fidelity
The parent tells the story. `services.exe` spawning a shell is a service binary that is a shell (PsExec-class tools). `wmiprvse.exe` spawning a shell is remote WMI. `wsmprovhost.exe` is WinRM. `mmc.exe` or `dllhost.exe` spawning shells is DCOM. Admins use these too, from a small number of jump hosts you can exclude.

## Query
```esql
FROM logs-crowdstrike.fdr-* METADATA _id, _index, _version
| WHERE event.action == "ProcessRollup2" AND host.os.type == "windows"
| EVAL parent = TO_LOWER(process.parent.name), child = TO_LOWER(process.name), cmd = TO_LOWER(process.command_line)
| WHERE (parent IN ("wmiprvse.exe", "wsmprovhost.exe", "mmc.exe", "dllhost.exe", "psexesvc.exe", "paexec.exe", "winrshost.exe")
        AND child IN ("cmd.exe", "powershell.exe", "pwsh.exe", "rundll32.exe", "regsvr32.exe", "mshta.exe", "wscript.exe", "cscript.exe", "certutil.exe", "net.exe", "whoami.exe", "reg.exe"))
   OR (parent == "services.exe" AND child IN ("cmd.exe", "powershell.exe", "pwsh.exe", "rundll32.exe"))
   OR child IN ("psexesvc.exe", "paexec.exe", "remcomsvc.exe")
   OR (child == "wmic.exe" AND cmd LIKE "*/node:*" AND cmd LIKE "*process call create*")
   OR (child == "schtasks.exe" AND cmd LIKE "*/s *" AND cmd LIKE "*/create*")
   OR (child == "sc.exe" AND cmd LIKE "*\\\\*" AND (cmd LIKE "*create*" OR cmd LIKE "*start*"))
   OR (child IN ("powershell.exe", "pwsh.exe") AND (cmd LIKE "*invoke-command*-computername*" OR cmd LIKE "*enter-pssession*"))
| KEEP @timestamp, host.name, user.name, parent, child, process.command_line, process.parent.command_line
```

## Known false positives / exclusions
- Configuration management and monitoring agents using WMI. Exclude by the child's command line, not by parent.
- Admin jump hosts as the source. Exclude by `user.name` being an approved admin only when the destination is a server. Workstation-to-workstation is never excluded.

## Triage
- Identify the source (4624 logon type 3 on the destination just before, or F05). Check the source host for W01 and the account for I05.

## Test
Run `psexec` to a lab host from a lab admin host.
