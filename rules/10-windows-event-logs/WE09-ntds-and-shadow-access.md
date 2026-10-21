---
id: WE09
name: NTDS.dit access, volume shadow copy creation, or ntdsutil on a domain controller
category: windows-events
status: todo
language: esql
index: logs-yourorg-crowdstrike-data-default*, logs-system.security*, logs-windows.forwarded*
mitre: [T1003.003]
data_source: CrowdStrike FDR ProcessRollup2 (DCs) and Windows Security 4656/4663 on NTDS
suppression:
  fields: [host.name]
  duration: 1h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
The AD database (`ntds.dit`) holds every password hash. Attackers copy it by making a volume shadow copy and reading the file, or with `ntdsutil ifm`, `vssadmin create shadow`, `esentutl`, or `diskshadow` on a DC. These commands on a domain controller are made by backup software (known) and attackers (everything else).

## Query
```esql
FROM logs-yourorg-crowdstrike-data-default* METADATA _id, _index, _version
| WHERE event.action == "processrollup2" AND host.os.type == "windows"
  AND (TO_LOWER(host.name) LIKE "dc*" OR TO_LOWER(host.name) LIKE "*-dc*")
| EVAL pname = TO_LOWER(process.name), cmd = TO_LOWER(process.command_line)
| WHERE (pname == "ntdsutil.exe" AND (cmd LIKE "*ifm*" OR cmd LIKE "*create full*" OR cmd LIKE "*ac i ntds*"))
   OR (pname == "vssadmin.exe" AND cmd LIKE "*create shadow*")
   OR (pname == "diskshadow.exe" AND (cmd LIKE "*create*" OR cmd LIKE "*expose*" OR cmd LIKE "*/s *"))
   OR (pname == "esentutl.exe" AND cmd LIKE "*ntds*")
   OR (pname IN ("cmd.exe", "powershell.exe", "pwsh.exe", "robocopy.exe", "xcopy.exe") AND cmd LIKE "*ntds.dit*")
   OR (pname IN ("cmd.exe", "powershell.exe", "pwsh.exe", "robocopy.exe", "xcopy.exe", "esentutl.exe")
       AND cmd LIKE "*harddiskvolumeshadowcopy*")   // copying files (ntds.dit, the SYSTEM hive) out of a shadow copy
   OR (pname == "reg.exe" AND cmd LIKE "*save*" AND (cmd LIKE """*hklm\\system*""" OR cmd LIKE """*hklm\\sam*""" OR cmd LIKE """*hklm\\security*"""))
| KEEP @timestamp, host.name, user.name, process.parent.name, pname, process.command_line, _id, _version, _index
```

**CrowdStrike (Falcon LogScale / Advanced Event Search)**
```logscale
#event_simpleName=/^(ProcessRollup2|SyntheticProcessRollup2)$/ event_platform=Win ComputerName=/^dc|-dc/i
| case {
    FileName=/^ntdsutil\.exe$/i CommandLine=/ifm|create full|ac i ntds/i;
    FileName=/^vssadmin\.exe$/i CommandLine=/create shadow/i;
    FileName=/^diskshadow\.exe$/i CommandLine=/create|expose|\/s /i;
    FileName=/^esentutl\.exe$/i CommandLine=/ntds/i;
    FileName=/^(cmd|powershell|pwsh|robocopy|xcopy)\.exe$/i CommandLine=/ntds\.dit/i;
    FileName=/^(cmd|powershell|pwsh|robocopy|xcopy|esentutl)\.exe$/i CommandLine=/harddiskvolumeshadowcopy/i;
    FileName=/^reg\.exe$/i CommandLine=/save/i CommandLine=/hklm\\(system|sam|security)/i;
  }
| select([@timestamp, aid, ComputerName, UserName, ParentBaseFileName, FileName, CommandLine])
```

Companion via the Security channel: 4656/4663 (object access) on the `ntds.dit` file by a process other than `lsass.exe` or the backup agent, if you audit that file's SACL.

## Suppression
Suppress by `host.name` for 1h. Alerts missing a key field are not suppressed. Copying the AD database takes several commands.

## Known false positives / exclusions
- Backup software creating shadow copies on DCs on schedule. Exclude by the backup service parent and expected schedule. `reg save` of SAM/SYSTEM is never routine on a DC.

## Triage
- This is domain-hash theft. Assume krbtgt and every account hash is compromised; begin AD recovery planning (double krbtgt reset). Find how the actor reached the DC.

## Test
Create an install-from-media (IFM) set with `ntdsutil` on a lab DC, then delete it.
