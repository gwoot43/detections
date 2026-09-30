---
id: WE09
name: NTDS.dit access, volume shadow copy creation, or ntdsutil on a domain controller
category: windows-events
status: todo
severity: critical
language: esql
index: logs-crowdstrike.fdr-*, logs-windows.security-*
mitre: [T1003.003]
data_source: CrowdStrike FDR ProcessRollup2 (DCs) and Windows Security 4656/4663 on NTDS
---
## Why this is high fidelity
The AD database (`ntds.dit`) holds every password hash. Attackers copy it by making a volume shadow copy and reading the file, or with `ntdsutil ifm`, `vssadmin create shadow`, `esentutl`, or `diskshadow` on a DC. These commands on a domain controller are made by backup software (known) and attackers (everything else).

## Query
```esql
FROM logs-crowdstrike.fdr-* METADATA _id, _index, _version
| WHERE event.action == "ProcessRollup2" AND host.os.type == "windows"
  AND (TO_LOWER(host.name) LIKE "dc*" OR TO_LOWER(host.name) LIKE "*-dc*")
| EVAL pname = TO_LOWER(process.name), cmd = TO_LOWER(process.command_line)
| WHERE (pname == "ntdsutil.exe" AND (cmd LIKE "*ifm*" OR cmd LIKE "*create full*" OR cmd LIKE "*ac i ntds*"))
   OR (pname == "vssadmin.exe" AND cmd LIKE "*create shadow*")
   OR (pname == "diskshadow.exe" AND (cmd LIKE "*create*" OR cmd LIKE "*expose*" OR cmd LIKE "*/s *"))
   OR (pname == "esentutl.exe" AND cmd LIKE "*ntds*")
   OR (pname IN ("cmd.exe", "powershell.exe", "pwsh.exe", "robocopy.exe", "xcopy.exe", "copy.exe", "esentutl.exe") AND cmd LIKE "*ntds.dit*")
   OR (pname IN ("cmd.exe", "powershell.exe", "pwsh.exe") AND cmd LIKE "*\\system32\\config\\system*" AND cmd LIKE "*save*")   // SYSTEM hive for the boot key
   OR (pname == "reg.exe" AND cmd LIKE "*save*" AND (cmd LIKE "*hklm\\system*" OR cmd LIKE "*hklm\\sam*" OR cmd LIKE "*hklm\\security*"))
| KEEP @timestamp, host.name, user.name, process.parent.name, pname, process.command_line
```
Companion via the Security channel: 4656/4663 (object access) on the `ntds.dit` file by a process other than `lsass.exe` or the backup agent, if you audit that file's SACL.

## Known false positives / exclusions
- Backup software creating shadow copies on DCs on schedule. Exclude by the backup service parent and expected schedule. `reg save` of SAM/SYSTEM is never routine on a DC.

## Triage
- This is domain-hash theft. Assume krbtgt and every account hash is compromised; begin AD recovery planning (double krbtgt reset). Find how the actor reached the DC.

## Test
Run `ntdsutil "ac i ntds" "ifm" "create full C:\temp\ifm" q q` on a lab DC.
