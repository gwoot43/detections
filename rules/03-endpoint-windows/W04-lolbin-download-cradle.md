---
id: W04
name: LOLBIN download cradle or remote script execution
category: endpoint-windows
status: todo
severity: high
language: esql
index: logs-crowdstrike.fdr-*
mitre: [T1105, T1218.005, T1218.010, T1197, T1059.001, T1218.007]
data_source: CrowdStrike FDR ProcessRollup2
---
## Why this is high fidelity
These binary-plus-argument combinations exist to fetch and run remote content and have almost no administrative use on user workstations. Each branch is a known LOLBAS entry.

## Query
```esql
FROM logs-crowdstrike.fdr-* METADATA _id, _index, _version
| WHERE event.action == "ProcessRollup2" AND host.os.type == "windows"
| EVAL pname = TO_LOWER(process.name), cmd = TO_LOWER(process.command_line)
| WHERE (pname == "certutil.exe"  AND (cmd LIKE "*urlcache*" OR cmd LIKE "*-decode*" OR cmd LIKE "*-verifyctl*"))
   OR (pname == "bitsadmin.exe"  AND (cmd LIKE "*transfer*" OR cmd LIKE "*addfile*" OR cmd LIKE "*setnotifycmdline*"))
   OR (pname == "mshta.exe"      AND (cmd LIKE "*http*" OR cmd LIKE "*javascript:*" OR cmd LIKE "*vbscript:*"))
   OR (pname == "regsvr32.exe"   AND (cmd LIKE "*scrobj*" OR cmd LIKE "*/i:http*" OR cmd LIKE "*.sct*"))
   OR (pname == "msiexec.exe"    AND cmd LIKE "*http*" AND (cmd LIKE "*/i*" OR cmd LIKE "*/q*"))
   OR (pname == "rundll32.exe"   AND (cmd LIKE "*javascript:*" OR cmd LIKE "*url.dll*openurl*" OR cmd LIKE "*http*"))
   OR (pname IN ("curl.exe", "wget.exe") AND (cmd LIKE "*-o *" OR cmd LIKE "*--output*") AND (cmd LIKE "*.exe*" OR cmd LIKE "*.dll*" OR cmd LIKE "*.ps1*" OR cmd LIKE "*.bat*" OR cmd LIKE "*.hta*" OR cmd LIKE "*\\temp\\*" OR cmd LIKE "*\\public\\*"))
   OR (pname IN ("powershell.exe", "pwsh.exe") AND (cmd LIKE "*downloadstring*" OR cmd LIKE "*downloadfile*" OR cmd LIKE "*net.webclient*" OR cmd LIKE "*start-bitstransfer*"
                                                   OR (cmd LIKE "*iex*" AND (cmd LIKE "*http*" OR cmd LIKE "*frombase64*"))
                                                   OR cmd LIKE "*-encodedcommand*" OR cmd LIKE "* -enc *" OR cmd LIKE "* -ec *"))
   OR (pname IN ("msbuild.exe", "installutil.exe", "regasm.exe", "regsvcs.exe", "cmstp.exe") AND (cmd LIKE "*http*" OR cmd LIKE "*\\temp\\*" OR cmd LIKE "*\\appdata\\*"))
| KEEP @timestamp, host.name, user.name, process.parent.name, pname, process.command_line
```

## Known false positives / exclusions
- Software deployment calling `msiexec /i https://…` from SYSTEM under the deployment agent parent. Exclude by parent process.
- `certutil -urlcache` in some update scripts. Exclude by exact command line.

## Triage
- Same chain as W03: URL, payload, network, then user context.

## Test
Atomic Red Team T1105 and T1218.005 on a lab host.
