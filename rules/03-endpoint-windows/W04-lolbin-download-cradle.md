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
suppression:
  fields: [host.id, pname]
  duration: 1h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
These binary-plus-argument combinations exist to fetch and run remote content and have almost no administrative use on user workstations. Each branch is a known LOLBAS entry. The branches that admin tooling also uses (encoded PowerShell, .NET build and registration tools) exclude the management agents and installers that run them by design.

## Query
```esql
FROM logs-crowdstrike.fdr-* METADATA _id, _index, _version
| WHERE event.action == "ProcessRollup2" AND host.os.type == "windows"
| EVAL pname = TO_LOWER(process.name), cmd = TO_LOWER(process.command_line), parent = TO_LOWER(COALESCE(process.parent.name, ""))
| WHERE (pname == "certutil.exe"  AND (cmd LIKE "*urlcache*" OR cmd LIKE "*-decode*" OR cmd LIKE "*-verifyctl*"))
   OR (pname == "bitsadmin.exe"  AND (cmd LIKE "*transfer*" OR cmd LIKE "*addfile*" OR cmd LIKE "*setnotifycmdline*"))
   OR (pname == "mshta.exe"      AND (cmd LIKE "*http*" OR cmd LIKE "*javascript:*" OR cmd LIKE "*vbscript:*"))
   OR (pname == "regsvr32.exe"   AND (cmd LIKE "*scrobj*" OR cmd LIKE "*/i:http*" OR cmd LIKE "*.sct*"))
   OR (pname == "msiexec.exe"    AND cmd LIKE "*http*")
   // rundll32 with a plain URL is how many apps open a browser (url.dll,FileProtocolHandler), so only the script and OpenURL forms count
   OR (pname == "rundll32.exe"   AND (cmd LIKE "*javascript:*" OR cmd LIKE "*url.dll*openurl*"))
   OR (pname IN ("curl.exe", "wget.exe") AND (cmd LIKE "*-o *" OR cmd LIKE "*--output*") AND (cmd LIKE "*.exe*" OR cmd LIKE "*.dll*" OR cmd LIKE "*.ps1*" OR cmd LIKE "*.bat*" OR cmd LIKE "*.hta*" OR cmd LIKE """*\\temp\\*""" OR cmd LIKE """*\\public\\*"""))
   OR (pname IN ("powershell.exe", "pwsh.exe") AND (cmd LIKE "*downloadstring*" OR cmd LIKE "*downloadfile*" OR cmd LIKE "*net.webclient*"
                                                   OR (cmd LIKE "*iex*" AND (cmd LIKE "*http*" OR cmd LIKE "*frombase64*"))))
   // encoded PowerShell, except from the management agents that run encoded scripts by design
   OR (pname IN ("powershell.exe", "pwsh.exe") AND (cmd LIKE "*-encodedcommand*" OR cmd LIKE "* -enc *" OR cmd LIKE "* -ec *" OR cmd LIKE "* -e *")
       AND parent NOT IN ("ccmexec.exe", "intunemanagementextension.exe", "agentexecutor.exe", "windowsazureguestagent.exe", "gc_worker.exe", "wsmprovhost.exe"))
   // .NET LOLBINs loading from user-writable paths; installers (msiexec) and Visual Studio run these legitimately
   OR (pname IN ("msbuild.exe", "installutil.exe", "regasm.exe", "regsvcs.exe", "cmstp.exe") AND (cmd LIKE "*http*" OR cmd LIKE """*\\temp\\*""" OR cmd LIKE """*\\appdata\\*""")
       AND parent NOT IN ("msiexec.exe", "devenv.exe"))
| KEEP @timestamp, host.id, host.name, user.name, process.parent.name, pname, process.command_line
```

## Suppression
Suppress by `host.id`, `pname` for 1h. Alerts missing a key field are not suppressed. Download cradles often retry or loop. `host.id` is the Falcon agent ID and is always present; `host.name` is filled only when the integration's host metadata enrichment is on.

## Known false positives / exclusions
- Software deployment calling `msiexec /i https://…` from SYSTEM under the deployment agent parent. Exclude by parent process.
- `certutil -urlcache` in some update scripts. Exclude by exact command line.
- Encoded PowerShell from SCCM, Intune, the Azure guest agent and WinRM sessions is excluded by parent. Ansible and other WinRM-driven tools land under `wsmprovhost.exe` and are covered by W08 instead. Add other management agents by parent name.
- Start-BitsTransfer is no longer matched. It is routine in admin scripts.

## Triage
- Same chain as W03: URL, payload, network, then user context.

## Test
Atomic Red Team T1105 and T1218.005 on a lab host.
