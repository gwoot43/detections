---
id: W04
name: LOLBIN download cradle or remote script execution
category: endpoint-windows
status: todo
severity: high
language: esql
index: logs-crowdstrike.fdr-*
mitre: [T1105, T1218.005, T1218.010, T1218.011, T1197, T1059.001, T1218.007, T1027.010]
data_source: CrowdStrike FDR ProcessRollup2
suppression:
  fields: [host.id, pname]
  duration: 1h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
These binary-plus-argument combinations exist to fetch and run remote content and have almost no administrative use on user workstations. Each branch is a known LOLBAS entry. The branches that admin tooling also uses (encoded PowerShell, .NET build and registration tools) exclude the management agents and installers that run them by design.

When the parent is `explorer.exe` and the child is one W03 watches (PowerShell, mshta, cmd, curl, msiexec, the script hosts, BITSAdmin, certutil, hh), the event is left to W03, so a cradle pasted into the Run dialog or address bar fires one rule, not two.

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
// Explorer-launched script hosts and downloaders are W03 (ClickFix/FileFix); one pasted cradle should alert once
| WHERE NOT (parent == "explorer.exe"
             AND pname IN ("powershell.exe", "pwsh.exe", "mshta.exe", "cmd.exe", "curl.exe", "msiexec.exe", "wscript.exe", "cscript.exe", "bitsadmin.exe", "certutil.exe", "hh.exe"))
| KEEP @timestamp, host.id, host.name, user.name, process.parent.name, pname, process.command_line, _id, _version, _index
```

**CrowdStrike (Falcon LogScale / Advanced Event Search)**
```logscale
#event_simpleName=/^(ProcessRollup2|SyntheticProcessRollup2)$/ event_platform=Win
| case {
    FileName=/^certutil\.exe$/i CommandLine=/urlcache|-decode|-verifyctl/i;
    FileName=/^bitsadmin\.exe$/i CommandLine=/transfer|addfile|setnotifycmdline/i;
    FileName=/^mshta\.exe$/i CommandLine=/http|javascript:|vbscript:/i;
    FileName=/^regsvr32\.exe$/i CommandLine=/scrobj|\/i:http|\.sct/i;
    FileName=/^msiexec\.exe$/i CommandLine=/http/i;
    // rundll32 with a plain URL is how many apps open a browser (url.dll,FileProtocolHandler), so only the script and OpenURL forms count
    FileName=/^rundll32\.exe$/i CommandLine=/javascript:|url\.dll.*openurl/i;
    FileName=/^(curl|wget)\.exe$/i CommandLine=/-o |--output/i
      CommandLine=/\.exe|\.dll|\.ps1|\.bat|\.hta|\\temp\\|\\public\\/i;
    FileName=/^(powershell|pwsh)\.exe$/i CommandLine=/downloadstring|downloadfile|net\.webclient/i;
    FileName=/^(powershell|pwsh)\.exe$/i CommandLine=/iex/i CommandLine=/http|frombase64/i;
    // encoded PowerShell, except from the management agents that run encoded scripts by design
    FileName=/^(powershell|pwsh)\.exe$/i CommandLine=/-encodedcommand| -enc | -ec | -e /i
      | !in(field="ParentBaseFileName", ignoreCase=true, values=["ccmexec.exe", "intunemanagementextension.exe", "agentexecutor.exe",
                                                                "windowsazureguestagent.exe", "gc_worker.exe", "wsmprovhost.exe"]);
    // .NET LOLBINs loading from user-writable paths; installers (msiexec) and Visual Studio run these legitimately
    FileName=/^(msbuild|installutil|regasm|regsvcs|cmstp)\.exe$/i CommandLine=/http|\\temp\\|\\appdata\\/i
      | !in(field="ParentBaseFileName", ignoreCase=true, values=["msiexec.exe", "devenv.exe"]);
  }
// Explorer-launched script hosts and downloaders are W03 (ClickFix/FileFix); one pasted cradle should alert once
| NOT (ParentBaseFileName=/^explorer\.exe$/i
       AND FileName=/^(powershell|pwsh|mshta|cmd|curl|msiexec|wscript|cscript|bitsadmin|certutil|hh)\.exe$/i)
| table([@timestamp, aid, ComputerName, UserName, ParentBaseFileName, FileName, CommandLine])
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
