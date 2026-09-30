---
id: W02
name: Office, browser, mail client or archiver spawning a script host or LOLBIN
category: endpoint-windows
status: todo
severity: high
language: esql
index: logs-crowdstrike.fdr-*
mitre: [T1204.002, T1566.001, T1059]
data_source: CrowdStrike FDR ProcessRollup2
---
## Why this is high fidelity
Word does not need PowerShell. Outlook does not need mshta. The parent list is small, the child list is small, and the intersection is malicious documents, HTML smuggling and archive-delivered loaders.

## Query
```esql
FROM logs-crowdstrike.fdr-* METADATA _id, _index, _version
| WHERE event.action == "ProcessRollup2" AND host.os.type == "windows"
| EVAL parent = TO_LOWER(process.parent.name), child = TO_LOWER(process.name), cmd = TO_LOWER(process.command_line)
| WHERE parent IN ("winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "onenote.exe", "msaccess.exe", "mspub.exe", "visio.exe",
                   "acrord32.exe", "acrobat.exe", "foxitreader.exe",
                   "msedge.exe", "chrome.exe", "firefox.exe", "brave.exe",
                   "teams.exe", "ms-teams.exe", "slack.exe",
                   "7zfm.exe", "winrar.exe", "winzip64.exe", "explorer.exe")
  AND child IN ("powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe",
                "certutil.exe", "bitsadmin.exe", "msiexec.exe", "msbuild.exe", "installutil.exe", "regasm.exe", "regsvcs.exe",
                "curl.exe", "wget.exe", "schtasks.exe", "wmic.exe", "cmstp.exe", "forfiles.exe", "hh.exe")
// explorer.exe as parent is only interesting when the child runs from a download/temp/archive path or carries a URL
| WHERE parent != "explorer.exe"
   OR cmd LIKE "*\\downloads\\*" OR cmd LIKE "*\\temp\\*" OR cmd LIKE "*\\appdata\\local\\*" OR cmd LIKE "*http*" OR cmd LIKE "*\\7z*" OR cmd LIKE "*\\rar$*"
| KEEP @timestamp, host.name, user.name, parent, child, process.command_line, process.parent.command_line
```

## Known false positives / exclusions
- Excel spawning `cmd.exe` for approved macros in finance. Exclude by exact command line after review, never by host.
- Chrome spawning `powershell.exe` for some enterprise extensions. Same approach.

## Triage
- Get the document or download (`process.parent.command_line` has the file path). Pull from Mimecast (E02) or detonate.
- Look for follow-on network connections from the child (F06).

## Test
Open a lab document with a macro that launches `calc.exe` via `cmd /c`.
