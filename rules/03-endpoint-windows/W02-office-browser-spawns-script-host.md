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
suppression:
  fields: [host.id, parent, child]
  duration: 1h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
Word does not need PowerShell. Outlook does not need mshta. The parent list is small, the child list is small, and the intersection is malicious documents, HTML smuggling and archive-delivered loaders.

Three benign patterns are removed in the query:
- Chrome and Edge start native-messaging hosts (password managers, Microsoft SSO) through `cmd.exe` with a `chrome-extension://` argument.
- Outlook and other apps call `rundll32 shell32.dll,OpenAs_RunDLL` for the "Open with" dialog.
- `msiexec.exe` is only counted under Office, PDF and mail parents. Users install downloaded MSIs from browsers and archives all the time.

`explorer.exe` as a parent is limited to script files launched from Downloads, a temp folder or an archive extraction folder. Commands pasted into the Run dialog or address bar are W03.

## Query
```esql
FROM logs-crowdstrike.fdr-* METADATA _id, _index, _version
| WHERE event.action == "ProcessRollup2" AND host.os.type == "windows"
| EVAL parent = TO_LOWER(process.parent.name), child = TO_LOWER(process.name), cmd = TO_LOWER(COALESCE(process.command_line, ""))
| EVAL doc_parent = parent IN ("winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "onenote.exe", "msaccess.exe", "mspub.exe", "visio.exe",
                               "acrord32.exe", "acrobat.exe", "foxitreader.exe"),
       web_parent = parent IN ("msedge.exe", "chrome.exe", "firefox.exe", "brave.exe", "teams.exe", "ms-teams.exe", "slack.exe",
                               "7zfm.exe", "winrar.exe", "winzip64.exe")
| WHERE ((doc_parent OR web_parent)
         AND child IN ("powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe",
                       "certutil.exe", "bitsadmin.exe", "msiexec.exe", "msbuild.exe", "installutil.exe", "regasm.exe", "regsvcs.exe",
                       "curl.exe", "wget.exe", "schtasks.exe", "wmic.exe", "cmstp.exe", "forfiles.exe", "hh.exe")
         AND NOT (child == "msiexec.exe" AND web_parent)
         AND NOT (child == "cmd.exe" AND cmd LIKE "*chrome-extension://*")
         AND NOT (child == "rundll32.exe" AND cmd LIKE "*shell32.dll*openas_rundll*"))
   // explorer.exe: a script file double-clicked from Downloads, a temp folder or an archive extraction folder
   OR (parent == "explorer.exe"
       AND child IN ("wscript.exe", "cscript.exe", "mshta.exe", "hh.exe", "cmd.exe", "powershell.exe", "pwsh.exe")
       AND (cmd LIKE """*\\downloads\\*""" OR cmd LIKE """*\\temp\\*""" OR cmd LIKE """*\\7zo*""" OR cmd LIKE """*\\rar$*"""))
| KEEP @timestamp, host.id, host.name, user.name, parent, child, process.command_line, process.parent.entity_id
```

## Suppression
Suppress by `host.id`, `parent`, `child` for 1h. Alerts missing a key field are not suppressed. A macro often spawns the same child several times. `host.id` is the Falcon agent ID and is always present; `host.name` is filled only when the integration's host metadata enrichment is on.

## Known false positives / exclusions
- Excel spawning `cmd.exe` for approved macros in finance. Exclude by exact command line after review, never by host.
- Browser extensions that launch a native host through `powershell.exe` instead of `cmd.exe`. Exclude by exact command line.
- Users double-clicking a `.bat` or `.ps1` they downloaded themselves. Rare on a managed fleet; confirm with the user.

## Triage
- FDR does not carry the parent's command line. Find the parent's own ProcessRollup2 (its `process.entity_id` equals this event's `process.parent.entity_id`) to get the document or download path. Pull it from Mimecast (E02) or detonate.
- Look for follow-on network connections from the child (NetworkConnectIP4 with the child's `process.entity_id`).

## Test
Open a lab document with a macro that launches `calc.exe` via `cmd /c`.
