---
id: W02
name: Office, browser, mail client or archiver spawning a script host or LOLBIN
category: endpoint-windows
status: todo
severity: high
language: esql
index: logs-yourorg-crowdstrike-data-default*
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

`explorer.exe` is not a parent here. W03 owns script hosts and LOLBINs launched from Explorer: commands pasted into the Run dialog or address bar (ClickFix/FileFix), and script files opened from Downloads, a temp folder or an archive extraction folder.

## Query
```esql
FROM logs-yourorg-crowdstrike-data-default* METADATA _id, _index, _version
| WHERE event.action == "processrollup2" AND host.os.type == "windows"
| EVAL parent = TO_LOWER(process.parent.name), child = TO_LOWER(process.name), cmd = TO_LOWER(COALESCE(process.command_line, ""))
| EVAL doc_parent = parent IN ("winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "onenote.exe", "msaccess.exe", "mspub.exe", "visio.exe",
                               "acrord32.exe", "acrobat.exe", "foxitreader.exe"),
       web_parent = parent IN ("msedge.exe", "chrome.exe", "firefox.exe", "brave.exe", "teams.exe", "ms-teams.exe", "slack.exe",
                               "7zfm.exe", "winrar.exe", "winzip64.exe")
| WHERE (doc_parent OR web_parent)
  AND child IN ("powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe",
                "certutil.exe", "bitsadmin.exe", "msiexec.exe", "msbuild.exe", "installutil.exe", "regasm.exe", "regsvcs.exe",
                "curl.exe", "wget.exe", "schtasks.exe", "wmic.exe", "cmstp.exe", "forfiles.exe", "hh.exe")
  AND NOT (child == "msiexec.exe" AND web_parent)
  AND NOT (child == "cmd.exe" AND cmd LIKE "*chrome-extension://*")
  AND NOT (child == "rundll32.exe" AND cmd LIKE "*shell32.dll*openas_rundll*")
| KEEP @timestamp, host.id, host.name, user.name, parent, child, process.command_line, process.parent.entity_id, _id, _version, _index
```

**CrowdStrike (Falcon LogScale / Advanced Event Search)**
```logscale
#event_simpleName=/^(ProcessRollup2|SyntheticProcessRollup2)$/ event_platform=Win
| in(field="FileName", ignoreCase=true, values=["powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe",
                                               "regsvr32.exe", "certutil.exe", "bitsadmin.exe", "msiexec.exe", "msbuild.exe", "installutil.exe",
                                               "regasm.exe", "regsvcs.exe", "curl.exe", "wget.exe", "schtasks.exe", "wmic.exe", "cmstp.exe",
                                               "forfiles.exe", "hh.exe"])
| case {
    // Office, PDF and mail parents: every child in the list, msiexec included
    in(field="ParentBaseFileName", ignoreCase=true, values=["winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "onenote.exe", "msaccess.exe",
                                                           "mspub.exe", "visio.exe", "acrord32.exe", "acrobat.exe", "foxitreader.exe"]);
    // browser, chat and archiver parents: msiexec is not counted
    in(field="ParentBaseFileName", ignoreCase=true, values=["msedge.exe", "chrome.exe", "firefox.exe", "brave.exe", "teams.exe", "ms-teams.exe",
                                                           "slack.exe", "7zfm.exe", "winrar.exe", "winzip64.exe"])
      | FileName!=/^msiexec\.exe$/i;
  }
| NOT (FileName=/^cmd\.exe$/i AND CommandLine=/chrome-extension:\/\//i)
| NOT (FileName=/^rundll32\.exe$/i AND CommandLine=/shell32\.dll.*openas_rundll/i)
| select([@timestamp, aid, ComputerName, UserName, ParentBaseFileName, FileName, CommandLine, ParentProcessId])
```

## Suppression
Suppress by `host.id`, `parent`, `child` for 1h. Alerts missing a key field are not suppressed. A macro often spawns the same child several times. `host.id` is the Falcon agent ID and is always present; `host.name` is filled only when the integration's host metadata enrichment is on.

## Known false positives / exclusions
- Excel spawning `cmd.exe` for approved macros in finance. Exclude by exact command line after review, never by host.
- Browser extensions that launch a native host through `powershell.exe` instead of `cmd.exe`. Exclude by exact command line.

## Triage
- FDR does not carry the parent's command line. Find the parent's own ProcessRollup2 (its `process.entity_id` equals this event's `process.parent.entity_id`) to get the document or download path. Pull it from Mimecast (E02) or detonate.
- Look for follow-on network connections from the child (NetworkConnectIP4 with the child's `process.entity_id`).

## Test
Open a lab document with a macro that launches `calc.exe` via `cmd /c`.
