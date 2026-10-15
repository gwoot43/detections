---
id: W03
name: Script host or LOLBIN launched from Explorer - ClickFix, FileFix or CrashFix pasted command, or a script file opened from Downloads, temp or an archive
category: endpoint-windows
status: todo
severity: high
language: esql
index: logs-crowdstrike.fdr-*
mitre: [T1204.004, T1204.002, T1059.001, T1105]
data_source: CrowdStrike FDR ProcessRollup2
suppression:
  fields: [host.id, user.name]
  duration: 1h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
This rule owns script hosts and LOLBINs launched from Explorer. W02 covers Office, browser, mail and archiver parents, and W04 leaves Explorer-launched children to this rule, so one Explorer-launched cradle alerts once.

ClickFix was close to half of initial access in Microsoft's 2025 reporting and grew FileFix (Explorer address bar) and CrashFix (browser crash lure) variants in 2026. The artefact is constant: `explorer.exe` is the parent, the child is a script host or downloader, and the command line contains a URL, a download cradle or Base64. Users do not hand-type those.

The second shape is a delivered script file the user double-clicks: a `.js`, `.vbs`, `.hta`, `.chm`, `.bat` or `.ps1` opened from Downloads, a temp folder or an archive extraction folder (7-Zip `7zO*`, WinRAR `Rar$*`) runs its script host with that path on the command line.

## Query
```esql
FROM logs-crowdstrike.fdr-* METADATA _id, _index, _version
| WHERE event.action == "ProcessRollup2" AND host.os.type == "windows"
| EVAL parent = TO_LOWER(process.parent.name), child = TO_LOWER(process.name), cmd = TO_LOWER(process.command_line)
| WHERE parent == "explorer.exe"
  AND child IN ("powershell.exe", "pwsh.exe", "mshta.exe", "cmd.exe", "curl.exe", "msiexec.exe", "wscript.exe", "cscript.exe", "bitsadmin.exe", "certutil.exe", "hh.exe")
  AND (
       cmd LIKE "*http://*" OR cmd LIKE "*https://*"
    // whole-word aliases only: "*irm *" alone also matches "-confirm ", "*iex*" also matches "iexplore"
    OR cmd LIKE "* iwr *" OR cmd LIKE "* irm *" OR cmd LIKE "*iex(*" OR cmd LIKE "*iex *" OR cmd LIKE "*|iex*" OR cmd LIKE "*| iex*"
    OR cmd LIKE "*invoke-webrequest*" OR cmd LIKE "*invoke-restmethod*" OR cmd LIKE "*invoke-expression*"
    OR cmd LIKE "*downloadstring*" OR cmd LIKE "*downloadfile*" OR cmd LIKE "*net.webclient*"
    OR cmd LIKE "* -enc*" OR cmd LIKE "*frombase64string*" OR cmd LIKE "* -w hidden*" OR cmd LIKE "*-windowstyle hidden*"
    OR cmd LIKE "*i am not a robot*" OR cmd LIKE "*captcha*" OR cmd LIKE "*verification*" OR cmd LIKE "*ray id*"
    // FileFix: a run of spaces before a "#" comment, or a fake file path after it, hides the command in the address bar
    OR cmd LIKE "*   #*" OR cmd LIKE """*# c:\\*"""
    // a script file double-clicked from Downloads, a temp folder or an archive extraction folder
    OR (child IN ("wscript.exe", "cscript.exe", "mshta.exe", "hh.exe", "cmd.exe", "powershell.exe", "pwsh.exe")
        AND (cmd LIKE """*\\downloads\\*""" OR cmd LIKE """*\\temp\\*""" OR cmd LIKE """*\\7zo*""" OR cmd LIKE """*\\rar$*"""))
  )
| EVAL user.name = TO_LOWER(MV_LAST(SPLIT(user.name, "\\")))
| KEEP @timestamp, host.id, host.name, user.name, parent, child, process.command_line, _id, _version, _index
```

**CrowdStrike (Falcon LogScale / Advanced Event Search)**
```logscale
#event_simpleName=/^(ProcessRollup2|SyntheticProcessRollup2)$/ event_platform=Win
| ParentBaseFileName=/^explorer\.exe$/i
| in(field="FileName", ignoreCase=true, values=["powershell.exe", "pwsh.exe", "mshta.exe", "cmd.exe", "curl.exe", "msiexec.exe", "wscript.exe",
                                               "cscript.exe", "bitsadmin.exe", "certutil.exe", "hh.exe"])
| case {
    CommandLine=/https?:\/\//i;
    // whole-word aliases only: "irm " alone also matches "-confirm ", "iex" alone also matches "iexplore"
    CommandLine=/ iwr | irm |iex\(|iex |\|iex|\| iex/i;
    CommandLine=/invoke-webrequest|invoke-restmethod|invoke-expression|downloadstring|downloadfile|net\.webclient/i;
    CommandLine=/ -enc|frombase64string| -w hidden|-windowstyle hidden/i;
    CommandLine=/i am not a robot|captcha|verification|ray id/i;
    // FileFix: a run of spaces before a "#" comment, or a fake file path after it, hides the command in the address bar
    CommandLine=/   #|# c:\\/i;
    // a script file double-clicked from Downloads, a temp folder or an archive extraction folder
    in(field="FileName", ignoreCase=true, values=["wscript.exe", "cscript.exe", "mshta.exe", "hh.exe", "cmd.exe", "powershell.exe", "pwsh.exe"])
      | CommandLine=/\\downloads\\|\\temp\\|\\7zo|\\rar\$/i;
  }
| table([@timestamp, aid, ComputerName, UserName, ParentBaseFileName, FileName, CommandLine])
```
The same technique also leaves `RunMRU` and `TypedPaths` registry values containing `powershell`, `mshta` or `http`. Those keys are not ASEPs, so CS02 does not watch them; add a registry branch only if your FDR feed records them.

## Suppression
Suppress by `host.id`, `user.name` for 1h. Alerts missing a key field are not suppressed. One pasted command produces a chain of child processes. `host.id` is the Falcon agent ID and is always present; `host.name` is filled only when the integration's host metadata enrichment is on. `user.name` is reduced to the bare, lowercased account name, since enrichment writes either `DOMAIN\user` or `user`.

## Known false positives / exclusions
- Developers pasting `iwr` one-liners. Rare enough to ask.
- Shortcuts or desktop files that start PowerShell with a URL. Exclude by exact command line.
- Users double-clicking a `.bat` or `.ps1` they downloaded themselves. Rare on a managed fleet; confirm with the user.

## Triage
- Ask the user what page they were on. Pull the URL from the command line, block it in Zscaler (N08), check for a dropped payload (file-written events) and outbound connections (NetworkConnectIP4) from the child.
- Script file from Downloads, temp or an archive: find where the file came from (the browser download or the mail attachment, E02) and pull it for detonation.

## Test
From Win+R on a lab host, run a hidden PowerShell command that fetches a local test URL. Separately, double-click a benign `.js` file saved in Downloads.
