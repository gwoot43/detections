---
id: CLICKONCE-01
name: Program started by the ClickOnce service (a ClickOnce app running, T1127.002)
language: esql
index: logs-yourorg-crowdstrike-data-default*
mitre: [T1127.002, T1204.002]
data_source: CrowdStrike FDR ProcessRollup2
suppression:
  fields: [host.id, process.name]
  duration: 24h
  missing_fields: do_not_suppress
---
A ClickOnce link (`.application`, or an `.appref-ms` shortcut) installs a .NET app into the user's profile and runs it, with no admin prompt. Whatever starts it (a click in the browser, `rundll32 dfshim.dll,ShOpenVerbApplication <url>`, a Startup shortcut), the app itself is started by the ClickOnce service, `dfsvc.exe`, from `%LOCALAPPDATA%\Apps\2.0\`. So a program whose parent is `dfsvc.exe` is a ClickOnce app actually running. Most estates run few ClickOnce apps; once those are excluded, anything else is new.

This is the higher-fidelity of the two ClickOnce detections: 07 sees the download through Zscaler, this sees the app run.

Run every 15 minutes over the last 20.

**CrowdStrike (Falcon LogScale)**
```logscale
//Filter for programs started by the ClickOnce service
#event_simpleName=ProcessRollup2 event_platform=Win ParentBaseFileName=/^dfsvc\.exe$/i
//Leave out the ClickOnce apps you use (placeholders)
| !in(field="FileName", values=["<known_clickonce_app>.exe"], ignoreCase=true)
//Display results
| table([@timestamp, ComputerName, UserName, FileName, ImageFileName, CommandLine, SHA256HashData])
```

**Elastic (ES|QL)**
```esql
FROM logs-yourorg-crowdstrike-data-default* METADATA _id, _index, _version
// Filter for programs started by the ClickOnce service
| WHERE event.action == "processrollup2" AND data.event_platform == "Win"
  AND data.ParentBaseFileName IN ("dfsvc.exe", "DFSVC.EXE", "Dfsvc.exe")
// Leave out the ClickOnce apps you use (placeholders)
| WHERE data.FileName IS NULL OR NOT data.FileName IN ("<known_clickonce_app>.exe")
// Display results
| KEEP @timestamp, host.id, host.name, user.name, data.FileName, process.executable, process.command_line,
       data.SHA256HashData, _id, _index, _version
```
Suppress by host and program for 24h.

## Before turning it on
- Find the ClickOnce apps you already run, and put them in the exclusion:
  ```logscale
  #event_simpleName=ProcessRollup2 event_platform=Win ParentBaseFileName=/^dfsvc\.exe$/i
  | groupBy([FileName], function=[count(aid, distinct=true, as=hosts), collect([ImageFileName], limit=3)], limit=max)
  ```
- Check in a lab that a ClickOnce app's process shows `dfsvc.exe` as its parent.

## What it misses
- A payload given the same file name as one of your excluded apps. Check the folder under `\Apps\2.0\` and the hash when an excluded name appears on a host that never ran it before.
- What the app does next: it runs as a normal .NET program. Pivot on its process ID for child processes and connections.

## When it fires
The app runs as the user. Look at its folder (`ImageFileName`) for the deployment it came from, its children and network connections, and Zscaler for the site it was downloaded from (07). A `.appref-ms` in the user's Startup folder means it will run again at every logon.
