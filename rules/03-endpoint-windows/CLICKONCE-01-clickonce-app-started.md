---
id: CLICKONCE-01
name: ClickOnce chain on an endpoint - a program started by the ClickOnce service, started by a ClickOnce app, or running from the ClickOnce cache (T1127.002)
language: esql
index: logs-yourorg-crowdstrike-data-default*
mitre: [T1127.002, T1204.002]
data_source: CrowdStrike FDR ProcessRollup2
suppression:
  fields: [host.id, data.FileName]
  duration: 24h
  missing_fields: do_not_suppress
---
A ClickOnce link (`.application`, or an `.appref-ms` shortcut) installs a .NET app into the user's profile and runs it, with no admin prompt. However it's launched, three things are true, and none depends on the tool or the app's name:
- **started by ClickOnce:** the app's parent is the ClickOnce service, `dfsvc.exe`. It often runs as its NGEN native image, `dfsvc.ni.exe`, so both names are matched.
- **started by a ClickOnce app:** anything the app launches has `dfsvc` as its grandparent. A loader's shell, PowerShell or `rundll32` shows up here.
- **running from the ClickOnce cache:** the app's image is under `%LOCALAPPDATA%\Apps\2.0\`, even when it's later run directly.

No ClickOnce apps have run in the estate in 30 days, so no allowlist is needed yet; every hit is worth reading. 07 sees the download through Zscaler; this sees what ran.

Run every 15 minutes over the last 20.

**CrowdStrike (Falcon LogScale)**
```logscale
//Filter for Windows process starts in the ClickOnce chain
#event_simpleName=ProcessRollup2 event_platform=Win
| ParentBaseFileName=/^dfsvc(\.ni)?\.exe$/i OR GrandParentBaseFileName=/^dfsvc(\.ni)?\.exe$/i OR ImageFileName=/\\AppData\\Local\\Apps\\2\.0\\/i
//Label where in the chain each process sits
| case {
    ParentBaseFileName=/^dfsvc(\.ni)?\.exe$/i | stage := "started by ClickOnce";
    GrandParentBaseFileName=/^dfsvc(\.ni)?\.exe$/i | stage := "started by a ClickOnce app";
    * | stage := "running from the ClickOnce cache";
  }
//Display results
| table([@timestamp, ComputerName, UserName, stage, FileName, ImageFileName, CommandLine, ParentBaseFileName, TargetProcessId, SHA256HashData])
```

**Elastic (ES|QL)**
```esql
FROM logs-yourorg-crowdstrike-data-default* METADATA _id, _index, _version
// Filter for Windows process starts in the ClickOnce chain: started by the ClickOnce service (dfsvc, or its NGEN
// image dfsvc.ni.exe), started by a ClickOnce app, or running from the ClickOnce cache (%LOCALAPPDATA%\Apps\2.0).
// The triple quotes keep the doubled backslashes, so LIKE matches each as one literal backslash.
| WHERE event.action == "processrollup2" AND data.event_platform == "Win"
  AND (data.ParentBaseFileName IN ("dfsvc.exe", "dfsvc.ni.exe", "DFSVC.EXE", "DFSVC.NI.EXE")
       OR data.GrandParentBaseFileName IN ("dfsvc.exe", "dfsvc.ni.exe", "DFSVC.EXE", "DFSVC.NI.EXE")
       OR data.ImageFileName LIKE """*\\AppData\\Local\\Apps\\2.0\\*""")
// Label where in the chain each process sits
| EVAL stage = CASE(TO_LOWER(data.ParentBaseFileName) IN ("dfsvc.exe", "dfsvc.ni.exe"), "started by ClickOnce",
                    TO_LOWER(data.GrandParentBaseFileName) IN ("dfsvc.exe", "dfsvc.ni.exe"), "started by a ClickOnce app",
                    "running from the ClickOnce cache")
// Sanctioned ClickOnce apps go here once you have any (none in 30 days):
// | WHERE NOT data.FileName IN ("<known_clickonce_app>.exe")
| KEEP @timestamp, host.id, host.name, user.name, stage, data.FileName, data.ImageFileName, process.command_line,
       data.ParentBaseFileName, data.GrandParentBaseFileName, data.TargetProcessId, data.SHA256HashData,
       _id, _index, _version
// Investigating a hit:
// 1. What ran. stage "started by ClickOnce" is the app itself: its folder under Apps\2.0 (data.ImageFileName) is
//    named after the app, and data.SHA256HashData can be looked up in Falcon and VirusTotal. notepad.exe here,
//    opening a file, means an install failed and the user opened the error log: read that log for the
//    deployment URL and the reason it failed.
// 2. Where it came from. Zscaler (07) for .application and .deploy requests from that user just before
//    @timestamp gives the deployment site; then find the email or chat message that linked to it.
// 3. What it did. Pivot on data.TargetProcessId (query below) for its child processes, connections, DNS
//    lookups and file writes. stage "started by a ClickOnce app" rows are those children: a shell, script host
//    or rundll32 means it's a loader. Treat the host as compromised.
// 4. Whether it stays. Look for an .appref-ms in the user's Startup folder, or a Run key pointing into Apps\2.0
//    (Falcon RTR on the host).
// 5. Scope. The same hash, file name or deployment site on other hosts and users.
// 6. Contain. Network-contain the host if step 3 found anything, uninstall the app from the user's installed apps
//    (ClickOnce installs per user), and block the deployment domain in Zscaler.
```
Suppress by host and program for 24h.

## Pivot: what the app did
```logscale
#event_simpleName=/^(ProcessRollup2|NetworkConnectIP4|DnsRequest|.*Written)$/ aid="<aid>"
| ParentProcessId="<TargetProcessId>" OR ContextProcessId="<TargetProcessId>"
| table([@timestamp, #event_simpleName, FileName, CommandLine, RemoteAddressIP4, RemotePort, DomainName, TargetFileName])
```
```esql
FROM logs-yourorg-crowdstrike-data-default*
// Everything the ClickOnce app did: its children, connections, lookups and file writes
| WHERE host.id == "<host.id>"
  AND (data.ParentProcessId == "<data.TargetProcessId>" OR data.ContextProcessId == "<data.TargetProcessId>")
| KEEP @timestamp, event.action, process.name, process.command_line, destination.ip, destination.port,
       data.DomainName, data.TargetFileName
| SORT @timestamp ASC
```

## Before turning it on
- Check `data.GrandParentBaseFileName` is filled on your process events (B09 uses it).
- When ClickOnce apps do get sanctioned, add them to the commented exclusion by name, and keep an eye on "started by a ClickOnce app" for them: a real app starting a shell is still worth a look.

## What it misses
- A payload that does everything inside the .NET app, with no child process. Step 3's pivot shows its connections.
- A payload copied out of the cache and run from somewhere else.
