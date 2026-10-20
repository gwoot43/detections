---
id: W12
name: Disk image mounted then a process runs from the new volume
category: endpoint-windows
status: todo
severity: high
language: esql
index: logs-yourorg-crowdstrike-data-default*
mitre: [T1553.005, T1204.002]
data_source: CrowdStrike FDR process events
suppression:
  fields: [host.id, exe]
  duration: 1h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
Attackers deliver payloads inside ISO, IMG and VHD files because contents mounted from a disk image do not carry the mark of the web, so SmartScreen and Office protections do not apply. A process executing from a mounted image volume, especially a script host or an unsigned binary, is a strong delivery signal. Legitimate use is mostly IT mounting install media, which you can scope out.

FDR records executables by device path (`\Device\HarddiskVolume3\...`), never by drive letter. Windows mounts ISO and IMG files as a virtual DVD drive, so a binary launched from one has a path under `\Device\CdRom<n>\`. That is the first branch. The second covers script hosts and LOLBINs that Explorer starts on a script or DLL at the root of a drive other than C:, which is how the file inside a mounted image is usually opened. VHD and VHDX mounts get an ordinary `HarddiskVolume` path and are only caught by the second branch.

## Query
```esql
FROM logs-yourorg-crowdstrike-data-default* METADATA _id, _index, _version
| WHERE event.action == "processrollup2" AND host.os.type == "windows"
| EVAL exe = TO_LOWER(COALESCE(process.executable, "")), pname = TO_LOWER(process.name),
       parent = TO_LOWER(process.parent.name), cmd = TO_LOWER(COALESCE(process.command_line, ""))
| WHERE exe LIKE """\\device\\cdrom*"""
   OR (parent == "explorer.exe"
       AND pname IN ("wscript.exe", "cscript.exe", "mshta.exe", "hh.exe", "rundll32.exe", "regsvr32.exe", "cmd.exe", "powershell.exe", "pwsh.exe")
       AND cmd RLIKE """.*[d-z]:\\[^\\]*\.(vbs|vbe|js|jse|wsf|hta|chm|bat|cmd|ps1|dll|cpl)([\", ].*)?""")
| KEEP @timestamp, host.id, host.name, user.name, parent, pname, exe, process.command_line, _id, _version, _index
```

**CrowdStrike (Falcon LogScale / Advanced Event Search)**
```logscale
#event_simpleName=/^(ProcessRollup2|SyntheticProcessRollup2)$/ event_platform=Win
| case {
    ImageFileName=/^\\device\\cdrom/i;
    ParentBaseFileName=/^explorer\.exe$/i
      | in(field="FileName", ignoreCase=true, values=["wscript.exe", "cscript.exe", "mshta.exe", "hh.exe", "rundll32.exe", "regsvr32.exe", "cmd.exe",
                                                 "powershell.exe", "pwsh.exe"])
      | CommandLine=/[d-z]:\\[^\\]*\.(vbs|vbe|js|jse|wsf|hta|chm|bat|cmd|ps1|dll|cpl)([\", ]|$)/i;
  }
| table([@timestamp, aid, ComputerName, UserName, ParentBaseFileName, FileName, ImageFileName, CommandLine])
```

## Suppression
Suppress by `host.id`, `exe` for 1h. Alerts missing a key field are not suppressed. One mount can launch several processes. `host.id` is the Falcon agent ID and is always present; `host.name` is filled only when the integration's host metadata enrichment is on.

## Known false positives / exclusions
- IT running `setup.exe` from mounted install media. Exclude by the admin account or the imaging hosts, not by file name.
- Physical CD and DVD drives present the same `\Device\CdRom` path. They are rare on a managed fleet.
- The second branch also matches a script or DLL at the root of a USB stick or a mapped network drive. Both are uncommon to double-click and worth a look; exclude a specific logon-script share by exact command line.

## Triage
- Find the image file that was mounted (usually in Downloads), pull it, and check what ran from it. Correlate with the delivery email (E01, E02).

## Test
Mount a benign ISO containing a script on a lab host and run it.
