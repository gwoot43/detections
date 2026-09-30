---
id: W12
name: Disk image mounted then a process runs from the new volume
category: endpoint-windows
status: todo
severity: high
language: esql
index: logs-crowdstrike.fdr-*
mitre: [T1553.005, T1204.002]
data_source: CrowdStrike FDR process events
suppression:
  fields: [host.name, exe]
  duration: 1h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
Attackers deliver payloads inside ISO, IMG and VHD files because contents mounted from a disk image do not carry the mark of the web, so SmartScreen and Office protections do not apply. A process executing from a mounted image volume, especially a script host or an unsigned binary, is a strong delivery signal. Legitimate use is mostly IT mounting install media, which you can scope out.

## Query
```esql
FROM logs-crowdstrike.fdr-* METADATA _id, _index, _version
| WHERE event.action == "ProcessRollup2" AND host.os.type == "windows"
| EVAL exe = TO_LOWER(TO_STRING(process.executable)), pname = TO_LOWER(process.name),
       parent = TO_LOWER(process.parent.name), vol = TO_LOWER(TO_STRING(COALESCE(process.working_directory, "")))
// Falcon exposes the mounted image path via the volume device; match execution from a non-system drive letter by a loader/script host
| WHERE (pname IN ("powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe", "hh.exe")
         OR exe LIKE "*.lnk" OR exe LIKE "*.iso\\*" OR exe LIKE "*.img\\*")
  AND parent IN ("explorer.exe", "isoburn.exe")
  AND NOT (exe LIKE "c:\\*")            // executed from a drive other than C: (a mounted image gets D:, E:, ...)
  AND exe != ""
| KEEP @timestamp, host.name, user.name, parent, pname, exe, process.command_line
```
Confirm how your FDR feed represents the mounted-volume path. If Falcon provides a mount or device event, key on that instead of the drive-letter heuristic, which is the weak part of this rule.

## Suppression
Suppress by `host.name`, `exe` for 1h. Alerts missing a key field are not suppressed. One mount can launch several processes.

## Known false positives / exclusions
- IT mounting install ISOs, and software distributed as ISO. Exclude by imaging hosts and by signed installer paths. Removable drives also present as non-C: letters; refine with the mount source once confirmed.

## Triage
- Find the image file that was mounted (usually in Downloads), pull it, and check what ran from it. Correlate with the delivery email (E01, E02).

## Test
Mount a benign ISO containing a script on a lab host and run it.
