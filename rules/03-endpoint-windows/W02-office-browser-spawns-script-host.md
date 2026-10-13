---
id: W02
name: Office or PDF reader starts a Windows built-in program
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
Word, Excel, Outlook and PDF readers have no reason to start Windows' own programs (PowerShell, cmd, mshta, rundll32, certutil and the rest). When they do, a document is running code: a macro, an exploit, or an embedded object the user clicked.

The rule doesn't list which programs count. Anything that runs from `\Windows\System32` or `\Windows\SysWOW64` does, so a LOLBIN nobody thought to list still fires. The parent list is the definition of the rule: the document apps that open attachments.

Two everyday children are excluded: Windows Error Reporting (`werfault.exe`) when Office crashes, and Notepad, which Outlook uses to open `.txt` attachments. The "Open with" dialog (`rundll32 shell32.dll,OpenAs_RunDLL`) is excluded by its command line.

Scripts opened from a browser's or an archiver's download are W12, and commands pasted into the Run dialog are W03.

## Query
```esql
FROM logs-crowdstrike.fdr-* METADATA _id, _index, _version
| WHERE event.action == "ProcessRollup2" AND host.os.type == "windows"
| EVAL parent = TO_LOWER(process.parent.name),
       child = TO_LOWER(process.name),
       path = TO_LOWER(COALESCE(process.executable, "")),
       cmd = TO_LOWER(COALESCE(process.command_line, ""))
| WHERE parent IN ("winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "onenote.exe", "msaccess.exe", "mspub.exe",
                   "visio.exe", "acrord32.exe", "acrobat.exe", "foxitreader.exe")
  AND path RLIKE """.*\\windows\\(system32|syswow64)\\.*"""
| WHERE NOT child IN ("werfault.exe", "notepad.exe") AND NOT cmd LIKE "*shell32.dll*openas_rundll*"
| KEEP @timestamp, host.id, host.name, user.name, parent, child, process.command_line, process.parent.entity_id,
       _id, _version, _index
```

This rule doesn't use rarity. A phishing wave that gets several users to enable the same macro should alert more, not less.

## Suppression
Suppress by `host.id`, `parent`, `child` for 1h. Alerts missing a key field are not suppressed. A macro often starts the same child several times. `host.id` is the Falcon agent ID and is always present.

## Known false positives / exclusions
- Office add-ins that shell out (some finance or CRM add-ins start `cmd.exe`). Run the rule in preview for a week and add each one by exact command line, never by host.
- Outlook opening an `.rdp` attachment starts `mstsc.exe`. That is worth an alert: rogue RDP files are a known phishing lure.

## Triage
- FDR does not carry the parent's command line. Find the parent's own ProcessRollup2 (its `process.entity_id` equals this event's `process.parent.entity_id`) to get the document path, then pull the document from Mimecast (E02) or detonate it.
- Look for network connections from the child (NetworkConnectIP4 with the child's `process.entity_id`).

## Test
Open a lab document with a macro that runs `cmd /c calc`.
