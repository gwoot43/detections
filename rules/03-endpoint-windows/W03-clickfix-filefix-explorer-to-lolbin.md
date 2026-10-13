---
id: W03
name: Command with a URL launched from Explorer (ClickFix, FileFix, CrashFix)
category: endpoint-windows
status: todo
severity: high
language: esql
index: logs-crowdstrike.fdr-*
mitre: [T1204.004, T1059.001, T1105]
data_source: CrowdStrike FDR ProcessRollup2
suppression:
  fields: [host.id, user.name]
  duration: 1h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
ClickFix, FileFix and CrashFix all end the same way: the user pastes a command into the Run dialog or the Explorer address bar, so `explorer.exe` starts a Windows program whose command line fetches something from the internet. People don't type URLs into `powershell` or `mshta` from the Run dialog. Programs started from the Start menu or a shortcut carry no URL.

The rule needs no list of script hosts or download keywords: any Windows built-in program (from `\Windows\System32` or `\Windows\SysWOW64`) started by Explorer with `http://` or `https://` on its command line.

W04 skips commands launched by Explorer, so one pasted command alerts once. A script file the user double-clicks from Downloads or an archive is W12.

## Query
```esql
FROM logs-crowdstrike.fdr-* METADATA _id, _index, _version
| WHERE event.action == "ProcessRollup2" AND host.os.type == "windows"
| EVAL parent = TO_LOWER(process.parent.name),
       path = TO_LOWER(COALESCE(process.executable, "")),
       cmd = TO_LOWER(COALESCE(process.command_line, ""))
| WHERE parent == "explorer.exe"
  AND path RLIKE """.*\\windows\\(system32|syswow64)\\.*"""
  AND cmd LIKE "*http*://*"
| KEEP @timestamp, host.id, host.name, user.name, process.name, process.command_line, _id, _version, _index
```

**Not covered:**
- A pasted command that hides its URL behind Base64 (`powershell -enc ...`). W15 catches that from any parent.
- A command that uses a bare IP address with no `http` (`iwr 203.0.113.5/x`).
- PowerShell 7 (`pwsh.exe`), which installs under `Program Files`.

## Suppression
Suppress by `host.id`, `user.name` for 1h. Alerts missing a key field are not suppressed. One pasted command produces a chain of child processes. `host.id` is the Falcon agent ID and is always present.

## Known false positives / exclusions
- Shortcuts that start `mshta` or `rundll32` with an intranet URL (legacy HTA apps). Exclude by exact command line.
- Developers pasting `iwr` one-liners into the Run dialog. Rare enough to ask about.

## Triage
- Ask the user what page they were on. Take the URL from the command line, block it in Zscaler (N08), and check for a dropped payload (file-written events) and network connections from the process.

## Test
From Win+R on a lab host, run `powershell -w hidden -c "iwr http://<lab-server>/test.txt"`.
