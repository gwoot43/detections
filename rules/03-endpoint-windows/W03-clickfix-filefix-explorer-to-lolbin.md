---
id: W03
name: ClickFix, FileFix or CrashFix: user-pasted command executed from Explorer or the Run dialog
category: endpoint-windows
status: todo
severity: high
language: esql
index: logs-crowdstrike.fdr-*
mitre: [T1204.004, T1059.001, T1105]
data_source: CrowdStrike FDR ProcessRollup2
suppression:
  fields: [host.name, user.name]
  duration: 1h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
ClickFix was close to half of initial access in Microsoft's 2025 reporting and grew FileFix (Explorer address bar) and CrashFix (browser crash lure) variants in 2026. The artefact is constant: `explorer.exe` is the parent, the child is a script host or downloader, and the command line contains a URL, a download cradle or Base64. Users do not hand-type those.

## Query
```esql
FROM logs-crowdstrike.fdr-* METADATA _id, _index, _version
| WHERE event.action == "ProcessRollup2" AND host.os.type == "windows"
| EVAL parent = TO_LOWER(process.parent.name), child = TO_LOWER(process.name), cmd = TO_LOWER(process.command_line)
| WHERE parent == "explorer.exe"
  AND child IN ("powershell.exe", "pwsh.exe", "mshta.exe", "cmd.exe", "curl.exe", "msiexec.exe", "wscript.exe", "cscript.exe", "bitsadmin.exe", "certutil.exe")
  AND (
       cmd LIKE "*http://*" OR cmd LIKE "*https://*"
    OR cmd LIKE "*iwr *" OR cmd LIKE "*irm *" OR cmd LIKE "*iex*" OR cmd LIKE "*invoke-webrequest*" OR cmd LIKE "*invoke-restmethod*" OR cmd LIKE "*invoke-expression*"
    OR cmd LIKE "*downloadstring*" OR cmd LIKE "*downloadfile*" OR cmd LIKE "*net.webclient*"
    OR cmd LIKE "* -enc*" OR cmd LIKE "*frombase64string*" OR cmd LIKE "* -w hidden*" OR cmd LIKE "*-windowstyle hidden*"
    OR cmd LIKE "*i am not a robot*" OR cmd LIKE "*captcha*" OR cmd LIKE "*verification*" OR cmd LIKE "*ray id*"
    OR cmd LIKE "*# *"       // FileFix: comment padding hides the command in the Explorer address bar
  )
| KEEP @timestamp, host.name, user.name, parent, child, process.command_line
```
Add the registry side once F01 is live: `RunMRU` and `TypedPaths` values containing `powershell`, `mshta` or `http` are the same technique seen from the registry.

## Suppression
Suppress by `host.name`, `user.name` for 1h. Alerts missing a key field are not suppressed. One pasted command produces a chain of child processes.

## Known false positives / exclusions
- Developers pasting `iwr` one-liners. Rare enough to ask.

## Triage
- Ask the user what page they were on. Pull the URL from the command line, block it in Zscaler (N08), check for a dropped payload (F07) and outbound connections (F06).

## Test
From Win+R on a lab host, run a `powershell -w hidden` command that fetches a local test URL.
