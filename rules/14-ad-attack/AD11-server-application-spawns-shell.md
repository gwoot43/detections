---
id: AD11
name: SQL Server or IIS application spawning a shell (xp_cmdshell, Exchange or SharePoint webshell)
category: ad-attack
status: todo
severity: high
rank: 11
language: esql
index: logs-crowdstrike.fdr-*
mitre: [T1505.001, T1505.003, T1190]
data_source: CrowdStrike FDR ProcessRollup2
suppression:
  fields: [host.name, parent]
  duration: 1h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
SQL Server, Exchange and SharePoint are common footholds into AD because they run as privileged service accounts and are often exposed. When they are compromised, the tell is the server process starting a shell: `sqlservr.exe` through `xp_cmdshell`, or the IIS worker `w3wp.exe` (which hosts Exchange OWA and ECP, SharePoint and other web apps) through a webshell. These processes rarely start shells in normal operation, and the legitimate cases are a short list you can baseline and exclude by exact command line.

L03 covers the same pattern for Linux web servers; W02 covers Office and browser parents.

## Query
```esql
FROM logs-crowdstrike.fdr-* METADATA _id, _index, _version
| WHERE event.action == "ProcessRollup2" AND host.os.type == "windows"
| EVAL parent = TO_LOWER(COALESCE(process.parent.name, "")),
       child = TO_LOWER(COALESCE(process.name, "")),
       cl = TO_LOWER(COALESCE(process.command_line, ""))
| WHERE parent IN ("sqlservr.exe", "w3wp.exe", "umworkerprocess.exe")
  AND child IN ("cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe",
                "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe", "curl.exe",
                "whoami.exe", "net.exe", "net1.exe", "nltest.exe", "systeminfo.exe", "tasklist.exe", "ipconfig.exe")
// baseline two weeks, then exclude exact legitimate command lines here
| WHERE NOT (cl IN ("cmd.exe /c echo ok"))
| KEEP @timestamp, host.name, user.name, parent, child, process.command_line, process.parent.command_line
```

## Suppression
Suppress by `host.name`, `parent` for 1h. Alerts missing a key field are not suppressed. A webshell session runs many commands; one alert per server process carries the count.

## Known false positives / exclusions
- SQL Agent jobs and maintenance scripts that call `xp_cmdshell` for file housekeeping (`dir`, `del`, `mkdir`, `bcp`). Exclude by exact command line after review.
- Some line-of-business web apps shell out by design. Exclude by exact command line, never by parent.

## Triage
- Discovery commands (`whoami`, `net`, `nltest`) under a server process are the first thing an intruder runs. Pull the IIS or SQL logs for the same minute to find the request, isolate the server, and look for a dropped webshell file in the web root.
- The service account is now in attacker hands; check its use elsewhere (B05, W08).

## Test
Enable `xp_cmdshell` on a lab SQL Server and run `whoami`.
