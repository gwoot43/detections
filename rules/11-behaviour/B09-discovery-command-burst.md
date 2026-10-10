---
id: B09
name: Host discovery command burst - catches post-exploitation recon and loaders by behaviour
category: behaviour
status: todo
severity: medium
language: esql
index: logs-crowdstrike.fdr-*
mitre: [T1033, T1016, T1057, T1082, T1087, T1049]
data_source: CrowdStrike FDR ProcessRollup2
suppression:
  fields: [host.id, user.name]
  duration: 1h
  missing_fields: do_not_suppress
---
## Why this is behavioural and high fidelity
After landing on a host, an operator or a loader runs a rapid series of built-in discovery commands to orient: host, network, process, account and domain reconnaissance. A real user runs one or two of these occasionally. This counts the number of distinct discovery utilities a single host runs in a short window, so it catches the orientation burst regardless of which script or framework drove it, and it generalises the AD-specific recon in W09 to host and network discovery.

## Query
Run every 10 minutes with a 15-minute lookback.
```esql
FROM logs-crowdstrike.fdr-*
| WHERE event.action == "ProcessRollup2" AND host.os.type == "windows"
| EVAL pname = TO_LOWER(process.name),
       parent = TO_LOWER(COALESCE(process.parent.name, "")),
       grandparent = TO_LOWER(COALESCE(crowdstrike.GrandParentBaseFileName, ""))
// SCCM and Intune scripts run inventory commands in bursts
| WHERE parent NOT IN ("ccmexec.exe", "intunemanagementextension.exe", "agentexecutor.exe")
  AND grandparent NOT IN ("ccmexec.exe", "intunemanagementextension.exe", "agentexecutor.exe")
// net.exe re-launches as net1.exe and query.exe as quser/qwinsta, so each pair counts once
| EVAL recon = CASE(
    pname IN ("net.exe", "net1.exe"), "net",
    pname IN ("quser.exe", "qwinsta.exe", "query.exe"), "sessions",
    pname IN ("whoami.exe", "hostname.exe", "systeminfo.exe", "tasklist.exe", "ipconfig.exe",
              "nltest.exe", "arp.exe", "route.exe", "netstat.exe", "nbtstat.exe",
              "dsquery.exe", "setspn.exe", "klist.exe", "cmdkey.exe"), pname,
    NULL)
| WHERE recon IS NOT NULL
// user.name is DOMAIN\user or user depending on enrichment; group on the bare, lowercased name
| EVAL user.name = TO_LOWER(MV_LAST(SPLIT(user.name, "\\")))
| STATS distinct_recon = COUNT_DISTINCT(recon),
        commands = VALUES(recon),
        parents = VALUES(parent),
        host.name = VALUES(host.name)
    BY host.id, user.name, BUCKET(@timestamp, 10 minutes)
| WHERE distinct_recon >= 6
```
These are native Windows utilities, so the signal is the count and speed, not any one command. `reg.exe`, `wmic.exe` and `fsutil.exe` are not counted: installers and inventory scripts call them constantly and they are not discovery-specific. Tune the threshold on your estate.

## Suppression
Suppress by `host.id`, `user.name` for 1h. Alerts missing a key field are not suppressed. Aggregating rule. A burst spans buckets; a different host or user still alerts. `host.id` is the Falcon agent ID and is always present; `host.name` is filled only when the integration's host metadata enrichment is on.

## Known false positives / exclusions
- Login scripts, inventory agents and support scripts run several of these at logon. SCCM and Intune are excluded by parent and grandparent; add your RMM or login-script host the same way.
- Admins troubleshooting. Context plus the parent process usually separates them; a scripted parent spawning the burst is the suspicious case.

## Triage
- Look at the parent process. A burst spawned by a script host, an Office child or an unsigned binary is post-exploitation orientation. Pivot to what ran before it (the initial access) and after it (lateral movement, B04, or credential access, B08).

## Test
Run six or more of the listed commands in sequence on a lab host and confirm the rule fires.
