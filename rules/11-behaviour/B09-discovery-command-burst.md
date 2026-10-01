---
id: B09
name: Host discovery command burst (many distinct recon utilities quickly)
category: behaviour
status: todo
severity: medium
language: esql
index: logs-crowdstrike.fdr-*
mitre: [T1033, T1016, T1057, T1082, T1087, T1049]
data_source: CrowdStrike FDR ProcessRollup2
suppression:
  fields: [host.name, user.name]
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
| EVAL pname = TO_LOWER(process.name)
| EVAL recon = CASE(
    pname IN ("whoami.exe", "hostname.exe", "systeminfo.exe", "tasklist.exe", "ipconfig.exe",
              "net.exe", "net1.exe", "nltest.exe", "arp.exe", "route.exe", "netstat.exe",
              "nbtstat.exe", "quser.exe", "qwinsta.exe", "query.exe", "wmic.exe",
              "dsquery.exe", "setspn.exe", "klist.exe", "reg.exe", "fsutil.exe", "cmdkey.exe"),
    pname, NULL)
| WHERE recon IS NOT NULL
| STATS distinct_recon = COUNT_DISTINCT(recon),
        commands = VALUES(recon),
        parents = VALUES(process.parent.name)
    BY host.name, user.name, BUCKET(@timestamp, 10 minutes)
| WHERE distinct_recon >= 6
```
These are native Windows utilities, so the signal is the count and speed, not any one command. Tune the threshold on your estate.

## Suppression
Suppress by `host.name`, `user.name` for 1h. Alerts missing a key field are not suppressed. Aggregating rule. A burst spans buckets; a different host or user still alerts.

## Known false positives / exclusions
- Login scripts, inventory agents and support scripts run several of these at logon. Exclude the parent process (the agent or the login script host) inline, and consider excluding the first few minutes after a user logon.
- Admins troubleshooting. Context plus the parent process usually separates them; a scripted parent spawning the burst is the suspicious case.

## Triage
- Look at the parent process. A burst spawned by a script host, an Office child or an unsigned binary is post-exploitation orientation. Pivot to what ran before it (the initial access) and after it (lateral movement, B04, or credential access, B08).

## Test
Run six or more of the listed commands in sequence on a lab host and confirm the rule fires.
