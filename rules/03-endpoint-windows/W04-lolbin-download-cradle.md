---
id: W04
name: Windows built-in program run with a URL that few hosts use
category: endpoint-windows
status: todo
severity: high
language: esql
index: logs-crowdstrike.fdr-*
mitre: [T1105, T1218.005, T1218.010, T1218.011, T1197, T1059.001, T1218.007]
data_source: CrowdStrike FDR ProcessRollup2
suppression:
  fields: [host.id, pname]
  duration: 24h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
Living-off-the-land downloads (`certutil -urlcache`, `bitsadmin /transfer`, `mshta http://`, `regsvr32 /i:http`, `msiexec /i http`, `curl`, PowerShell `DownloadString`) all share one trait: a Windows built-in program with a URL on its command line. The rule matches that trait instead of listing each program and its arguments, so it also catches the ones nobody listed.

Admin scripts and installers do the same thing, but they do it on many hosts against the same few domains. Attackers do it on one or two. So the rule counts, across the whole fleet, how many hosts ran the same program against the same domain, and only alerts when it is 3 or fewer.

Two things are left out:
- `cmd.exe`, because it can't download anything itself. The program it starts carries the URL and is matched instead.
- `rundll32 url.dll,FileProtocolHandler`, which is how many apps open a link in the browser.

Commands launched by Explorer are W03.

## Query
Run hourly with a 24-hour lookback, so "few hosts" means few hosts in the last day.
```esql
FROM logs-crowdstrike.fdr-*
| WHERE event.action == "ProcessRollup2" AND host.os.type == "windows"
| EVAL pname = TO_LOWER(process.name),
       parent = TO_LOWER(COALESCE(process.parent.name, "")),
       path = TO_LOWER(COALESCE(process.executable, "")),
       cmd = TO_LOWER(COALESCE(process.command_line, ""))
| WHERE path RLIKE """.*\\windows\\(system32|syswow64)\\.*""" AND cmd LIKE "*http*://*"
| WHERE parent != "explorer.exe" AND pname != "cmd.exe" AND NOT cmd LIKE "*fileprotocolhandler*"
| GROK cmd """https?://%{IPORHOST:url_host}"""
| STATS runs = COUNT(*),
        first_seen = MIN(@timestamp),
        last_seen = MAX(@timestamp),
        host.name = VALUES(host.name),
        users = VALUES(user.name),
        parents = VALUES(parent),
        commands = VALUES(process.command_line)
    BY host.id, pname, url_host
| INLINE STATS hosts = COUNT_DISTINCT(host.id) BY pname, url_host
| WHERE hosts <= 3
| KEEP host.id, host.name, pname, url_host, hosts, runs, first_seen, last_seen, users, parents, commands
```

**Not covered:** encoded PowerShell with no visible URL (W15), `certutil -decode` of a file already on disk, and inline `javascript:` in `mshta` or `rundll32`.

## Suppression
Suppress by `host.id`, `pname` for 24h. Alerts missing a key field are not suppressed. Aggregating rule: each hourly run sees the same 24 hours again. A different host or program still alerts.

## Known false positives / exclusions
- Developers using `curl.exe` against niche sites. Each one is rare, so each one alerts. If that's noisy, exclude the developer hosts' group, not `curl`.
- A new internal tool rolled out to only a few hosts. It drops out on its own once more than 3 hosts run it.

## Triage
- `url_host` and `commands` show what was fetched. Check the domain in Zscaler (N07), look for a file written just after the command, and look for network connections from the process.

## Test
On a lab host, run `certutil -urlcache -f http://<lab-server>/test.txt test.txt`.
