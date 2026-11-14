---
id: W20
name: Rare binary executed from a user-writable path - seen on two hosts or fewer in the fleet in a day
category: endpoint-windows
status: todo
language: esql
index: logs-yourorg-crowdstrike-data-default*
mitre: [T1204.002, T1036.005]
data_source: CrowdStrike FDR ProcessRollup2 (SHA256HashData)
suppression:
  fields: [data.SHA256HashData]
  duration: 24h
  missing_fields: do_not_suppress
---

Payloads land where a user can write: `AppData`, `Temp`, `Downloads`, `Users\Public`, `ProgramData`, `PerfLogs`. So
does a great deal of legitimate software: Teams, Zoom and VS Code install per-user, and updaters unpack into Temp.
Lists of "known good" names in these paths go stale within a month.

This rule does not use a list. It keys on **the file hash, across the fleet**. Software the estate runs is on many
machines. A payload is on one or two. A binary whose SHA-256 ran from a user-writable path on two hosts or fewer in
the last day, and ran within the last hour, is the rarity that matters. The hash also keeps a renamed copy of a
common tool in the same row as its original, so renaming does not make it look rare.

**Risk grade.** On its own this is a new download a user ran. `shape` raises it: a binary launched by Office, a
script host or a shell is delivery, not a user installing something.

Mounted disk images and ClickOnce, the container half of this item, are `W12` and `CLICKONCE-01`.

## Query

Run every hour with a 24-hour lookback. The 24 hours are the rarity window, and the last hour is what is new.

```esql
FROM logs-yourorg-crowdstrike-data-default*
| WHERE @timestamp >= NOW() - 24 hours
  AND event.action == "processrollup2"
  AND data.event_platform == "Win"
  AND data.SHA256HashData IS NOT NULL
| EVAL img = TO_LOWER(COALESCE(process.executable, ""))
// user-writable locations; per-user installs here are fleet-common, and the rarity test removes them without a list
| WHERE img LIKE """*\\appdata\\*""" OR img LIKE """*\\users\\public\\*""" OR img LIKE """*\\programdata\\*"""
     OR img LIKE """*\\windows\\temp\\*""" OR img LIKE """*\\perflogs\\*""" OR img LIKE """*\\downloads\\*"""
| STATS hosts = COUNT_DISTINCT(host.id),
        executions = COUNT(*),
        last_seen = MAX(@timestamp),
        names = MV_SLICE(VALUES(process.name), 0, 3),
        paths = MV_SLICE(VALUES(process.executable), 0, 3),
        host_sample = MV_SLICE(VALUES(host.name), 0, 3),
        users = MV_SLICE(VALUES(user.name), 0, 3),
        parents = MV_SLICE(VALUES(process.parent.name), 0, 3)
    BY data.SHA256HashData
// Baseline: a hash on 3+ hosts in a day is software the estate runs. One or two hosts is the rarity that matters;
// only rows whose latest run falls inside this run's 1-hour schedule are new.
| WHERE hosts <= 2 AND last_seen >= NOW() - 1 hour
| EVAL p = TO_LOWER(COALESCE(MV_CONCAT(parents, ","), "")),
       shape = CASE(p LIKE "*winword*" OR p LIKE "*excel*" OR p LIKE "*powerpnt*" OR p LIKE "*outlook*"
                    OR p LIKE "*acrord32*" OR p LIKE "*powershell*" OR p LIKE "*wscript*" OR p LIKE "*cscript*"
                    OR p LIKE "*mshta*" OR p LIKE "*cmd.exe*" OR p LIKE "*rundll32*" OR p LIKE "*regsvr32*",
                    "launched_by_office_or_script_host", "launched_by_user_or_other")
| SORT shape, last_seen DESC
| LIMIT 100
```

```logscale
#event_simpleName=ProcessRollup2 event_platform=Win
| ImageFileName=/\\(appdata|users\\public|programdata|windows\\temp|perflogs|downloads)\\/i
| SHA256HashData=*
| groupBy([SHA256HashData], function=[count(aid, distinct=true, as=hosts), count(as=executions), max(@timestamp, as=last_seen), collect([FileName, ComputerName, UserName, ParentBaseFileName], limit=5)], limit=max)
// Baseline: a hash on 3+ hosts in a day is software the estate runs; one or two hosts is the rarity that matters
| hosts <= 2
| test(last_seen >= (now() - 3600000))
| select([SHA256HashData, hosts, executions, last_seen, FileName, ComputerName, UserName, ParentBaseFileName])
```

## Before turning it on

Run the ES|QL over a normal day without the `last_seen` condition, and count the rows. That is the daily risk volume.
If it is too high for the risk score to absorb, scope `img` to the narrower paths (`Temp`, `Public`, `PerfLogs`,
`Downloads`) and leave `AppData` and `ProgramData` to the `shape` tier only.

## What it misses

- **Living off the land.** A signed system binary (`rundll32`, `mshta`) runs from `System32`, not a writable path.
  That is `W04` and `W03`.
- **A payload that is common on purpose.** A loader pushed to many hosts at once, for example through a compromised
  deployment tool, is not rare. `W13` (management platform deploying at scale) is the counterpart.
- **DLL sideloading.** The executable is a signed, common one, and the malicious code is a DLL beside it. Image-load
  events, not process starts, are what would show that.

## When it fires

Look the hash up in Falcon and your threat-intel source. Then check whether the binary wrote anything or made network
connections: pivot on the process's `ContextProcessId` / `TargetProcessId` to the network and file events.
