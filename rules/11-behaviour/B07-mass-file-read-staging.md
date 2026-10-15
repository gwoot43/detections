---
id: B07
name: Mass file read or collection - catches TruffleHog, gitleaks and data-collection tools by behaviour
category: behaviour
status: todo
severity: medium
language: esql
index: logs-crowdstrike.fdr-*
mitre: [T1119, T1005, T1552.001]
data_source: CrowdStrike FDR file access events
suppression:
  fields: [host.id, process.entity_id]
  duration: 1h
  missing_fields: do_not_suppress
---
## Why this is behavioural and high fidelity
Secret scanners like TruffleHog and gitleaks, data-collection scripts, infostealers and the read phase before ransomware all do the same thing: one process opens a very large number of distinct files across many directories in a short time. This counts that behaviour rather than matching a tool, so a renamed or custom collector is caught. Interactive users and most applications touch few files per minute.

## Query
Run every 10 minutes with a 15-minute lookback.
```esql
FROM logs-crowdstrike.fdr-*
| WHERE event.action IN ("FileOpenInfo", "FsPostOpen") AND file.path IS NOT NULL
// file-open events often lack the process name; fall back to the raw context name, then group by process instance
| EVAL process.name = TO_LOWER(COALESCE(process.name, crowdstrike.ContextBaseFileName, "unknown"))
// search indexers, AV and sync agents read many files by design; add your backup agent here
| WHERE process.name NOT IN ("searchprotocolhost.exe", "searchfilterhost.exe", "searchindexer.exe",
                             "msmpeng.exe", "mssense.exe", "csfalconservice.exe", "onedrive.exe")
| STATS files = COUNT_DISTINCT(file.path),
        dirs = COUNT_DISTINCT(file.directory),
        extensions = COUNT_DISTINCT(file.extension),
        sample_ext = VALUES(file.extension),
        pname = VALUES(process.name),
        host.name = VALUES(host.name)
    BY host.id, process.entity_id, BUCKET(@timestamp, 5 minutes)
| WHERE files >= 300 AND dirs >= 20
```

**CrowdStrike (Falcon LogScale / Advanced Event Search)**
```logscale
#event_simpleName=/^(FileOpenInfo|FsPostOpen)$/ TargetFileName=*
// file-open events often lack the process name; group by process instance
| pname := lower(ContextBaseFileName)
| default(field=pname, value="unknown", replaceEmpty=true)
// search indexers, AV and sync agents read many files by design; add your backup agent here
| !in(field="pname", values=["searchprotocolhost.exe", "searchfilterhost.exe", "searchindexer.exe",
                              "msmpeng.exe", "mssense.exe", "csfalconservice.exe", "onedrive.exe"])
// directory and extension split from the path, as the Elastic integration does for file.directory and file.extension
| case {
    TargetFileName=/^(?<fdir>.*)[\\\/][^\\\/]+$/;
    *;
  }
| case {
    TargetFileName=/[\\\/][^\\\/]*\.(?<fext>[^.\\\/]*)$/;
    *;
  }
| bucket_start := @timestamp - (@timestamp % 300000)
| groupBy([aid, ContextProcessId, bucket_start], function=[count(TargetFileName, distinct=true, as=files), count(fdir, distinct=true, as=dirs),
                                                          count(fext, distinct=true, as=extensions), collect([fext, pname, ComputerName])],
          limit=max)
| test(files >= 300 AND dirs >= 20)
| bucket_start := formatTime(format="%F %T", field=bucket_start, timezone="Australia/Sydney")
```
File-read telemetry is high volume and may be sampled or off by default in CrowdStrike. Confirm which of these events your feed sends and that collection is enabled before relying on this. Counting per process instance (`process.entity_id`) keeps two busy processes on one host from adding up. Tune `files` and `dirs` to your environment.

## Suppression
Suppress by `host.id`, `process.entity_id` for 1h. Alerts missing a key field are not suppressed. Aggregating rule. A sweep spans buckets; a different process still alerts. `host.id` is the Falcon agent ID and is always present; `host.name` is filled only when the integration's host metadata enrichment is on.

## Known false positives / exclusions
- Backup agents, indexers (search, antivirus scans), build tools and IDEs read many files by design. Windows Search, Defender, Falcon and OneDrive are excluded by name; add the rest inline. Name exclusions only work when the event carries a process name.
- Developer machines running local scans. Scope the rule to servers, or exclude developer hosts inline, if this is noisy.

## Triage
- Identify the process (find its ProcessRollup2 by `process.entity_id`) and the directories touched. A shell, interpreter or unsigned binary reading hundreds of files across source, config or user-profile directories is collection or secret scanning. Check for a following upload (B06, N08) and archive creation (B07 companion: a large archive written right after).

## Test
Run TruffleHog or a recursive secret scan over a lab directory tree and confirm the file count fires.
