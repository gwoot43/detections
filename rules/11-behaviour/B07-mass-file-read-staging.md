---
id: B07
name: Mass file read or collection by a single process
category: behaviour
status: todo
severity: medium
language: esql
index: logs-crowdstrike.fdr-*
mitre: [T1119, T1005, T1552.001]
data_source: CrowdStrike FDR file access events
suppression:
  fields: [host.name, process.name]
  duration: 1h
  missing_fields: do_not_suppress
---
## Why this is behavioural and high fidelity
Secret scanners like TruffleHog and gitleaks, data-collection scripts, infostealers and the read phase before ransomware all do the same thing: one process opens a very large number of distinct files across many directories in a short time. This counts that behaviour rather than matching a tool, so a renamed or custom collector is caught. Interactive users and most applications touch few files per minute.

## Query
Run every 10 minutes with a 15-minute lookback.
```esql
FROM logs-crowdstrike.fdr-*
| WHERE event.category == "file" AND TO_LOWER(event.action) RLIKE ".*(open|read).*"
  AND file.path IS NOT NULL
| STATS files = COUNT_DISTINCT(file.path),
        dirs = COUNT_DISTINCT(file.directory),
        extensions = COUNT_DISTINCT(file.extension),
        sample_ext = VALUES(file.extension)
    BY host.name, process.name, user.name, BUCKET(@timestamp, 5 minutes)
| WHERE files >= 300 AND dirs >= 20
```
File-read telemetry is high volume and may be sampled or off by default in CrowdStrike. Confirm the read event name and that collection is enabled before relying on this. Tune `files` and `dirs` to your environment.

## Suppression
Suppress by `host.name`, `process.name` for 1h. Alerts missing a key field are not suppressed. Aggregating rule. A sweep spans buckets; a different process still alerts.

## Known false positives / exclusions
- Backup agents, indexers (search, antivirus scans), build tools and IDEs read many files by design. These are few and named; exclude them inline by process name.
- Developer machines running local scans. Scope the rule to servers, or exclude developer hosts inline, if this is noisy.

## Triage
- Identify the process and the directories touched. A shell, interpreter or unsigned binary reading hundreds of files across source, config or user-profile directories is collection or secret scanning. Check for a following upload (B06, N08) and archive creation (B07 companion: a large archive written right after).

## Test
Run TruffleHog or a recursive secret scan over a lab directory tree and confirm the file count fires.
