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
// Activity: file opens. Filename fallback: gitleaks or Nosey Parker starting on a folder rather than a repository,
// which alerts even when file-read telemetry is off or sampled. TruffleHog by name is CS17.
| WHERE (event.action IN ("FileOpenInfo", "FsPostOpen") AND file.path IS NOT NULL)
     OR (event.action IN ("ProcessRollup2", "SyntheticProcessRollup2")
         AND TO_LOWER(process.name) IN ("gitleaks", "gitleaks.exe", "noseyparker", "noseyparker.exe"))
// file-open events often lack the process name; fall back to the raw context name, then group by process instance
| EVAL process.name = TO_LOWER(COALESCE(process.name, crowdstrike.ContextBaseFileName, "unknown")),
       cmd = TO_LOWER(COALESCE(process.command_line, "")),
       // gitleaks scans a folder with `dir` or `detect --no-git`, Nosey Parker with `scan`; on a repository it's a team's own check
       named = event.action IN ("ProcessRollup2", "SyntheticProcessRollup2")
               AND (cmd RLIKE ".* (dir|directory)( .*)?" OR cmd LIKE "*--no-git*" OR (process.name LIKE "noseyparker*" AND cmd RLIKE ".* scan( .*)?"))
| WHERE named OR event.action IN ("FileOpenInfo", "FsPostOpen")
// search indexers, AV and sync agents read many files by design; add your backup agent here
| WHERE process.name NOT IN ("searchprotocolhost.exe", "searchfilterhost.exe", "searchindexer.exe",
                             "msmpeng.exe", "mssense.exe", "csfalconservice.exe", "onedrive.exe")
// One row per process and 5-minute window: how many files and folders it read.
| STATS files = COUNT_DISTINCT(file.path),
        dirs = COUNT_DISTINCT(file.directory),
        extensions = COUNT_DISTINCT(file.extension),
        sample_ext = VALUES(file.extension),
        named = MAX(CASE(named, 1, 0)),
        process.command_line = VALUES(process.command_line),
        pname = VALUES(process.name),
        host.name = VALUES(host.name)
    BY host.id, process.entity_id, BUCKET(@timestamp, 5 minutes)
// One row per process: whether any window was a mass read, and whether it started as a scanner.
| EVAL mass_read = CASE(files >= 300 AND dirs >= 20, 1, 0)
| STATS mass_read = MAX(mass_read), named = MAX(named), files = MAX(files), dirs = MAX(dirs), extensions = MAX(extensions),
        sample_ext = VALUES(sample_ext), process.command_line = VALUES(process.command_line), pname = VALUES(pname),
        host.name = VALUES(host.name)
    BY host.id, process.entity_id
// Activity first: 300+ files in 20+ folders in one window. Then the filename fallback.
| WHERE mass_read == 1 OR named == 1
| EVAL finding = CASE(mass_read == 1 AND named == 1, "secret scanner reading a folder tree",
                      mass_read == 1, "mass file read by behaviour",
                      "secret scanner started on a folder (by name)")
```

**CrowdStrike (Falcon LogScale / Advanced Event Search)**
```logscale
#event_simpleName=/^(FileOpenInfo|FsPostOpen|ProcessRollup2|SyntheticProcessRollup2)$/
| case {
    // Activity: file opens, grouped by process instance (file-open events often lack the process name).
    #event_simpleName=/^(FileOpenInfo|FsPostOpen)$/ TargetFileName=*
      | falconPID := ContextProcessId | pname := lower(ContextBaseFileName);
    // Filename fallback: gitleaks or Nosey Parker starting on a folder rather than a repository.
    FileName=/^gitleaks(\.exe)?$/i CommandLine=/ (dir|directory)( |$)|--no-git/i
      | falconPID := TargetProcessId | pname := lower(FileName) | named := 1;
    FileName=/^noseyparker(\.exe)?$/i CommandLine=/ scan( |$)/i
      | falconPID := TargetProcessId | pname := lower(FileName) | named := 1;
  }
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
// One row per process and 5-minute window: how many files and folders it read.
| bucket_start := @timestamp - (@timestamp % 300000)
| groupBy([aid, falconPID, bucket_start], function=[count(TargetFileName, distinct=true, as=files), count(fdir, distinct=true, as=dirs),
                                                    count(fext, distinct=true, as=extensions), count(named, as=named),
                                                    collect([fext, pname, ComputerName, CommandLine])], limit=max)
// One row per process: whether any window was a mass read, and whether it started as a scanner.
| case {
    test(files >= 300 AND dirs >= 20) | mass_read := 1;
    *;
  }
| groupBy([aid, falconPID], function=[count(mass_read, as=mass_windows), sum(named, as=named), max(files, as=files), max(dirs, as=dirs),
                                      collect([fext, pname, ComputerName, CommandLine])], limit=max)
// Activity first: 300+ files in 20+ folders in one window. Then the filename fallback.
| test(mass_windows > 0 OR named > 0)
| case {
    test(mass_windows > 0 AND named > 0) | finding := "secret scanner reading a folder tree";
    test(mass_windows > 0) | finding := "mass file read by behaviour";
    * | finding := "secret scanner started on a folder (by name)";
  }
```
File-read telemetry is high volume and may be sampled or off by default in CrowdStrike. Confirm which of these events your feed sends and that collection is enabled before relying on the activity half; the filename fallback (gitleaks or Nosey Parker run on a folder) works without it. `finding` says which fired. Counting per process instance (`process.entity_id`) keeps two busy processes on one host from adding up. Tune `files` and `dirs` to your environment.

## Suppression
Suppress by `host.id`, `process.entity_id` for 1h. Alerts missing a key field are not suppressed. Aggregating rule. A sweep spans buckets; a different process still alerts. `host.id` is the Falcon agent ID and is always present; `host.name` is filled only when the integration's host metadata enrichment is on.

## Known false positives / exclusions
- Backup agents, indexers (search, antivirus scans), build tools and IDEs read many files by design. Windows Search, Defender, Falcon and OneDrive are excluded by name; add the rest inline. Name exclusions only work when the event carries a process name.
- Developer machines running local scans. Scope the rule to servers, or exclude developer hosts inline, if this is noisy.

## Triage
- Identify the process (find its ProcessRollup2 by `process.entity_id`) and the directories touched. A shell, interpreter or unsigned binary reading hundreds of files across source, config or user-profile directories is collection or secret scanning. Check for a following upload (B06, N08) and archive creation (B07 companion: a large archive written right after).

## Test
Run TruffleHog or a recursive secret scan over a lab directory tree and confirm the file count fires.
