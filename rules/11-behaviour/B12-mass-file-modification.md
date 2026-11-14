---
id: B12
name: Mass file modification - files rewritten, renamed or replaced at ransomware speed in synced or cloud storage
category: behaviour
status: todo
language: esql
index: logs-o365.audit-*
mitre: [T1486, T1485]
data_source: O365 unified audit (SharePoint and OneDrive file operations)
suppression:
  fields: [usr]
  duration: 6h
  missing_fields: do_not_suppress
---

**This is the last line of defence.** If it fires, the backup-tampering (`W06`) and security-tampering (`W05`, `W19`,
`CS05`) rules have already missed. Pair it with automated host isolation, not a ticket.

Encryption has a shape whatever the family: one identity rewrites, renames or replaces hundreds of files in minutes,
often appending one new extension, and drops the same ransom note into many folders.

**What this estate can see.** Windows endpoint file-write events are not collected. The only file events in the FDR
index are deletions. So endpoint encryption on a local disk or a mapped share is not directly visible, and that gap is
stated, not papered over. What **is** collected is the O365 audit log, which sees every file a OneDrive or SharePoint
sync client changes. Ransomware on a laptop with OneDrive sync, or on a host with a synced library, encrypts the
synced copy too. So this rule fires within minutes of encryption reaching those folders.

The Linux and ESXi version is `L10`. The host-side precursor chain is `X05`. Falcon's own ransomware detections are
`CS04`.

## Query

Run every 5 minutes with a 15-minute lookback.

```esql
FROM logs-o365.audit-*
| WHERE event.provider IN ("SharePoint", "OneDrive")
  AND event.action IN ("FileModified", "FileModifiedExtended", "FileRenamed", "FileUploaded", "FileDeleted")
| EVAL usr = TO_LOWER(COALESCE(o365.audit.UserId, "")),
       fname = TO_LOWER(COALESCE(o365.audit.SourceFileName, "")),
       new_ext = TO_LOWER(COALESCE(o365.audit.DestinationFileExtension, "")),
       renamed = event.action == "FileRenamed",
       // ransom-note names: one note per folder is the encryptor's habit. Leading wildcard on purpose: the note's
       // keyword sits anywhere in its file name (!!READ_ME!!.txt, HOW_TO_DECRYPT.html)
       note = event.action == "FileUploaded"
              AND (fname LIKE "*readme*" OR fname LIKE "*decrypt*" OR fname LIKE "*restore*" OR fname LIKE "*recover*"
                   OR fname LIKE "*ransom*" OR fname LIKE "*how_to*")
| WHERE usr != "" AND NOT (usr IN ("app@sharepoint", "system account"))     // the service's own housekeeping
| STATS changed_files = COUNT_DISTINCT(url.original),
        renames = COUNT(*) WHERE renamed,
        deletes = COUNT(*) WHERE event.action == "FileDeleted",
        rename_exts = COUNT_DISTINCT(CASE(renamed, new_ext, NULL)),
        top_new_exts = MV_SLICE(VALUES(CASE(renamed, new_ext, NULL)), 0, 5),
        notes = COUNT(*) WHERE note,
        note_folders = COUNT_DISTINCT(CASE(note, o365.audit.SourceRelativeUrl, NULL)),
        sites = COUNT_DISTINCT(o365.audit.SiteUrl),
        clients = MV_SLICE(VALUES(user_agent.original), 0, 3),
        ips = MV_SLICE(VALUES(TO_STRING(source.ip)), 0, 3),
        first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
    BY usr, BUCKET(@timestamp, 15 minutes)
// Baseline: a sync client catching up after a laptop rebuild changes many files but renames almost none and drops
// no notes. Encryption renames or replaces at volume, or leaves the same note in several folders. 100 files and 50
// renames/deletes in 15 minutes are starting values; set them above your own p99 with the baseline query below.
| WHERE (changed_files >= 100 AND (renames >= 50 OR deletes >= 50))
     OR note_folders >= 3
| EVAL shape = CASE(note_folders >= 3, "ransom_note_dropped_across_folders",
                    renames >= 50 AND rename_exts <= 2, "bulk_rename_to_one_new_extension",
                    "bulk_rewrite_or_replace")
| SORT changed_files DESC
| LIMIT 50
```

## Before turning it on

Measure the busiest legitimate 15 minutes per user:

```esql
FROM logs-o365.audit-*
| WHERE @timestamp >= NOW() - 14 days
  AND event.provider IN ("SharePoint", "OneDrive")
  AND event.action IN ("FileModified", "FileRenamed", "FileUploaded", "FileDeleted")
| STATS changed_files = COUNT_DISTINCT(url.original), renames = COUNT(*) WHERE event.action == "FileRenamed"
    BY o365.audit.UserId, BUCKET(@timestamp, 15 minutes)
// second STATS: per-user, per-window counts into the percentiles the thresholds are set from
| STATS p99_files = PERCENTILE(changed_files, 99), max_files = MAX(changed_files),
        p99_renames = PERCENTILE(renames, 99), max_renames = MAX(renames)
```

Also confirm the field names on one real `FileRenamed` event: `DestinationFileExtension`, `SourceFileName` and
`SourceRelativeUrl`. The O365 integration maps them from the audit record, and a mis-mapped field returns null
without an error.

For the endpoint half, check whether any Windows file-write telemetry exists before assuming it does not:

```esql
FROM logs-yourorg-crowdstrike-data-default*
| WHERE @timestamp >= NOW() - 24 hours AND data.event_platform == "Win"
  // leading wildcard on purpose: this probe exists to discover which file event names arrive at all
  AND event.action LIKE "*file*"
| STATS events = COUNT(*) BY event.action
| SORT events DESC
```

## What it misses

- **Encryption of local disks and file shares that are not synced to OneDrive or SharePoint.** This is the gap.
  Closing it needs Falcon file-write telemetry on Windows (an FDR subscription change), or `4663` with a SACL on the
  file servers' share roots. Until then, `CS04` (Falcon's own ransomware verdicts) and the `X05` precursor chain are
  the endpoint coverage.
- **Slow encryption** under the threshold, for example intermittent encryption of large files only.
- **Encryption by a service account that the exclusion list removes.** Keep the exclusion to the two built-in service
  identities only.

## When it fires

Isolate every host the `usr` is signed in to, then suspend the user's sync session. OneDrive's **Restore your
OneDrive** rolls a library back to before `first_seen`. Do that only after the encrypting host is off the network.
