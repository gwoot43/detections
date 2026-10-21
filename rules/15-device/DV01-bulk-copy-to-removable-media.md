---
id: DV01
name: Bulk copy of documents or archives to removable media
category: device
status: todo
rank: 3
language: esql
index: logs-yourorg-crowdstrike-data-default*
mitre: [T1052.001, T1074.001]
data_source: CrowdStrike FDR file-written events flagged IsOnRemovableDisk (option A); Windows Security 4663 Removable Storage (option B)
suppression:
  fields: [host.id]
  duration: 12h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
Falcon records a file-written event for documents, archives, PDFs and executables, and flags the ones written to a removable disk. Normal USB use is a handful of files. Dozens of documents or archives copied to a stick within an hour is staging for exfiltration, or someone walking out with data. The insider rules (IN01-IN09) cover cloud downloads. This is the physical path they can't see.

## Query
**Option A: CrowdStrike FDR (recommended, no extra auditing needed)**
```esql
FROM logs-yourorg-crowdstrike-data-default*
| WHERE event.action LIKE "*filewritten" AND data.IsOnRemovableDisk IN ("1", "true")
| EVAL fpath = TO_LOWER(COALESCE(file.path, "")),
       is_archive = CASE(fpath RLIKE ".*\\.(zip|7z|rar|tar|gz|iso|vhdx?)", 1, 0)
| STATS files = COUNT_DISTINCT(fpath), archives = SUM(is_archive), users = VALUES(user.name), host_names = VALUES(host.name),
        file_types = VALUES(event.action), devices = VALUES(file.device), sample_files = VALUES(fpath),
        first_write = MIN(@timestamp), last_write = MAX(@timestamp)
    BY host.id
| WHERE files >= 25 OR archives >= 3
| EVAL sample_files = MV_SLICE(sample_files, 0, 19)
| KEEP host.id, host_names, users, files, archives, file_types, devices, first_write, last_write, sample_files
```

**CrowdStrike (Falcon LogScale / Advanced Event Search)**, run over the last hour:
```logscale
#event_simpleName=/FileWritten$/
| in(field="IsOnRemovableDisk", values=["1", "true"])
| fpath := lower(TargetFileName)
| case {
    fpath=/\.(zip|7z|rar|tar|gz|iso|vhdx?)$/ | is_archive := 1;
    * | is_archive := 0;
  }
| groupBy([aid], function=[count(fpath, distinct=true, as=files), sum(is_archive, as=archives),
                           collect([UserName, ComputerName, #event_simpleName, DiskParentDeviceInstanceId]),
                           collect([fpath], limit=20),
                           min(@timestamp, as=first_write), max(@timestamp, as=last_write)], limit=max)
| test(files >= 25 OR archives >= 3)
| rename(field=fpath, as=sample_files)
| first_write := formatTime(format="%F %T", field=first_write, timezone="Australia/Sydney")
| last_write := formatTime(format="%F %T", field=last_write, timezone="Australia/Sydney")
```
Run every 15 minutes with a 1-hour lookback.

Falcon only emits `*FileWritten` events for the file types it tracks (Office documents, PDFs, archives, executables and scripts). That is the content that matters here. The `file.device` column is the removable disk's device instance ID, so you can tell one stick from another.

The query groups on `host.id` (the Falcon agent ID), which every FDR event carries. `host.name` and `user.name` are only filled when the CrowdStrike integration's "Enrich Host and User Metadata" option is on. Grouping on an empty `host.name` would add every host's writes into one row.

**Option B: Windows Security 4663 (needs "Audit Removable Storage")**
```esql
FROM logs-system.security*, logs-windows.forwarded*
| WHERE event.code == "4663" AND winlog.task == "Removable Storage"
| EVAL access = MV_CONCAT(TO_STRING(winlog.event_data.AccessList), ","),
       obj = TO_LOWER(COALESCE(winlog.event_data.ObjectName, "")),
       host_key = TO_LOWER(COALESCE(winlog.computer_name, host.name))
| WHERE access LIKE "*4417*"
| STATS files = COUNT_DISTINCT(obj), first_write = MIN(@timestamp), last_write = MAX(@timestamp),
        sample_files = VALUES(obj)
    BY host_key, winlog.event_data.SubjectUserName
| WHERE files >= 100
| EVAL sample_files = MV_SLICE(sample_files, 0, 19)
```
4663 logs every object touched, not only documents, so the threshold is higher. `4417` is the WriteData access code. `AccessList` is multi-valued, which is why it's joined into one string before matching. Use `winlog.computer_name` because, with event forwarding, `host.name` is the collector.

## Suppression
Suppress by `host.id` (option B: `host_key`) for 12h. Alerts missing a key field are not suppressed. One copy session spans several runs of the 1-hour lookback.

## Known false positives / exclusions
- **Approved transfers:** the IT build team, forensics workstations, and media production teams moving large projects. Add their `host.id` values to the WHERE.
- **Backup to USB disk** on standalone kiosks or lab machines.
- If you run CrowdStrike Device Control with USB storage blocked, this rule only sees the approved device classes, so it doubles as a check that the allow list is not abused.

## Triage
- Who was logged on (`users`), and are they a leaver, on a performance plan, or on notice? Check with HR through the insider-risk process before contacting them.
- Look at `sample_files` for sensitive names, and check whether the same files were pulled from SharePoint first (IN01, IN09).
- `devices` identifies the stick. Search FDR for the same device ID on other hosts.

## Test
Copy 30 Office documents or 3 zip files to a USB stick on a lab host and confirm the FDR events carry `data.IsOnRemovableDisk`.
