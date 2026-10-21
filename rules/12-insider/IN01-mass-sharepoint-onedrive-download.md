---
id: IN01
name: Mass SharePoint or OneDrive download by one user, at any hour or as a smaller after-hours burst
category: insider
status: todo
language: esql
index: logs-o365.audit-*
mitre: [T1213.002, T1530, T1119]
data_source: Microsoft 365 Unified Audit Log (SharePoint file operations)
suppression:
  fields: [usr]
  duration: 12h
  missing_fields: do_not_suppress
---
## Why this is high fidelity for insider risk
The unified audit log records SharePoint and OneDrive file activity without any Graph API feed. Bulk downloading, or syncing a whole library to a device, is the clearest sign of someone taking data, and it spikes when a person is leaving. This counts distinct files downloaded or synced by one user in an hour, which a normal day of work does not reach.

Data theft also happens when few people are watching: nights and weekends. A bulk download concentrated outside working hours is more suspicious than the same volume during the day, because the legitimate reasons are fewer. So the rule has two thresholds, and the `tier` column says which one was met:
- `volume`: 200 or more distinct files downloaded or synced in an hour, at any time of day.
- `after_hours`: 75 or more distinct files downloaded through the browser (`FileDownloaded`) in an hour before 07:00, from 19:00, or at the weekend. The time of day already narrows it, so the threshold is lower.
- `volume_after_hours`: both at once.

## Query
Run hourly with a 1-hour lookback.
```esql
FROM logs-o365.audit-*
| WHERE event.provider IN ("SharePoint", "OneDrive")
  AND event.action IN ("FileDownloaded", "FileSyncDownloadedFull")
| EVAL usr = TO_LOWER(o365.audit.UserId),
       hour = DATE_EXTRACT("hour_of_day", @timestamp),       // UTC; shift for your timezone
       dow = DATE_EXTRACT("day_of_week", @timestamp)         // 6 = Saturday, 7 = Sunday
| WHERE NOT (usr IN ("app@sharepoint", "system account", "sharepoint\\system")
             OR usr IN ("svc-migration@yourdomain.com", "svc-backup@yourdomain.com"))   // migration and backup accounts
// after-hours tier: browser downloads only; client sync catching up overnight is not counted
| EVAL after_hours_file = CASE(event.action == "FileDownloaded" AND (hour < 7 OR hour >= 19 OR dow >= 6), url.original, NULL)
| STATS files = COUNT_DISTINCT(url.original),
        after_hours_files = COUNT_DISTINCT(after_hours_file),
        downloads = COUNT(*),
        sites = COUNT_DISTINCT(o365.audit.SiteUrl),
        client_ips = VALUES(source.ip),
        sample = VALUES(file.name)
    BY usr, BUCKET(@timestamp, 1 hour)
| WHERE files >= 200 OR after_hours_files >= 75
| EVAL tier = CASE(files >= 200 AND after_hours_files >= 75, "volume_after_hours",
                   files >= 200, "volume",
                   "after_hours")
```
For SharePoint file operations the integration moves `Workload` to `event.provider`, `ObjectId` (the full file URL) to `url.original`, `SourceFileName` to `file.name`, and `ClientIP` to `source.ip`. `FileSyncDownloadedFull` is the OneDrive client syncing a library; a burst of it is a bulk pull to a device. Tune `files` to your normal peak.

`DATE_EXTRACT` works in UTC. Adjust the hour boundaries to your main timezone, or subtract an offset before comparing. OneDrive client sync is left out of the after-hours count: a laptop left on overnight catches up on colleagues' changes, which is the main false positive at that threshold. Bulk sync is still caught by the `volume` tier at any hour.

## Suppression
Suppress by `usr` for 12h. Alerts missing a key field are not suppressed. Aggregating rule. A large pull spans buckets; a different user still alerts.

## Known false positives / exclusions
- A user's first OneDrive sync on a new device downloads many files once. Check `client_ips` and the device before escalating, or accept the occasional onboarding hit.
- Migration and backup service accounts. Keep them in the inline exclusion.
- `after_hours`: shift workers, global teams and genuine evening work. If you have night shifts, scope the after-hours tier to day-shift populations or raise its threshold.
- `after_hours`: browser or script downloads by a scheduled job running as a user. Check `client_ips` and the user agent, and exclude the job's account.

## Triage
- Check whether the user is a leaver or under notice (the strongest context), the client IP (home or unmanaged device raises concern), and the sites involved (sensitive or team content they do not own).
- `after_hours`: confirm the user normally works those hours and from that location. An after-hours bulk download from a home or unmanaged IP, especially by a leaver, is exfiltration.
- Combine with IN02 external sharing and IN05 personal-webmail exfil for the same user in the same period.

## Test
Download or sync a few hundred files from a lab SharePoint library as a test user. For the after-hours tier, download 75 or more files through the browser at a time outside your configured business hours.
