---
id: IN01
name: Mass SharePoint or OneDrive download by one user
category: insider
status: todo
severity: high
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

## Query
Run hourly with a 1-hour lookback.
```esql
FROM logs-o365.audit-*
| WHERE event.provider IN ("SharePoint", "OneDrive")
  AND event.action IN ("FileDownloaded", "FileSyncDownloadedFull")
| EVAL usr = TO_LOWER(o365.audit.UserId)
| WHERE NOT (usr IN ("app@sharepoint", "system account", "sharepoint\\system")
             OR usr IN ("svc-migration@yourdomain.com", "svc-backup@yourdomain.com"))   // migration and backup accounts
| STATS files = COUNT_DISTINCT(url.original),
        downloads = COUNT(*),
        sites = COUNT_DISTINCT(o365.audit.SiteUrl),
        client_ips = VALUES(source.ip),
        sample = VALUES(file.name)
    BY usr, BUCKET(@timestamp, 1 hour)
| WHERE files >= 200
```
For SharePoint file operations the integration moves `Workload` to `event.provider`, `ObjectId` (the full file URL) to `url.original`, `SourceFileName` to `file.name`, and `ClientIP` to `source.ip`. `FileSyncDownloadedFull` is the OneDrive client syncing a library; a burst of it is a bulk pull to a device. Tune `files` to your normal peak.

## Suppression
Suppress by `usr` for 12h. Alerts missing a key field are not suppressed. Aggregating rule. A large pull spans buckets; a different user still alerts.

## Known false positives / exclusions
- A user's first OneDrive sync on a new device downloads many files once. Check `client_ips` and the device before escalating, or accept the occasional onboarding hit.
- Migration and backup service accounts. Keep them in the inline exclusion.

## Triage
- Check whether the user is a leaver or under notice (the strongest context), the client IP (home or unmanaged device raises concern), and the sites involved (sensitive or team content they do not own).
- Combine with IN02 external sharing and IN05 personal-webmail exfil for the same user in the same period.

## Test
Download or sync a few hundred files from a lab SharePoint library as a test user.
