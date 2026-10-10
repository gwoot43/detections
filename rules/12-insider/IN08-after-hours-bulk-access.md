---
id: IN08
name: After-hours bulk download from SharePoint or OneDrive
category: insider
status: todo
severity: medium
language: esql
index: logs-o365.audit-*
mitre: [T1213.002, T1530]
data_source: Microsoft 365 Unified Audit Log (SharePoint file operations)
suppression:
  fields: [usr]
  duration: 12h
  missing_fields: do_not_suppress
---
## Why this is high fidelity for insider risk
Data theft often happens when few people are watching: nights and weekends. A bulk download concentrated outside working hours is more suspicious than the same volume during the day, because the legitimate reasons are fewer. This flags download bursts whose timestamps fall outside business hours, at a lower volume threshold than the daytime rule IN01.

## Query
Run hourly with a 1-hour lookback.
```esql
FROM logs-o365.audit-*
| WHERE event.provider IN ("SharePoint", "OneDrive")
  AND event.action == "FileDownloaded"
| EVAL usr = TO_LOWER(o365.audit.UserId),
       hour = DATE_EXTRACT("hour_of_day", @timestamp),       // UTC; shift for your timezone
       dow = DATE_EXTRACT("day_of_week", @timestamp)         // 6 = Saturday, 7 = Sunday
| WHERE NOT (usr IN ("app@sharepoint", "system account", "sharepoint\\system")
             OR usr IN ("svc-migration@yourdomain.com", "svc-backup@yourdomain.com"))   // migration and backup accounts
  AND (hour < 7 OR hour >= 19 OR dow >= 6)
| STATS files = COUNT_DISTINCT(url.original),
        downloads = COUNT(*),
        client_ips = VALUES(source.ip)
    BY usr, BUCKET(@timestamp, 1 hour)
| WHERE files >= 75
```
`DATE_EXTRACT` works in UTC. Adjust the hour boundaries to your main timezone, or subtract an offset before comparing. `files` is lower than IN01 because the hour already narrows it. OneDrive client sync (`FileSyncDownloadedFull`) is left out: a laptop left on overnight catches up on colleagues' changes, which is the main false positive at this threshold. Bulk sync is still caught by IN01 at any hour.

## Suppression
Suppress by `usr` for 12h. Alerts missing a key field are not suppressed. Aggregating rule. Overnight pulls span buckets; a different user still alerts.

## Known false positives / exclusions
- Shift workers, global teams and genuine evening work. If you have night shifts, scope the rule to day-shift populations or raise the threshold. Keep service accounts in the inline exclusion.
- Browser or script downloads by a scheduled job running as a user. Check `client_ips` and the user agent, and exclude the job's account.

## Triage
- Confirm the user normally works those hours and from that location. An after-hours bulk download from a home or unmanaged IP, especially by a leaver, is exfiltration.

## Test
Download 75 or more files from a lab library at a time outside your configured business hours.
