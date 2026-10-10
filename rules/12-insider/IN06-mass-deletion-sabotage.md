---
id: IN06
name: Mass file or site deletion (insider sabotage)
category: insider
status: todo
severity: high
language: esql
index: logs-o365.audit-*
mitre: [T1485, T1490]
data_source: Microsoft 365 Unified Audit Log (SharePoint/OneDrive)
suppression:
  fields: [usr]
  duration: 6h
  missing_fields: do_not_suppress
---
## Why this is high fidelity for insider risk
A disgruntled insider may delete rather than steal. Bulk deletion of files, versions or whole sites is destructive and rare for a normal user. The unified audit log records each deletion, so a burst from one user stands out.

## Query
Run hourly with a 1-hour lookback.
```esql
FROM logs-o365.audit-*
| WHERE event.provider IN ("SharePoint", "OneDrive")
  AND event.action IN ("FileDeleted", "FileRecycled", "FileVersionsAllDeleted", "FileVersionRecycled",
                       "SiteDeleted", "FileDeletedFirstStageRecycleBin", "FileDeletedSecondStageRecycleBin")
| EVAL usr = TO_LOWER(o365.audit.UserId)
| WHERE NOT (usr IN ("app@sharepoint", "system account", "sharepoint\\system")
             OR usr IN ("svc-retention@yourdomain.com", "svc-migration@yourdomain.com"))   // retention and migration accounts
| STATS deletions = COUNT(*),
        files = COUNT_DISTINCT(url.original),
        sites = COUNT_DISTINCT(o365.audit.SiteUrl),
        site_deletes = SUM(CASE(event.action == "SiteDeleted", 1, 0)),
        site_list = VALUES(o365.audit.SiteUrl)
    BY usr, BUCKET(@timestamp, 1 hour)
| WHERE files >= 100 OR site_deletes >= 1
```
Files are counted by `url.original`, where the integration puts the file URL (`ObjectId`) for SharePoint file operations. Deleting a file and then emptying it from the recycle bin writes several events for the same URL, so it counts once.

## Suppression
Suppress by `usr` for 6h. Alerts missing a key field are not suppressed. Aggregating rule. A deletion spree spans buckets; a different user still alerts.

## Known false positives / exclusions
- Legitimate cleanup, retention automation and migration. Keep those service accounts in the inline exclusion; confirm large human deletions against a ticket.
- A user clearing their own OneDrive before leaving is still worth seeing, so keep OneDrive in scope.

## Triage
- Confirm intent with the user's manager. Preserve the recycle bin and, for a site deletion, restore from the deleted-sites retention. Treat a departing employee deleting shared team content as sabotage.

## Test
Delete a hundred files in a lab library as a test user.
