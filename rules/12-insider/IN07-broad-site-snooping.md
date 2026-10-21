---
id: IN07
name: Broad SharePoint access across many sites the user does not own
category: insider
status: todo
language: esql
index: logs-o365.audit-*
mitre: [T1213.002, T1087]
data_source: Microsoft 365 Unified Audit Log (SharePoint file access)
suppression:
  fields: [usr]
  duration: 12h
  missing_fields: do_not_suppress
---
## Why this is high fidelity for insider risk
Theft is about volume from one place (IN01); snooping is about breadth. A user accessing files across many distinct sites in a short window, especially sites outside their team, is browsing for sensitive content. The audit log records file access with the site URL, so breadth is measurable without a Graph feed or a permissions lookup.

## Query
Run every 2 hours with a 2-hour lookback.
```esql
FROM logs-o365.audit-*
| WHERE event.provider == "SharePoint"
  AND event.action IN ("FileAccessed", "FileDownloaded", "FilePreviewed")
| EVAL usr = TO_LOWER(o365.audit.UserId)
| WHERE NOT (usr IN ("app@sharepoint", "system account", "sharepoint\\system")
             OR usr IN ("records-manager@yourdomain.com"))        // roles that legitimately span many sites
| STATS sites = COUNT_DISTINCT(o365.audit.SiteUrl),
        files = COUNT_DISTINCT(url.original),
        site_list = VALUES(o365.audit.SiteUrl)
    BY usr, BUCKET(@timestamp, 2 hours)
| WHERE sites >= 25 AND files >= 50
```
`PageViewed` is left out: browsing intranet news and hub pages touches many sites without opening any content. `files >= 50` requires real file opens, not one file per site. `url.original` is the integration's name for the file URL. Without a per-user baseline (no lookup), fixed thresholds are the pragmatic choice; tune both on two weeks of data.

## Suppression
Suppress by `usr` for 12h. Alerts missing a key field are not suppressed. Aggregating rule. Browsing spans buckets; a different user still alerts.

## Known false positives / exclusions
- Roles that legitimately span many sites (IT, records management, auditors, senior leadership). Keep those users in the inline exclusion.
- Search-driven work that opens one file on each of many sites. The `files >= 50` condition removes most of it.

## Triage
- Compare the sites accessed with the user's team and role. A developer opening finance, HR and legal sites is snooping. Combine with IN01 if they also downloaded in volume.

## Test
Open 50 or more files across 25 or more lab sites as a test user.
