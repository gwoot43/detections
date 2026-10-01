---
id: IN07
name: Broad SharePoint access across many sites the user does not own
category: insider
status: todo
severity: medium
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
| WHERE event.dataset == "o365.audit" AND o365.audit.Workload == "SharePoint"
  AND event.action IN ("FileAccessed", "FileDownloaded", "FilePreviewed", "PageViewed")
| EVAL usr = TO_LOWER(o365.audit.UserId)
| WHERE NOT (usr LIKE "app@sharepoint" OR usr == "system account")
| STATS sites = COUNT_DISTINCT(o365.audit.SiteUrl),
        files = COUNT_DISTINCT(o365.audit.ObjectId),
        site_list = VALUES(o365.audit.SiteUrl)
    BY usr, BUCKET(@timestamp, 2 hours)
| WHERE sites >= 25
```
Tune `sites` to how many sites a normal user touches. Without a per-user baseline (no lookup), a fixed breadth threshold is the pragmatic choice; review and adjust after two weeks.

## Suppression
Suppress by `usr` for 12h. Alerts missing a key field are not suppressed. Aggregating rule. Browsing spans buckets; a different user still alerts.

## Known false positives / exclusions
- Roles that legitimately span many sites (IT, records management, auditors, senior leadership). Exclude those users inline.
- Search-driven work that opens many sites briefly. The file-count condition and review reduce this.

## Triage
- Compare the sites accessed with the user's team and role. A developer opening finance, HR and legal sites is snooping. Combine with IN01 if they also downloaded in volume.

## Test
Access files across 25 or more lab sites as a test user.
