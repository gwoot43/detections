---
id: IN03
name: Confluence bulk page view, export or space export
category: insider
status: todo
severity: medium
language: esql
index: logs-confluence-*
mitre: [T1213.001, T1119]
data_source: Confluence audit log / access log (via syslog or app ingest)
suppression:
  fields: [usr]
  duration: 12h
  missing_fields: do_not_suppress
---
## Why this is high fidelity for insider risk
Confluence holds documentation, designs and runbooks that leavers and snoopers take. The behaviours that matter are a space export (one action that packages a whole space), a PDF or Word export at volume, and viewing or reading an unusually large number of distinct pages in a short time. These are recorded in Confluence's audit and access logs.

## Query
Run hourly with a 1-hour lookback. Field names depend on how you parse Confluence logs; map user, action and page into these.
```esql
FROM logs-confluence-*
| EVAL usr = TO_LOWER(TO_STRING(user.name)),
       action = TO_LOWER(TO_STRING(COALESCE(event.action, url.path, ""))),
       page = TO_STRING(COALESCE(confluence.object_id, url.path))
| WHERE action LIKE "*export*" OR action LIKE "*/pages/*" OR action LIKE "*viewpage*" OR action LIKE "*exportword*" OR action LIKE "*exportpdf*" OR action LIKE "*spaceexport*"
| STATS space_exports = SUM(CASE(action LIKE "*spaceexport*" OR action LIKE "*exportspace*", 1, 0)),
        exports = SUM(CASE(action LIKE "*export*", 1, 0)),
        pages_viewed = COUNT_DISTINCT(page),
        spaces = COUNT_DISTINCT(TO_STRING(confluence.space_key))
    BY usr, BUCKET(@timestamp, 1 hour)
| WHERE space_exports >= 1 OR exports >= 30 OR pages_viewed >= 150
```
A space export is high severity on its own; the view and export counts are the bulk-reading signal. Tune to your Confluence usage.

## Suppression
Suppress by `usr` for 12h. Alerts missing a key field are not suppressed. Aggregating rule. Bulk reading spans buckets; a different user still alerts.

## Known false positives / exclusions
- Documentation and knowledge-management teams who legitimately export. Exclude those users inline.
- Scheduled backup or archiving integrations. Exclude their service account.

## Triage
- A space export or heavy export by someone outside the documentation team, especially a leaver, is data gathering. Confirm which spaces and whether the content is sensitive.

## Test
Export a space and open many pages quickly as a test Confluence user.
