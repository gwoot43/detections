---
id: IN03
name: Confluence space or site export, or page export at volume
category: insider
status: todo
severity: medium
language: esql
index: logs-atlassian_confluence.audit-*
mitre: [T1213.001, T1119]
data_source: Confluence audit log (Elastic Atlassian Confluence integration, audit data stream; Cloud API or Data Center audit files)
suppression:
  fields: [user.id]
  duration: 12h
  missing_fields: do_not_suppress
---
## Why this is high fidelity for insider risk
Confluence holds documentation, designs and runbooks that leavers and snoopers take. A space or site export packages a whole space in one action and is rare outside admins and the documentation team. The audit log records it in the Import/Export category.

Page views are not covered. Confluence Cloud's audit log does not record page views, and Data Center records them only in the access log, which this integration does not collect. Bulk reading is not visible from the audit log.

## Query
Run hourly with a 1-hour lookback.
```esql
FROM logs-atlassian_confluence.audit-*
| EVAL summary = TO_LOWER(COALESCE(confluence.audit.type.action, "")),
       action_key = TO_LOWER(COALESCE(event.action, "")),
       category = TO_LOWER(COALESCE(confluence.audit.type.category, ""))
| WHERE (category == "import/export" OR action_key LIKE "*export*")
  AND (summary LIKE "*export*" OR action_key LIKE "*export*")
| WHERE NOT COALESCE(user.id, "") IN ("<backup-service-account-id>")     // backup or archiving integration
| STATS space_exports = SUM(CASE(summary LIKE "*space*" OR summary LIKE "*site*"
                                 OR action_key LIKE "*space*" OR action_key LIKE "*site*", 1, 0)),
        exports = COUNT(*),
        actions = VALUES(confluence.audit.type.action),
        names = VALUES(user.full_name),
        ips = VALUES(source.ip)
    BY user.id, BUCKET(@timestamp, 1 hour)
| WHERE space_exports >= 1 OR exports >= 30
```
Data Center writes `event.action` as the message key (`audit.logging.summary.space.import` in the package samples; exports follow the same pattern), and Cloud writes the summary text (`Space created`). `confluence.audit.type.action` holds the summary text on both. `user.id` is the Cloud account ID or the Data Center user key; `user.full_name` is the display name. A space export alerts on its own; `exports >= 30` applies only if your edition audits page exports.

## Suppression
Suppress by `user.id` for 12h. Alerts missing a key field are not suppressed. Aggregating rule. One user exporting several spaces in a session is one alert with a count; a different user still alerts.

## Known false positives / exclusions
- Documentation and knowledge-management staff who export as part of their job. Exclude their `user.id` inline.
- Scheduled backup or archiving integrations. Exclude their service account.

## Triage
- A space export by someone outside the documentation team, especially a leaver, is data gathering. Confirm which space was exported (open the event's affected objects) and whether the content is sensitive.

## Test
Export a small test space as a test Confluence user and confirm the audit event's `confluence.audit.type.category` is Import/Export.
