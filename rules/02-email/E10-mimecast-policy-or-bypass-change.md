---
id: E10
name: Mimecast protection policy weakened or bypass created
category: email
status: todo
language: esql
index: logs-mimecast.audit_events-*
mitre: [T1685, T1078]
data_source: Mimecast administration audit events (Elastic Mimecast integration, audit_events data stream)
suppression:
  fields: [user.email, event.action]
  duration: 1h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
Creating a bypass for URL, Attachment or Impersonation Protect or for anti-spoofing, adding a permitted sender, or deleting or disabling a protection policy is the mail-gateway equivalent of turning off the EDR. Mimecast admin changes are low volume and made by a handful of named admins. Logons, 2FA and API events are left out: they are routine and say nothing about protection.

## Query
```esql
FROM logs-mimecast.audit_events-* METADATA _id, _index, _version
| EVAL act = TO_LOWER(COALESCE(event.action, "")), info = TO_LOWER(COALESCE(mimecast.eventInfo, ""))
| WHERE NOT COALESCE(mimecast.category, "") IN ("authentication_logs", "case_review_logs", "archive_service_logs", "reporting_logs")
| EVAL protection = info LIKE "*url protect*" OR info LIKE "*attachment protect*" OR info LIKE "*impersonation protect*"
                    OR info LIKE "*anti-spoof*" OR info LIKE "*dns authentication*" OR info LIKE "*targeted threat protection*"
| WHERE info LIKE "*bypass*" OR info LIKE "*permitted sender*"
     OR (protection AND (act LIKE "*delet*" OR act LIKE "*disabl*" OR info LIKE "*disabled*"))
| WHERE NOT COALESCE(user.email, "") IN ("svc-mimecast-automation@yourdomain.com")          // policy automation, if any
| KEEP @timestamp, event.action, mimecast.category, user.email, info, client.ip, _id, _version, _index
```
The integration moves `auditType` to `event.action` (lower case, spaces as hyphens, for example `user-logged-on`), `user` to `user.email`, and the admin's IP to `client.ip`. `mimecast.category` and `mimecast.eventInfo` keep their names.

## Suppression
Suppress by `user.email`, `event.action` for 1h. Alerts missing a key field are not suppressed. One admin session writes many audit lines for the same change.

## Known false positives / exclusions
- Routine permitted-sender additions by the service desk. Keep them visible: repeated permits for the same external domain are a pattern. If they are too frequent, route the `permitted sender` branch to a lower-scored rule rather than dropping it.

## Triage
- Confirm the change with the admin. Check the admin's Mimecast logon source IP against known locations.

## Test
Create and delete a test URL Protect bypass policy in the Mimecast admin console.
