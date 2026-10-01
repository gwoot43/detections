---
id: E12
name: Zero-hour auto purge (ZAP) disabled in a protection policy
category: email
status: todo
severity: high
language: esql
index: logs-o365.audit-*
mitre: [T1562.001, T1562.006]
data_source: Microsoft 365 Unified Audit Log (Exchange admin)
suppression:
  fields: [usr, event.action]
  duration: 6h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
Zero-hour auto purge removes mail that is re-rated malicious after delivery. Turning it off in the anti-malware, anti-spam or anti-phishing policy means a message found bad after delivery stays in the inbox. It is a deliberate weakening of post-delivery protection and a rare admin change.

## Query
```esql
FROM logs-o365.audit-* METADATA _id, _index, _version
| WHERE event.dataset == "o365.audit" AND event.provider == "Exchange" AND event.outcome == "success"
  AND event.action IN ("Set-MalwareFilterPolicy", "Set-HostedContentFilterPolicy", "Set-AntiPhishPolicy", "Set-AtpPolicyForO365")
| EVAL usr = TO_LOWER(o365.audit.UserId), params = TO_LOWER(TO_STRING(o365.audit.Parameters))
| WHERE params LIKE "*zap*false*" OR params LIKE "*zapenabled*false*"
     OR params LIKE "*phishzapenabled*false*" OR params LIKE "*spamzapenabled*false*" OR params LIKE "*malwarezapenabled*false*"
| KEEP @timestamp, usr, event.action, o365.audit.ObjectId, o365.audit.ClientIP, params
```
Covers the combined `ZapEnabled` switch and the newer split phish, spam and malware ZAP switches. Confirm the parameter spelling in your integration.

## Suppression
Suppress by `usr`, `event.action` for 6h. Alerts missing a key field are not suppressed. One edit can write several lines; a different admin still alerts.

## Known false positives / exclusions
- Policy-as-code pipelines. Exclude the pipeline account inline and confirm human changes against change control. There is almost no good reason to disable ZAP in production.

## Triage
- Re-enable ZAP, confirm who changed it, and check for delivered-but-malicious mail in the window it was off (E14). Correlate with other protection weakening (CP01) by the same admin.

## Test
Disable ZAP on a test content-filter policy in a lab tenant and re-enable it.
