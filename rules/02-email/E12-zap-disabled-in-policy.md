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
Zero-hour auto purge removes mail that is re-rated malicious after delivery. Turning it off in the anti-malware or anti-spam policy means a message found bad after delivery stays in the inbox. It is a deliberate weakening of post-delivery protection and a rare admin change.

## Prerequisite
The ZAP switches are mapped only after an admin first sets them: `o365.audit.Parameters.ZapEnabled` (anti-malware, and the older anti-spam switch), `PhishZapEnabled` and `SpamZapEnabled` (anti-spam). On most tenants they do not exist yet and the query fails with "Unknown column". Map all three as `keyword` in the `logs-o365.audit@custom` component template before enabling the rule.

## Query
```esql
FROM logs-o365.audit-* METADATA _id, _index, _version
| WHERE event.provider == "Exchange" AND event.outcome == "success"
  AND event.action IN ("Set-MalwareFilterPolicy", "Set-HostedContentFilterPolicy", "New-MalwareFilterPolicy", "New-HostedContentFilterPolicy")
| EVAL usr = TO_LOWER(o365.audit.UserId),
       zap = TO_LOWER(COALESCE(o365.audit.Parameters.ZapEnabled, "")),
       phish_zap = TO_LOWER(COALESCE(o365.audit.Parameters.PhishZapEnabled, "")),
       spam_zap = TO_LOWER(COALESCE(o365.audit.Parameters.SpamZapEnabled, ""))
| WHERE zap == "false" OR phish_zap == "false" OR spam_zap == "false"
| WHERE NOT usr IN ("svc-exo-policy-pipeline@yourdomain.com")    // policy-as-code account, if any
| KEEP @timestamp, usr, event.action, o365.audit.ObjectId, source.ip, zap, phish_zap, spam_zap
```
Anti-phishing and Safe Links policies have no ZAP switch, so `Set-AntiPhishPolicy` and `Set-AtpPolicyForO365` are not queried; their weakening is in CP01.

## Suppression
Suppress by `usr`, `event.action` for 6h. Alerts missing a key field are not suppressed. One edit can write several lines; a different admin still alerts.

## Known false positives / exclusions
- Policy-as-code pipelines. Keep the pipeline account in the inline exclusion and confirm human changes against change control. There is almost no good reason to disable ZAP in production.

## Triage
- Re-enable ZAP, confirm who changed it, and check for delivered-but-malicious mail in the window it was off (E14). Correlate with other protection weakening (CP01) by the same admin.

## Test
Disable ZAP on a test anti-spam policy in a lab tenant and re-enable it.
