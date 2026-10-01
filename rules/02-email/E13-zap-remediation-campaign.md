---
id: E13
name: ZAP post-delivery remediation across many recipients (phishing or malware wave)
category: email
status: todo
severity: medium
language: esql
index: logs-o365.audit-*
mitre: [T1566.001, T1566.002]
data_source: Microsoft 365 Unified Audit Log (Defender for Office threat intelligence records)
suppression:
  fields: [campaign]
  duration: 12h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
When ZAP moves a message to quarantine or junk after delivery across many mailboxes in a short window, a malicious campaign got past the gateway and reached inboxes before Defender caught up. The remediation count is a direct measure of how many users were exposed, and a spike is an active wave worth working as an incident, not a quiet dashboard number.

## Query
Run hourly with a 1-hour lookback.
```esql
FROM logs-o365.audit-*
| WHERE event.dataset == "o365.audit" AND event.action == "TIMailData"
| EVAL action = TO_LOWER(TO_STRING(o365.audit.LatestDeliveryLocation)),
       orig = TO_LOWER(TO_STRING(o365.audit.DeliveryAction)),
       verdict = TO_LOWER(TO_STRING(o365.audit.Verdict)),
       zapped = TO_LOWER(TO_STRING(COALESCE(o365.audit.SystemActionType, o365.audit.ZapDetail, ""))),
       campaign = COALESCE(TO_STRING(o365.audit.NetworkMessageId), TO_STRING(o365.audit.InternetMessageId))
// delivered, then moved post-delivery by ZAP to quarantine/junk/deleted
| WHERE orig == "delivered"
  AND action IN ("quarantine", "junk folder", "deleted items folder")
  AND (verdict LIKE "*phish*" OR verdict LIKE "*malware*" OR zapped LIKE "*zap*")
| STATS recipients = COUNT_DISTINCT(o365.audit.Recipients),
        subjects = VALUES(o365.audit.Subject),
        senders = VALUES(o365.audit.P2Sender),
        verdicts = VALUES(verdict)
    BY campaign, BUCKET(@timestamp, 1 hour)
| WHERE recipients >= 10
```
Field names for the ZAP detail and delivery location vary by tenant version; run `STATS COUNT(*) BY o365.audit.LatestDeliveryLocation` once and confirm. Group by a campaign identifier if your records share one across recipients; otherwise group by subject and sender.

## Suppression
Suppress by `campaign` for 12h. Alerts missing a key field are not suppressed. A wave spans buckets; a different campaign still alerts.

## Known false positives / exclusions
- Bulk and graymail that ZAP reclassifies as spam. The verdict filter keeps phish and malware, which cuts most of this; drop the spam-only reclassifications.

## Triage
- Treat as an active phishing or malware wave that reached inboxes. Confirm ZAP moved every copy (E14 finds the ones it missed), check for clicks and opens (E01, E04, E05), and block the sender and URL.

## Test
Validate against historical TIMailData records in the Defender portal rather than generating a live campaign.
