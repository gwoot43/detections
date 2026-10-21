---
id: E13
name: ZAP post-delivery removal across many recipients (phishing or malware wave)
category: email
status: todo
language: esql
index: logs-o365.audit-*
mitre: [T1566.001, T1566.002]
data_source: Microsoft 365 Unified Audit Log (Defender for Office TIMailData records)
suppression:
  fields: [sender_domain]
  duration: 12h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
When ZAP moves phishing or malware out of many inboxes after delivery, a campaign got past the gateway and reached users before Defender caught up. The count of distinct recipients is a direct measure of exposure, and a spike is an active wave worth working as an incident, not a quiet dashboard number. Spam and bulk reclassifications are left out.

## Query
Run hourly with a 1-hour lookback.
```esql
FROM logs-o365.audit-*
| WHERE event.action == "TIMailData"
| EVAL orig_loc = REPLACE(TO_LOWER(COALESCE(o365.audit.OriginalDeliveryLocation, "")), " ", ""),
       loc = REPLACE(TO_LOWER(COALESCE(o365.audit.LatestDeliveryLocation, "")), " ", ""),
       detection = TO_LOWER(COALESCE(o365.audit.DetectionType, "")),
       verdict = TO_LOWER(COALESCE(o365.audit.Verdict, "")),
       rcpt = TO_LOWER(MV_FIRST(o365.audit.Recipients)),
       sender = TO_LOWER(COALESCE(o365.audit.P2Sender, o365.audit.P1Sender, "")),
       sender_domain = MV_LAST(SPLIT(sender, "@"))
// phish or malware removed after delivery: a ZAP record, or delivered to the inbox and now in quarantine, junk or deleted items
| WHERE verdict IN ("phish", "malware")
  AND (detection == "zap" OR (orig_loc == "inbox" AND (loc IN ("quarantine", "junkfolder") OR loc LIKE "deleted*")))
| STATS recipients = COUNT_DISTINCT(rcpt), messages = COUNT_DISTINCT(o365.audit.NetworkMessageId),
        subjects = VALUES(o365.audit.Subject), senders = VALUES(sender), verdicts = VALUES(verdict)
    BY sender_domain, BUCKET(@timestamp, 1 hour)
| WHERE recipients >= 10
```
Grouping is by sender domain, because a campaign is often many separate messages with their own network message IDs. Delivery locations are logged without spaces (`JunkFolder`); the query strips spaces so either form matches.

## Suppression
Suppress by `sender_domain` for 12h. Alerts missing a key field are not suppressed. A wave spans buckets; a campaign from a different domain still alerts.

## Known false positives / exclusions
- A wave sent from a large shared mail service (a compromised account on a webmail provider) groups under that provider's domain. Read `senders` and `subjects` before treating two alerts as one campaign.

## Triage
- Treat as an active phishing or malware wave that reached inboxes. Confirm ZAP moved every copy (E14 finds the ones it missed), check for clicks (E01, E04, E05), and block the sender and URL.

## Test
Validate against historical TIMailData records in the Defender portal rather than generating a live campaign.
