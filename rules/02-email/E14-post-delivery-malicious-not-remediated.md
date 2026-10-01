---
id: E14
name: Message rated malicious after delivery but still in the inbox (remediation gap)
category: email
status: todo
severity: high
language: esql
index: logs-o365.audit-*
mitre: [T1566.001, T1566.002]
data_source: Microsoft 365 Unified Audit Log (Defender for Office threat intelligence records)
suppression:
  fields: [usr]
  duration: 6h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
This is the ZAP miss. Defender re-rates a delivered message as phishing or malware, but its location is still the inbox, so ZAP did not remove it, whether because ZAP is off (E12), the mailbox was excluded, or the move failed. The malicious message is sitting in front of the user right now, which makes it the most actionable of the ZAP signals.

## Query
Run every 15 minutes with a 1-hour lookback.
```esql
FROM logs-o365.audit-* METADATA _id, _index, _version
| WHERE event.dataset == "o365.audit" AND event.action == "TIMailData"
| EVAL usr = TO_LOWER(TO_STRING(COALESCE(o365.audit.Recipients, o365.audit.UserId))),
       orig = TO_LOWER(TO_STRING(o365.audit.DeliveryAction)),
       loc = TO_LOWER(TO_STRING(o365.audit.LatestDeliveryLocation)),
       verdict = TO_LOWER(TO_STRING(o365.audit.Verdict))
| WHERE orig == "delivered"
  AND loc IN ("inbox", "")                                   // still in inbox (or location unknown)
  AND (verdict LIKE "*phish*" OR verdict LIKE "*malware*")
| KEEP @timestamp, usr, verdict, o365.audit.Subject, o365.audit.P2Sender, loc, o365.audit.NetworkMessageId
```

## Suppression
Suppress by `usr` for 6h. Alerts missing a key field are not suppressed. One wave produces several records per recipient; a different recipient still alerts.

## Known false positives / exclusions
- Timing: a record written in the instant before ZAP acts can look unremediated. A short delay before the rule runs, or re-checking the message location at triage, resolves this.

## Triage
- Purge the message from the recipient's mailbox now, then find out why ZAP missed it: check E12 for ZAP disabled, the mailbox for a ZAP exclusion, and whether the user already interacted (E01, E04, E05).

## Test
Validate against historical TIMailData records where the delivery location remained Inbox.
