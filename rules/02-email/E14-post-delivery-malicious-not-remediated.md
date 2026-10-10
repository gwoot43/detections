---
id: E14
name: Message rated malicious after delivery but still in the inbox (remediation gap)
category: email
status: todo
severity: high
language: esql
index: logs-o365.audit-*
mitre: [T1566.001, T1566.002]
data_source: Microsoft 365 Unified Audit Log (Defender for Office TIMailData records)
suppression:
  fields: [usr]
  duration: 6h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
This is the ZAP miss. Defender re-rates a delivered message as phishing or malware after delivery, but 30 minutes later nothing has moved it out of the inbox: ZAP is off (CP01), the mailbox is excluded, or the move failed. The malicious message is sitting in front of the user right now, which makes it the most actionable of the ZAP signals. Messages rated malicious at delivery time but let through by an allow entry or override are left out; that is CP03's area.

## Query
Run every 15 minutes with a 2-hour lookback.
```esql
FROM logs-o365.audit-*
| WHERE event.action == "TIMailData"
| EVAL msg = o365.audit.NetworkMessageId,
       usr = TO_LOWER(MV_FIRST(o365.audit.Recipients)),
       orig = TO_LOWER(COALESCE(o365.audit.DeliveryAction, "")),
       loc = REPLACE(TO_LOWER(COALESCE(o365.audit.LatestDeliveryLocation, "")), " ", ""),
       detection = TO_LOWER(COALESCE(o365.audit.DetectionType, "")),
       verdict = TO_LOWER(COALESCE(o365.audit.Verdict, ""))
| WHERE msg IS NOT NULL AND usr IS NOT NULL AND verdict IN ("phish", "malware")
| EVAL in_inbox = detection != "inline" AND orig == "delivered" AND loc == "inbox",     // post-delivery verdict, still in the inbox
       removed = loc IN ("quarantine", "junkfolder") OR loc LIKE "deleted*"
| STATS still_in_inbox = SUM(CASE(in_inbox, 1, 0)), removals = SUM(CASE(removed, 1, 0)),
        first_flagged = MIN(CASE(in_inbox, @timestamp, NULL)),
        verdicts = VALUES(verdict), subject = VALUES(o365.audit.Subject), sender = VALUES(o365.audit.P2Sender)
    BY msg, usr
// no later record shows it moved, and ZAP has had 30 minutes
| WHERE still_in_inbox > 0 AND removals == 0 AND DATE_DIFF("minute", first_flagged, NOW()) >= 30
```
Defender writes a separate `TIMailData` record when it re-rates a message after delivery (`DetectionType` other than Inline) and another when ZAP moves it. The query waits for the second one and alerts only if it never arrives.

## Suppression
Suppress by `usr` for 6h. Alerts missing a key field are not suppressed. One wave produces several records per recipient; a different recipient still alerts.

## Known false positives / exclusions
- A message moved by the user or an admin without a new `TIMailData` record still looks unremediated. Re-check the message location at triage.

## Triage
- Purge the message from the recipient's mailbox now, then find out why ZAP missed it: check CP01 for ZAP disabled, the mailbox for a ZAP exclusion, and whether the user already clicked (E01, E04, E05).

## Test
Validate against historical TIMailData records where the delivery location remained Inbox after a post-delivery verdict.
