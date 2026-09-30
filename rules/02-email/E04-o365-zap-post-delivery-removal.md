---
id: E04
name: Zero-hour auto purge removed a message the user had already opened or clicked
category: email
status: todo
severity: high
language: esql
index: logs-o365.audit-*
mitre: [T1566.001, T1566.002]
data_source: Microsoft 365 Unified Audit Log via Elastic O365 integration (Defender for Office 365 threat intelligence records)
suppression:
  fields: [msg, usr]
  duration: 24h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
ZAP means Microsoft changed its mind after delivery. The message sat in the inbox. Combining the post-delivery verdict with a Safe Links click or a MailItemsAccessed read for the same message gives you only the cases where a person interacted.

## Query
```esql
FROM logs-o365.audit-* METADATA _id, _index, _version
| WHERE event.action IN ("TIMailData", "TIUrlClickData", "MailItemsAccessed")
| EVAL msg = COALESCE(o365.audit.NetworkMessageId, o365.audit.InternetMessageId),
       usr = TO_LOWER(COALESCE(o365.audit.UserId, o365.audit.Recipients)),
       zapped = CASE(event.action == "TIMailData"
                     AND TO_LOWER(o365.audit.DeliveryAction) == "delivered"
                     AND TO_LOWER(o365.audit.LatestDeliveryLocation) IN ("quarantine", "junk folder", "deleted items folder"), 1, 0),
       interacted = CASE(event.action IN ("TIUrlClickData", "MailItemsAccessed"), 1, 0)
| WHERE msg IS NOT NULL
| STATS zaps = SUM(zapped), touches = SUM(interacted), verdict = VALUES(o365.audit.Verdict), subject = VALUES(o365.audit.Subject), sender = VALUES(o365.audit.P2Sender)
    BY msg, usr
| WHERE zaps > 0 AND touches > 0
```
If `MailItemsAccessed` is not licensed (needs E5 / Purview Audit Premium), drop it and keep the Safe Links click branch only.

## Suppression
Suppress by `msg`, `usr` for 24h. Alerts missing a key field are not suppressed. Aggregating rule keyed on message and user.

## Known false positives / exclusions
- Bulk/spam ZAP is excluded by design because the query requires interaction.

## Triage
- Same as E01. Treat a ZAP-plus-click as a confirmed phishing interaction.

## Test
Not safely testable in production. Validate the query against historical ZAP alerts in the Defender portal.
