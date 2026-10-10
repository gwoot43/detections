---
id: E04
name: Zero-hour auto purge removed a message the user had already clicked
category: email
status: todo
severity: high
language: esql
index: logs-o365.audit-*
mitre: [T1566.001, T1566.002]
data_source: Microsoft 365 Unified Audit Log via Elastic O365 integration (TIMailData and TIUrlClickData records)
suppression:
  fields: [msg, usr]
  duration: 24h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
ZAP means Microsoft changed its mind after delivery: the message sat in the inbox, then was moved to quarantine, junk or deleted items. Joining that removal to a Safe Links click on the same message by the same recipient leaves only the cases where a person interacted with mail now known to be bad.

## Prerequisite
- Safe Links must be on, so clicks are logged as `TIUrlClickData`. The click record carries the message ID in `o365.audit.SourceId`, a dynamically mapped field that exists once the first click is ingested.
- `MailItemsAccessed` is not used. It lists messages in a nested folder structure that ES|QL cannot read, so it cannot be joined by message ID.

## Query
Run hourly with a 24-hour lookback, so a click and a later ZAP on the same message meet in one window.
```esql
FROM logs-o365.audit-*
| WHERE event.action IN ("TIMailData", "TIUrlClickData")
| EVAL is_mail = event.action == "TIMailData",
       orig_loc = REPLACE(TO_LOWER(COALESCE(o365.audit.OriginalDeliveryLocation, "")), " ", ""),
       loc = REPLACE(TO_LOWER(COALESCE(o365.audit.LatestDeliveryLocation, "")), " ", ""),
       detection = TO_LOWER(COALESCE(o365.audit.DetectionType, "")),
       verdict = TO_LOWER(COALESCE(o365.audit.Verdict, "")),
       msg = CASE(is_mail, o365.audit.NetworkMessageId, o365.audit.SourceId),
       usr = TO_LOWER(CASE(is_mail, MV_FIRST(o365.audit.Recipients), o365.audit.UserId))
// phish or malware removed after delivery: a ZAP record, or delivered to the inbox and now in quarantine, junk or deleted items
| EVAL zapped = is_mail AND verdict IN ("phish", "malware") AND (detection == "zap"
                             OR (orig_loc == "inbox" AND (loc IN ("quarantine", "junkfolder") OR loc LIKE "deleted*"))),
       clicked = NOT is_mail
| WHERE msg IS NOT NULL AND usr IS NOT NULL AND (zapped OR clicked)
| STATS zaps = SUM(CASE(zapped, 1, 0)), clicks = SUM(CASE(clicked, 1, 0)),
        first_click = MIN(CASE(clicked, @timestamp, NULL)),
        verdicts = VALUES(CASE(zapped, verdict, NULL)), subject = VALUES(o365.audit.Subject), sender = VALUES(o365.audit.P2Sender)
    BY msg, usr
| WHERE zaps > 0 AND clicks > 0
```
`TIMailData` names the recipient in `Recipients`; its `UserId` is the service ("ThreatIntel"), so it cannot be the join key. Delivery locations are logged without spaces (`JunkFolder`); the query strips spaces so either form matches.

## Suppression
Suppress by `msg`, `usr` for 24h. Alerts missing a key field are not suppressed. Aggregating rule keyed on message and user; the 24-hour lookback would otherwise re-alert every run.

## Known false positives / exclusions
- Spam and bulk reclassifications are excluded: only phish and malware verdicts count as a removal.

## Triage
- Same as E01. Treat a ZAP-plus-click as a confirmed phishing interaction. `first_click` tells you where to start in the sign-in and endpoint timelines.

## Test
Not safely testable in production. Validate the query against historical ZAP events in the Defender portal.
