---
id: E05
name: Safe Links block page clicked through
category: email
status: todo
language: esql
index: logs-o365.audit-*
mitre: [T1204.001, T1566.002]
data_source: Microsoft 365 Unified Audit Log (Safe Links TIUrlClickData records)
suppression:
  fields: [usr, o365.audit.URL]
  duration: 24h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
Users can only click through a Safe Links block page if the policy allows it (`AllowClickThrough`). When they do, the URL was already rated malicious and the user chose to proceed. Volume is a few per week and every one is a conversation with the user.

## Prerequisite
The click fields are mapped dynamically from the first `TIUrlClickData` record. Microsoft documents them as `URLClickAction` (a number) and `URL`. Before enabling, open one record in Discover and confirm both names; if your data uses different casing, change the query to match, or the rule fails with "Unknown column".

## Query
```esql
FROM logs-o365.audit-* METADATA _id, _index, _version
| WHERE event.action == "TIUrlClickData"
| EVAL click_action = TO_LOWER(TO_STRING(o365.audit.URLClickAction)),
       usr = TO_LOWER(o365.audit.UserId)
| WHERE click_action IN ("4", "blockpageoverride")                 // clicked through the block page
  AND NOT usr IN ("soc-sandbox@yourdomain.com")                    // analyst test mailboxes
| KEEP @timestamp, usr, o365.audit.URL, click_action, o365.audit.SourceId, _id, _version, _index
```
`URLClickAction` 4 is BlockPageOverride. 5 (PendingDetonationPageOverride, clicked through while the URL was still being scanned) is left out: the URL had no malicious verdict yet. `SourceId` is the network message ID of the email, for purging.

## Suppression
Suppress by `usr`, `o365.audit.URL` for 24h. Alerts missing a key field are not suppressed. Users click the same link repeatedly. A different link still alerts.

## Known false positives / exclusions
- Security analysts. Keep the analyst mailboxes in the inline exclusion.

## Triage
- Same as E01, plus disable click-through in the Safe Links policy if it is not needed.

## Test
With a test policy that permits click-through, click a URL from the Microsoft Safe Links test list and continue past the block page.
