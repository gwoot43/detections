---
id: E05
name: Safe Links block page clicked through
category: email
status: todo
severity: high
language: esql
index: logs-o365.audit-*
mitre: [T1204.001, T1566.002]
data_source: Microsoft 365 Unified Audit Log (Safe Links URL click records)
suppression:
  fields: [o365.audit.UserId, o365.audit.Url]
  duration: 24h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
Users can only click through a Safe Links block if the policy allows it. When they do, the URL was already rated malicious and the user chose to proceed. Volume is a few per week and every one is a conversation with the user.

## Query
```esql
FROM logs-o365.audit-* METADATA _id, _index, _version
| WHERE event.action == "TIUrlClickData"
  AND TO_LOWER(o365.audit.UrlClickAction) IN ("clickedthroughblock", "clickedeventhoughblocked", "clickthrough")
| KEEP @timestamp, o365.audit.UserId, o365.audit.Url, o365.audit.UrlClickAction, o365.audit.Workload, o365.audit.ClientIP, o365.audit.SourceId
```
The `UrlClickAction` value set differs by tenant version. Run `STATS COUNT(*) BY o365.audit.UrlClickAction` once and pick the click-through values you actually see.

## Suppression
Suppress by `o365.audit.UserId`, `o365.audit.Url` for 24h. Alerts missing a key field are not suppressed. Users click the same link repeatedly. A different link still alerts.

## Known false positives / exclusions
- Security analysts. Exclude the analyst mailbox list.

## Triage
- Same as E01, plus disable click-through in the Safe Links policy if it is not needed.

## Test
With a test policy that permits click-through, click a URL from the Microsoft Safe Links test list.
