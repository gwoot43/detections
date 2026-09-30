---
id: E11
name: Email bombing (inbound flood to a single recipient)
category: email
status: todo
severity: medium
language: esql
index: logs-mimecast.siem_logs-*
mitre: [T1566, T1656]
data_source: Mimecast SIEM receipt logs (inbound route)
suppression:
  fields: [rcpt]
  duration: 24h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
A sudden flood of subscription confirmations and newsletters to one mailbox is the setup for a help-desk social engineering call: overwhelm the user, then offer to help via Quick Assist or a remote tool (the Black Basta and 3AM playbook). Hundreds of inbound messages to one recipient in a few minutes has no benign cause and is the earliest signal of that intrusion, ahead of the endpoint side (W10) and the correlation (X06).

## Query
```esql
FROM logs-mimecast.siem_logs-*
| WHERE TO_LOWER(mimecast.Dir) == "inbound"
| EVAL rcpt = TO_LOWER(TO_STRING(mimecast.Rcpt))
| STATS msgs = COUNT(*), senders = COUNT_DISTINCT(mimecast.Sender), sample = VALUES(mimecast.Subject)
    BY rcpt, BUCKET(@timestamp, 5 minutes)
| WHERE msgs >= 100 AND senders >= 50
```
Field names are the Mimecast SIEM receipt-log names (`Dir`, `Rcpt`, `Sender`). Confirm the casing your integration produces. Tune the thresholds to your normal peak inbound rate per mailbox.

## Suppression
Suppress by `rcpt` for 24h. Alerts missing a key field are not suppressed. One bombing run spans many 5-minute buckets; a different recipient still alerts.

## Known false positives / exclusions
- A shared or role mailbox that legitimately receives high volume (support, sales). Raise its threshold or exclude it, keeping individual user mailboxes sensitive.

## Triage
- Contact the recipient directly and warn them not to accept unsolicited IT help. Watch that user for an external Teams contact or a remote-access tool in the next few hours (X06, W10).

## Test
Validate on historical data. Do not generate a real flood against a production mailbox.
