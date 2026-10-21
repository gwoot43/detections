---
id: IN05
name: Outbound mail with attachments to personal webmail at volume
category: insider
status: todo
language: esql
index: logs-mimecast.siem_logs-*
mitre: [T1114, T1567, T1048.003]
data_source: Mimecast SIEM delivery logs, outbound (Elastic Mimecast integration, siem_logs data stream)
suppression:
  fields: [sender]
  duration: 12h
  missing_fields: do_not_suppress
---
## Why this is high fidelity for insider risk
A common, low-tech exfiltration is mailing work to a personal account. Because the outbound mail gateway is Mimecast, this is visible without any Graph feed: one internal sender sending five or more messages with attachments to consumer webmail domains in an hour. Messages without attachments are not counted, and a single message is never flagged.

## Query
Run hourly with a 1-hour lookback.
```esql
FROM logs-mimecast.siem_logs-*
| WHERE TO_LOWER(mimecast.log_type) == "delivery" AND email.direction == "outbound"
| EVAL sender = TO_LOWER(MV_MIN(email.from.address)),
       rcpt = TO_LOWER(MV_FIRST(email.to.address)),
       attachments = COALESCE(mimecast.AttCnt, TO_LONG(mimecast.numberAttachments), TO_LONG(0)),
       personal = rcpt LIKE "*@gmail.com" OR rcpt LIKE "*@outlook.com" OR rcpt LIKE "*@hotmail.com"
                  OR rcpt LIKE "*@yahoo.com" OR rcpt LIKE "*@icloud.com" OR rcpt LIKE "*@proton.me"
                  OR rcpt LIKE "*@protonmail.com" OR rcpt LIKE "*@gmx.*" OR rcpt LIKE "*@aol.com"
| WHERE personal AND attachments > 0 AND sender LIKE "*@yourdomain.com"
  AND NOT sender IN ("notifications@yourdomain.com")                      // addresses that mail consumers by design
| STATS with_attachments = COUNT_DISTINCT(email.message_id),
        distinct_personal = COUNT_DISTINCT(rcpt),
        recipients = VALUES(rcpt),
        subjects = VALUES(email.subject)
    BY sender, BUCKET(@timestamp, 1 hour)
| WHERE with_attachments >= 5
```
Delivery logs are used because they carry the recipient, direction and attachment count together (receipt logs lack the count, process logs lack the recipient). The attachment count is `mimecast.AttCnt` in the 1.0 SIEM API and `mimecast.numberAttachments` in the 2.0 API. Messages are counted by `email.message_id`, so delivery retries count once. Replace `yourdomain.com` with your domains.

## Suppression
Suppress by `sender` for 12h. Alerts missing a key field are not suppressed. Aggregating rule. A drip spans buckets; a different sender still alerts.

## Known false positives / exclusions
- People legitimately mailing themselves the odd document. Five attached messages in an hour is above that; tune on two weeks of data.
- Distribution and notification addresses that mail external consumers. Keep them in the inline exclusion.

## Triage
- Confirm the sender and recipient relationship and the attachments. A spike to a personal address, especially from a leaver, is exfiltration. Correlate with IN01 and IN02 for the same person.

## Test
Send several attachments from a test mailbox to a personal address through the gateway.
