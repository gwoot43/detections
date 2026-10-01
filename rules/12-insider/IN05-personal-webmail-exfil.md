---
id: IN05
name: Outbound mail to personal webmail with attachments at volume
category: insider
status: todo
severity: medium
language: esql
index: logs-mimecast.siem_logs-*
mitre: [T1114, T1567, T1048.003]
data_source: Mimecast SIEM receipt logs (outbound route)
suppression:
  fields: [sender]
  duration: 12h
  missing_fields: do_not_suppress
---
## Why this is high fidelity for insider risk
A common, low-tech exfiltration is mailing work to a personal account. Because the outbound mail gateway is Mimecast, this is visible without any Graph feed: one internal sender sending repeatedly, or with many attachments, to consumer webmail domains. The signal is volume to personal domains, not a single message.

## Query
Run hourly with a 1-hour lookback, and as a daily rollup.
```esql
FROM logs-mimecast.siem_logs-*
| WHERE TO_LOWER(mimecast.Dir) == "outbound"
| EVAL sender = TO_LOWER(TO_STRING(mimecast.Sender)),
       rcpt = TO_LOWER(TO_STRING(mimecast.Rcpt)),
       personal = CASE(rcpt LIKE "*@gmail.com" OR rcpt LIKE "*@outlook.com" OR rcpt LIKE "*@hotmail.com"
                       OR rcpt LIKE "*@yahoo.com" OR rcpt LIKE "*@icloud.com" OR rcpt LIKE "*@proton.me"
                       OR rcpt LIKE "*@protonmail.com" OR rcpt LIKE "*@gmx.*" OR rcpt LIKE "*@aol.com", 1, 0)
| WHERE sender LIKE "*@yourdomain.com" AND personal == 1
| STATS messages = COUNT(*),
        distinct_personal = COUNT_DISTINCT(rcpt),
        with_attachments = SUM(CASE(TO_STRING(mimecast.Attachments) != "" AND mimecast.Attachments IS NOT NULL, 1, 0)),
        recipients = VALUES(rcpt)
    BY sender, BUCKET(@timestamp, 1 hour)
| WHERE messages >= 10 OR with_attachments >= 5
```
Confirm the Mimecast receipt-log field names and that an attachment indicator is present. Replace `yourdomain.com` with your domains.

## Suppression
Suppress by `sender` for 12h. Alerts missing a key field are not suppressed. Aggregating rule. A drip spans buckets; a different sender still alerts.

## Known false positives / exclusions
- People legitimately mailing themselves small things. The attachment and volume thresholds reduce this; tune them. A single message is never flagged.
- Distribution and notification addresses that mail external consumers. Exclude them inline.

## Triage
- Confirm the sender and recipient relationship and the attachments. A spike to a personal address, especially from a leaver, is exfiltration. Correlate with IN01 and IN02 for the same person.

## Test
Send several attachments from a test mailbox to a personal address through the gateway.
