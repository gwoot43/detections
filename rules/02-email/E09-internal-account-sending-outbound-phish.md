---
id: E09
name: Internal account sending outbound mail that Mimecast holds or rejects at volume
category: email
status: todo
severity: high
language: esql
index: logs-mimecast.siem_logs-*
mitre: [T1534, T1114, T1078.004]
data_source: Mimecast SIEM receipt/process logs (outbound route)
---
## Why this is high fidelity
A compromised mailbox is usually first noticed when it starts sending the phish onward. Ten or more outbound messages from one internal sender that Mimecast holds, rejects or tags as spam within 15 minutes has no benign explanation outside marketing tools, which you exclude.

## Query
```esql
FROM logs-mimecast.siem_logs-*
| WHERE TO_LOWER(mimecast.Dir) == "outbound"
  AND (TO_LOWER(mimecast.Act) IN ("hld", "rej", "rejected", "held") OR TO_LOWER(mimecast.SpamScore) IS NOT NULL AND TO_DOUBLE(mimecast.SpamScore) >= 5)
| EVAL sender = TO_LOWER(mimecast.Sender)
| WHERE sender LIKE "*@yourdomain.com" AND NOT (sender IN ("marketing@yourdomain.com", "noreply@yourdomain.com"))
| STATS n = COUNT(*), rcpts = COUNT_DISTINCT(mimecast.Rcpt), subjects = VALUES(mimecast.Subject), ips = VALUES(mimecast.IP)
    BY sender, BUCKET(@timestamp, 15 minutes)
| WHERE n >= 10 AND rcpts >= 5
```
Field names here are the Mimecast SIEM receipt-log names (`Dir`, `Act`, `Sender`, `Rcpt`, `SpamScore`). Check the exact casing your integration produces.

## Known false positives / exclusions
- Marketing and transactional senders. Exclude by address.
- Legitimate mass mail flagged by a broken DKIM key. Still worth knowing.

## Triage
- Disable the account, revoke sessions, check inbox rules (E06), check sign-ins (I05, I07).

## Test
Validate on historical data. Do not send test spam from production.
