---
id: E09
name: Internal account sending outbound mail that Mimecast holds as spam or rejects, at volume
category: email
status: todo
severity: high
language: esql
index: logs-mimecast.siem_logs-*
mitre: [T1534, T1114, T1078.004]
data_source: Mimecast SIEM receipt and process logs (Elastic Mimecast integration, siem_logs data stream)
suppression:
  fields: [sender]
  duration: 24h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
A compromised mailbox is usually first noticed when it starts sending the phish onward. Ten or more distinct messages from one internal sender in 15 minutes that Mimecast rejects outbound or holds as spam has no benign explanation outside marketing tools, which you exclude.

## Query
```esql
FROM logs-mimecast.siem_logs-*
| EVAL log_type = TO_LOWER(mimecast.log_type), act = TO_LOWER(COALESCE(event.action, "")),
       reason = TO_LOWER(COALESCE(event.reason, ""))
| WHERE (log_type == "receipt" AND email.direction == "outbound" AND act == "rej")
     OR (log_type == "process" AND act == "hld" AND reason == "spm")     // held as spam
| EVAL sender = TO_LOWER(MV_MIN(email.from.address))
| WHERE sender LIKE "*@yourdomain.com"
  AND NOT sender IN ("marketing@yourdomain.com", "noreply@yourdomain.com")
| STATS messages = COUNT_DISTINCT(email.message_id), rcpts = COUNT_DISTINCT(email.to.address),
        subjects = VALUES(email.subject), ips = VALUES(source.ip)
    BY sender, BUCKET(@timestamp, 15 minutes)
| WHERE messages >= 10
```
The integration moves the SIEM fields to ECS: `Dir` to `email.direction` (lower case), `Act` to `event.action`, `Hld` to `event.reason`, `Sender` to `email.from.address`, `Rcpt` to `email.to.address`, `Subject` to `email.subject`, `IP` to `source.ip`, `MsgId` to `email.message_id`. The same names apply to the 2.0 API logs. Process logs carry no direction or recipient, so `rcpts` counts receipt rows only.

## Suppression
Suppress by `sender` for 24h. Alerts missing a key field are not suppressed. Aggregating rule. A compromised mailbox keeps sending for hours.

## Known false positives / exclusions
- Marketing and transactional senders. Exclude by address.
- Legitimate mass mail flagged because of a broken DKIM key. Still worth knowing.

## Triage
- Disable the account, revoke sessions, check inbox rules (E06), check sign-ins (I07, S13, S14).

## Test
Validate on historical data. Do not send test spam from production.
