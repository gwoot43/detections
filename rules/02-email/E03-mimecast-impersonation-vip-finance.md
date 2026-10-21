---
id: E03
name: Impersonation Protect hit targeting executives or finance
category: email
status: todo
language: esql
index: logs-mimecast.ttp_ip_logs-*
mitre: [T1684.001, T1534, T1566.003]
data_source: Mimecast TTP Impersonation Protect logs (Elastic Mimecast integration, ttp_ip_logs data stream)
suppression:
  fields: [sender, rcpt]
  duration: 24h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
Impersonation hits in general are noisy. Restricting to your payment-capable recipients and to the strong identifiers (internal user display name, similar internal domain, reply-to mismatch) turns it into a BEC early-warning with a small daily volume.

## Query
```esql
FROM logs-mimecast.ttp_ip_logs-* METADATA _id, _index, _version
| EVAL ids = TO_LOWER(MV_CONCAT(mimecast.identifiers, ",")),
       rcpt = TO_LOWER(MV_FIRST(email.to.address)),
       sender = TO_LOWER(MV_FIRST(email.from.address)),
       action = TO_LOWER(COALESCE(event.action, "none"))
| WHERE (ids LIKE "*internal_user_name*" OR ids LIKE "*similar_internal_domain*" OR ids LIKE "*reply_address_mismatch*")
  AND (rcpt IN ("cfo@yourdomain.com", "ceo@yourdomain.com", "ap@yourdomain.com", "payments@yourdomain.com")
       OR rcpt LIKE "*finance*" OR rcpt LIKE "*payroll*" OR rcpt LIKE "*accounts*")
  AND NOT (action LIKE "*bounce*" OR action LIKE "*reject*")    // delivered, tagged or held, not bounced
| KEEP @timestamp, rcpt, sender, email.subject, ids, action, rule.name, mimecast.taggedMalicious, source.ip, _id, _version, _index
```
The integration moves recipient and sender to `email.to.address` and `email.from.address`, `action` to `event.action`, `definition` to `rule.name`, and `senderIpAddress` to `source.ip`. Move the VIP list to an Elastic value list once it is stable.

## Suppression
Suppress by `sender`, `rcpt` for 24h. Alerts missing a key field are not suppressed. A BEC sender writes repeatedly to the same target.

## Known false positives / exclusions
- Newsletters using an executive's name as the friendly-from. Exclude by sender domain after review.

## Triage
- Read the message. Payment redirection, gift-card and urgency language means notify the recipient by phone and block the sender.
- Check whether the recipient replied (Mimecast outbound logs).

## Test
Send a test mail from an external Gmail with the CFO's display name to a finance test mailbox.
