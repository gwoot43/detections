---
id: E03
name: Impersonation Protect hit targeting executives or finance
category: email
status: todo
severity: medium
language: esql
index: logs-mimecast.ttp_ip_logs-*
mitre: [T1656, T1534, T1566.003]
data_source: Mimecast TTP Impersonation Protect logs
---
## Why this is high fidelity
Impersonation hits in general are noisy. Restricting to your payment-capable recipients and to the strong identifiers (internal user display name, similar internal domain, reply-to mismatch) turns it into a BEC early-warning with a small daily volume.

## Query
```esql
FROM logs-mimecast.ttp_ip_logs-* METADATA _id, _index, _version
| EVAL ids = TO_LOWER(MV_CONCAT(mimecast.identifiers, ",")),
       rcpt = TO_LOWER(mimecast.recipientAddress),
       action = TO_LOWER(COALESCE(mimecast.action, "none"))
| WHERE (ids LIKE "*internal_user_name*" OR ids LIKE "*similar_internal_domain*" OR ids LIKE "*reply_address_mismatch*")
  AND (rcpt IN ("cfo@yourdomain.com", "ceo@yourdomain.com", "ap@yourdomain.com", "payments@yourdomain.com")
       OR rcpt LIKE "*finance*" OR rcpt LIKE "*payroll*" OR rcpt LIKE "*accounts*")
  AND action IN ("none", "tag", "hold")    // delivered or held, not bounced
| KEEP @timestamp, rcpt, mimecast.senderAddress, mimecast.subject, ids, action, mimecast.definition, mimecast.taggedMalicious
```
Move the VIP list to a lookup index or an Elastic value list once it is stable.

## Known false positives / exclusions
- Newsletters using an executive's name as the friendly-from. Exclude by sender domain after review.

## Triage
- Read the message. Payment redirection, gift-card and urgency language means notify the recipient by phone and block the sender.
- Check whether the recipient replied (Mimecast outbound logs).

## Test
Send a test mail from an external Gmail with the CFO's display name to a finance test mailbox.
