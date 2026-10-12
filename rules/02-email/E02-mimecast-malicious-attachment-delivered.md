---
id: E02
name: Malicious attachment verdict on a message that was delivered or released
category: email
status: todo
severity: high
language: esql
index: logs-mimecast.ttp_ap_logs-*
mitre: [T1566.001, T1204.002]
data_source: Mimecast TTP Attachment Protect logs (Elastic Mimecast integration, ttp_ap_logs data stream)
suppression:
  fields: [rcpt, sha256]
  duration: 24h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
Attachment Protect blocks most malware at the gateway. The signal you want is the residue: a malicious verdict where no blocking action was triggered, or where the message was released anyway. That happens when a monitor-only definition applies (often internal mail), or when a user or admin released a held message.

## Query
```esql
FROM logs-mimecast.ttp_ap_logs-* METADATA _id, _index, _version
| EVAL result = TO_LOWER(COALESCE(mimecast.result, "")),
       triggered = TO_LOWER(COALESCE(event.action, "none")),
       rcpt = TO_LOWER(MV_FIRST(email.to.address)),
       sha256 = COALESCE(email.attachments.file.hash.sha256, mimecast.fileHash)
| WHERE result IN ("malicious", "unsafe")
  AND (triggered LIKE "none*" OR triggered LIKE "*release*")    // nothing blocked it, or it was released
| KEEP @timestamp, rcpt, email.from.address, email.subject, email.attachments.file.name,
       email.attachments.file.mime_type, sha256, result, triggered, rule.name, email.direction, _id, _version, _index
```
The integration moves `actionTriggered` to `event.action`, rewritten as lower-case words joined by underscores (`user release, none` becomes `user_release_none`). Recipient, sender, file name, hash, subject and definition move to `email.*` and `rule.name`. A hash that is not 64 characters stays in `mimecast.fileHash`.

## Suppression
Suppress by `rcpt`, `sha256` for 24h. Alerts missing a key field are not suppressed. The same attachment is often re-delivered or re-released.

## Known false positives / exclusions
- Very few. Releases by the security team on confirmed false positives should be logged with the ticket, not excluded.

## Triage
- Hash lookup in CrowdStrike (`file.hash.sha256` across FDR `PeFileWritten` and `ProcessRollup2`). If the file was written or executed on the recipient's host, escalate to W02 / X01 handling.
- Purge the message from all recipient mailboxes.

## Test
Deliver an EICAR attachment to a lab mailbox with Attachment Protect set to hold, then release it.
