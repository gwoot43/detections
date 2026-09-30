---
id: E02
name: Malicious attachment verdict on a message that was delivered or released
category: email
status: todo
severity: high
language: esql
index: logs-mimecast.ttp_ap_logs-*
mitre: [T1566.001, T1204.002]
data_source: Mimecast TTP Attachment Protect logs
---
## Why this is high fidelity
Attachment Protect blocks most malware at the gateway. The signal you want is the residue: a malicious verdict where the message still reached the mailbox, usually because it was held then released, or the verdict arrived after delivery (sandbox timeout, safe-file conversion off).

## Query
```esql
FROM logs-mimecast.ttp_ap_logs-* METADATA _id, _index, _version
| EVAL result = TO_LOWER(mimecast.result), triggered = TO_LOWER(COALESCE(mimecast.actionTriggered, "none"))
| WHERE result IN ("malicious", "unsafe")
  AND (triggered IN ("none", "user release", "admin release") OR triggered LIKE "*release*")
| KEEP @timestamp, mimecast.recipientAddress, mimecast.senderAddress, mimecast.subject, mimecast.fileName, mimecast.fileType, mimecast.fileHash, result, triggered, mimecast.definition, mimecast.route
```

## Known false positives / exclusions
- Very few. Releases by the security team on confirmed false positives should be logged with the ticket, not excluded.

## Triage
- Hash lookup in CrowdStrike (`file.hash.sha256` across FDR `PeFileWritten` and `ProcessRollup2`). If the file was written or executed on the recipient's host, escalate to W02 / X01 handling.
- Purge the message from all recipient mailboxes.

## Test
Deliver an EICAR attachment to a lab mailbox with Attachment Protect set to hold, then release it.
