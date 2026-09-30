---
id: E07
name: Mailbox forwarding enabled or transport rule that redirects or BCCs mail
category: email
status: todo
severity: high
language: esql
index: logs-o365.audit-*
mitre: [T1114.003]
data_source: Microsoft 365 Unified Audit Log (Exchange admin audit)
suppression:
  fields: [o365.audit.UserId, o365.audit.ObjectId]
  duration: 1h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
`Set-Mailbox -ForwardingSmtpAddress` and transport rules with `RedirectMessageTo` or `BlindCopyTo` are organisation-level exfiltration channels that survive the user's password reset. They are admin actions with a very small legitimate population.

## Query
```esql
FROM logs-o365.audit-* METADATA _id, _index, _version
| WHERE event.action IN ("Set-Mailbox", "New-TransportRule", "Set-TransportRule", "Enable-TransportRule", "New-JournalRule", "Set-RemoteDomain", "New-RemoteDomain")
  AND event.outcome == "success"
| EVAL p = TO_LOWER(TO_STRING(o365.audit.Parameters))
| WHERE (event.action == "Set-Mailbox" AND (p LIKE "*forwardingsmtpaddress*" OR p LIKE "*forwardingaddress*") AND NOT (p LIKE "*forwardingsmtpaddress\", \"value\": \"\"*"))
   OR (event.action LIKE "*TransportRule" AND (p LIKE "*redirectmessageto*" OR p LIKE "*blindcopyto*" OR p LIKE "*copyto*" OR p LIKE "*addtorecipients*"))
   OR (event.action LIKE "*JournalRule")
   OR (event.action LIKE "*RemoteDomain" AND p LIKE "*autoforwardenabled\", \"value\": \"true*")
| KEEP @timestamp, o365.audit.UserId, o365.audit.ClientIP, event.action, o365.audit.ObjectId, p
```

## Suppression
Suppress by `o365.audit.UserId`, `o365.audit.ObjectId` for 1h. Alerts missing a key field are not suppressed. Admin scripts re-apply the same setting.

## Known false positives / exclusions
- Leaver process forwarding to a manager (internal address). Split severity on whether the target is internal.
- Compliance journaling changes. Ticket-gated, not excluded.

## Triage
- Remove the forwarding, identify the admin session, look for a matching privileged role assignment (C03) or credential add (C04).

## Test
Set and clear `ForwardingSmtpAddress` on a test mailbox.
