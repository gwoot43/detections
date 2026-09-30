---
id: E08
name: Full access, Send As or folder permission granted on a mailbox
category: email
status: todo
severity: medium
language: esql
index: logs-o365.audit-*
mitre: [T1098.002]
data_source: Microsoft 365 Unified Audit Log (Exchange admin audit)
suppression:
  fields: [actor, target]
  duration: 1h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
Delegation is how an attacker with admin reads an executive's mailbox without touching the executive's account. Grants to executive and finance mailboxes, or grants where the grantee is not a service desk account, are rare.

## Query
```esql
FROM logs-o365.audit-* METADATA _id, _index, _version
| WHERE event.action IN ("Add-MailboxPermission", "Add-RecipientPermission", "Add-MailboxFolderPermission", "Set-MailboxFolderPermission")
  AND event.outcome == "success"
| EVAL p = TO_LOWER(TO_STRING(o365.audit.Parameters)),
       target = TO_LOWER(TO_STRING(o365.audit.ObjectId)),
       actor = TO_LOWER(o365.audit.UserId)
| WHERE (p LIKE "*fullaccess*" OR p LIKE "*sendas*" OR p LIKE "*owner*" OR p LIKE "*editor*")
  AND NOT (actor IN ("svc-exchange-automation@yourdomain.com"))
  AND NOT (p LIKE "*\"user\", \"value\": \"nt authority\\self*")
| KEEP @timestamp, actor, target, event.action, o365.audit.ClientIP, p
```
Raise to high when `target` is on the VIP list from E03.

## Suppression
Suppress by `actor`, `target` for 1h. Alerts missing a key field are not suppressed. Permissions on one mailbox are often granted in several commands.

## Known false positives / exclusions
- Delegation self-service by users on their own calendar (`Add-MailboxFolderPermission` on `\Calendar`). Exclude when the folder is Calendar and grantee is internal.
- Shared-mailbox onboarding by the service desk. Exclude the service desk group, not individuals.

## Triage
- Who granted, to whom, on which mailbox. Check `MailItemsAccessed` for the grantee on that mailbox afterwards.

## Test
Grant and remove FullAccess on a test mailbox.
