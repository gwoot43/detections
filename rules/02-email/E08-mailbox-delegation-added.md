---
id: E08
name: Full access, Send As or folder owner/editor permission granted on a mailbox
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
Delegation is how an attacker with admin rights reads an executive's mailbox without touching the executive's account. Grants made by a person (not by Exchange provisioning), excluding self-service calendar sharing, are rare.

## Prerequisite
`o365.audit.Parameters.AccessRights` is mapped by the integration. `Parameters.User` and `Parameters.Identity` are mapped dynamically; they appear in almost every tenant, but if either is missing the query fails with "Unknown column". Map them as `keyword` in the `logs-o365.audit@custom` component template to be safe.

## Query
```esql
FROM logs-o365.audit-* METADATA _id, _index, _version
| WHERE event.provider == "Exchange" AND event.outcome == "success"
  AND event.action IN ("Add-MailboxPermission", "Add-RecipientPermission", "Add-MailboxFolderPermission", "Set-MailboxFolderPermission")
| EVAL rights = TO_LOWER(MV_CONCAT(o365.audit.Parameters.AccessRights, ",")),
       target = TO_LOWER(o365.audit.ObjectId),
       actor = TO_LOWER(o365.audit.UserId),
       grantee = TO_LOWER(COALESCE(o365.audit.Parameters.User, "")),
       folder = TO_LOWER(COALESCE(o365.audit.Parameters.Identity, ""))
| WHERE (rights LIKE "*fullaccess*" OR rights LIKE "*sendas*" OR rights LIKE "*owner*" OR rights LIKE "*editor*")
  AND NOT actor LIKE "nt authority*"                                                 // Exchange provisioning
  AND NOT actor IN ("svc-exchange-automation@yourdomain.com")                       // service desk automation
  AND NOT grantee == "nt authority\\self"
  AND NOT (event.action LIKE "*FolderPermission" AND folder LIKE """*:\\calendar*""")   // calendar sharing
| KEEP @timestamp, actor, target, grantee, rights, event.action, source.ip, _id, _version, _index
```
`Add-RecipientPermission` names the grantee in `Trustee`, which is not read here to avoid another dynamic field; `target` and `rights` are enough to triage. Raise to high when `target` is on the VIP list from E03.

## Suppression
Suppress by `actor`, `target` for 1h. Alerts missing a key field are not suppressed. Permissions on one mailbox are often granted in several commands.

## Known false positives / exclusions
- Shared-mailbox onboarding by the service desk. Keep the service desk automation accounts in the inline exclusion, not individuals.

## Triage
- Who granted, to whom, on which mailbox. Check `MailItemsAccessed` for the grantee on that mailbox afterwards.

## Test
Grant and remove FullAccess on a test mailbox.
