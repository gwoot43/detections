---
id: E06
name: Inbox rule that forwards externally, deletes, or hides security-related mail
category: email
status: todo
severity: high
language: esql
index: logs-o365.audit-*
mitre: [T1114.003, T1564.008]
data_source: Microsoft 365 Unified Audit Log (Exchange admin audit, New-InboxRule and Set-InboxRule)
suppression:
  fields: [o365.audit.UserId, rule_name]
  duration: 1h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
This is the most reliable post-compromise indicator in Microsoft 365. Attackers create rules to forward mail out, or to delete or bury replies and security notifications so the victim never notices. The rule fires on three precise shapes: forwarding or redirecting to an address outside your domain, deleting or moving mail that matches words like "password" or "invoice", and a rule whose name is only punctuation or spaces.

## Prerequisite
The integration turns `Parameters` into one field per cmdlet parameter (`o365.audit.Parameters.<Name>`). `ForwardTo`, `ForwardAsAttachmentTo` and `RedirectTo` are mapped by the integration. `SubjectContainsWords`, `SubjectOrBodyContainsWords`, `MoveToFolder` and `DeleteMessage` are mapped only after the first rule that uses them is ingested. If any is missing, the query fails with "Unknown column". Map them as `keyword` in the `logs-o365.audit@custom` component template so the rule runs on a quiet tenant.

## Query
```esql
FROM logs-o365.audit-* METADATA _id, _index, _version
| WHERE event.provider == "Exchange" AND event.action IN ("New-InboxRule", "Set-InboxRule")
  AND event.outcome == "success"
| EVAL rule_name = MV_LAST(SPLIT(COALESCE(o365.audit.ObjectId, ""), "\\")),        // ObjectId is mailbox\rule name
       fwd = TO_LOWER(CONCAT(COALESCE(o365.audit.Parameters.ForwardTo, ""), ";",
                             COALESCE(o365.audit.Parameters.ForwardAsAttachmentTo, ""), ";",
                             COALESCE(o365.audit.Parameters.RedirectTo, ""))),
       words = TO_LOWER(CONCAT(COALESCE(o365.audit.Parameters.SubjectContainsWords, ""), ";",
                               COALESCE(o365.audit.Parameters.SubjectOrBodyContainsWords, ""))),
       folder = TO_LOWER(COALESCE(o365.audit.Parameters.MoveToFolder, "")),
       deletes = TO_LOWER(COALESCE(o365.audit.Parameters.DeleteMessage, "")) == "true"
// drop internal addresses; any address left is external
| EVAL forwards_out = REPLACE(fwd, "[a-z0-9._%+'-]+@yourdomain\\.com", "") LIKE "*@*",
       hides = (deletes OR folder LIKE "*rss*" OR folder LIKE "*conversation history*" OR folder LIKE "*archive*"
                OR folder LIKE "*deleted items*" OR folder LIKE "*junk*")
               AND (words LIKE "*password*" OR words LIKE "*invoice*" OR words LIKE "*payment*" OR words LIKE "*bank*"
                    OR words LIKE "*wire*" OR words LIKE "*hacked*" OR words LIKE "*phish*" OR words LIKE "*suspicious*"
                    OR words LIKE "*security*" OR words LIKE "*compromise*" OR words LIKE "*mfa*" OR words LIKE "*verification*"),
       odd_name = rule_name RLIKE "[^a-zA-Z0-9]+"                                       // name is only punctuation or spaces
| WHERE forwards_out OR hides OR odd_name
| WHERE NOT o365.audit.UserId IN ("svc-mailbox-automation@yourdomain.com")           // service desk automation
| KEEP @timestamp, o365.audit.UserId, source.ip, event.action, rule_name, forwards_out, hides, odd_name, fwd, folder, words
```
Rules created in the Outlook desktop client are logged as `UpdateInboxRules`, with the rule in `OperationProperties` rather than `Parameters`. They are not covered here.

## Suppression
Suppress by `o365.audit.UserId`, `rule_name` for 1h. Alerts missing a key field are not suppressed. Creating a rule is often followed by edits to the same rule.

## Known false positives / exclusions
- Users forwarding to a personal address is a policy problem, not a false positive. Keep it.
- Forwarding to an internal address given as a display name or `EX:` address has no `@`, so it is treated as internal. Add your other accepted domains to the `REPLACE` pattern.
- Shared-mailbox automation rules created by the service desk. Keep those accounts in the inline exclusion.

## Triage
- Check the creating session's IP (`source.ip`) against the user's normal Entra sign-in locations (I05).
- Remove the rule, reset the password, revoke sessions, and review sent items for the last 24 hours.

## Test
Create an inbox rule on a test mailbox that forwards to an external address.
