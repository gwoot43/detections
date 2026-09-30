---
id: E06
name: Inbox rule that forwards externally, deletes, or hides security-related mail
category: email
status: todo
severity: high
language: esql
index: logs-o365.audit-*
mitre: [T1114.003, T1564.008]
data_source: Microsoft 365 Unified Audit Log (Exchange mailbox audit)
suppression:
  fields: [o365.audit.UserId, rule_name]
  duration: 1h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
This is the most reliable post-compromise indicator in Microsoft 365. Attackers create rules to forward mail out, or to hide replies and security notifications so the victim never notices. Legitimate users rarely forward to external domains or delete based on keywords like "password" or "invoice".

## Query
```esql
FROM logs-o365.audit-* METADATA _id, _index, _version
| WHERE event.action IN ("New-InboxRule", "Set-InboxRule", "UpdateInboxRules", "Enable-InboxRule")
  AND event.outcome == "success"
| EVAL p = TO_LOWER(TO_STRING(o365.audit.Parameters))
| EVAL forwards_out = (p LIKE "*forwardto*" OR p LIKE "*forwardasattachmentto*" OR p LIKE "*redirectto*")
                      AND NOT (p LIKE "*@yourdomain.com*"),
       hides = (p LIKE "*deletemessage*" OR p LIKE "*movetofolder*" OR p LIKE "*markasread*")
               AND (p LIKE "*password*" OR p LIKE "*invoice*" OR p LIKE "*payment*" OR p LIKE "*bank*"
                    OR p LIKE "*hacked*" OR p LIKE "*phish*" OR p LIKE "*suspicious*" OR p LIKE "*security*"
                    OR p LIKE "*mfa*" OR p LIKE "*verification*" OR p LIKE "*rss feeds*" OR p LIKE "*conversation history*"),
       rule_name = TO_LOWER(TO_STRING(o365.audit.ObjectId))
| WHERE forwards_out OR hides OR rule_name IN (".", "..", ",", "a", "1", " ")
| KEEP @timestamp, o365.audit.UserId, o365.audit.ClientIP, event.action, rule_name, forwards_out, hides, p
```
`o365.audit.Parameters` is an array of `{Name, Value}` in the raw log. If your pipeline keeps it as an object you can test `o365.audit.Parameters.ForwardTo` directly. The `TO_STRING` approach works on either shape.

## Suppression
Suppress by `o365.audit.UserId`, `rule_name` for 1h. Alerts missing a key field are not suppressed. Creating a rule is often followed by edits to the same rule.

## Known false positives / exclusions
- Users forwarding to a personal address is a policy problem, not a false positive. Keep it.
- Shared-mailbox automation rules created by the service desk. Exclude those service accounts.

## Triage
- Check the creating session's IP against the user's normal Entra sign-in locations (I05).
- Remove the rule, reset the password, revoke sessions, review sent items for the last 24 hours.

## Test
Create an inbox rule on a test mailbox that forwards to an external address.
