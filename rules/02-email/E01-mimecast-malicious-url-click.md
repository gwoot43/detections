---
id: E01
name: User clicked a URL Mimecast rated malicious, or clicked through a warning
category: email
status: todo
severity: high
language: esql
index: logs-mimecast.ttp_url_logs-*
mitre: [T1566.002, T1204.001]
data_source: Mimecast TTP URL Protect logs (Elastic Mimecast integration, ttp_url_logs data stream)
suppression:
  fields: [usr, url.original]
  duration: 24h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
A click is a human acting on the lure. The rule keeps only real user clicks (`creationMethod` "User Click", not gateway entry scans) where Mimecast rated the URL malicious at click time, or where the user went past a block or warning page. Delivered-but-ignored mail and awareness challenges on allowed URLs are left out. This is the trigger for the correlation rule X01 (click then EDR alert).

## Query
```esql
FROM logs-mimecast.ttp_url_logs-* METADATA _id, _index, _version
| EVAL method = TO_LOWER(COALESCE(mimecast.creationMethod, "")),
       result = TO_LOWER(COALESCE(mimecast.scanResult, "")),
       action = TO_LOWER(COALESCE(mimecast.action, "")),
       user_override = TO_LOWER(COALESCE(mimecast.userOverride, "none")),
       awareness = TO_LOWER(COALESCE(event.action, "")),
       usr = TO_LOWER(MV_FIRST(user.email))
| WHERE method == "user click"
  AND (result == "malicious"
       OR (action IN ("block", "warn")                                   // user went past the block or warning page
           AND (NOT user_override IN ("none", "n/a", "") OR awareness == "continue")))
  AND NOT usr IN ("soc-sandbox@yourdomain.com")                                        // analyst test mailboxes
| KEEP @timestamp, usr, url.original, result, action, user_override, awareness, email.from.address, email.subject,
       email.direction, rule.name, mimecast.category
```
The click-through values (`mimecast.userOverride`, and `event.action` "Continue" on a block or warning page) are not in the package samples; confirm them on one real click-through. The same click definition drives X01. The integration renames most URL log fields: `url` to `url.original`, `userEmailAddress` to `user.email`, `fromUserEmailAddress` to `email.from.address`, `subject` to `email.subject`, `route` to `email.direction`, `ttpDefinition` to `rule.name`, `userAwarenessAction` to `event.action`. The old `mimecast.*` names are empty.

## Suppression
Suppress by `usr`, `url.original` for 24h. Alerts missing a key field are not suppressed. Users click the same link repeatedly. A different link still alerts.

## Known false positives / exclusions
- Security team sandbox clicks. Keep the analyst mailboxes in the inline exclusion.
- Internal-route clicks (`email.direction == "internal"`) on a malicious verdict still matter: an internal account is forwarding a phish.

## Triage
- `action` says whether Mimecast blocked the page. A blocked click is lower impact; an allowed or overridden click means the user reached the page.
- Pull the message and the URL destination, and check whether the page harvested credentials.
- Check Entra sign-ins for the user in the next 2 hours (I05, I07) and CrowdStrike for the host (X01). If credentials were entered, reset and revoke tokens.

## Test
Click a URL from Mimecast's test set in a lab mailbox and confirm the record has `creationMethod` "User Click" and a malicious result.
