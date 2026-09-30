---
id: E01
name: User clicked a URL Mimecast rated malicious, or clicked through a warning
category: email
status: todo
severity: high
language: esql
index: logs-mimecast.ttp_url_logs-*
mitre: [T1566.002, T1204.001]
data_source: Mimecast TTP URL Protect logs (Elastic Mimecast integration, v1 field names)
---
## Why this is high fidelity
A click is a human acting on the lure. Mimecast's own verdict at click time filters out the noise of delivered-but-ignored mail. This is the trigger for the correlation rule X01 (click then EDR alert).

## Query
```esql
FROM logs-mimecast.ttp_url_logs-* METADATA _id, _index, _version
| EVAL result = TO_LOWER(mimecast.scanResult), action = TO_LOWER(mimecast.action),
       override = TO_LOWER(COALESCE(mimecast.userOverride, "none"))
| WHERE result == "malicious"
   OR (action == "block" AND override != "none")          // user clicked through the block page
   OR TO_LOWER(mimecast.userAwarenessAction) == "continue" // continued past awareness challenge on a suspicious URL
| KEEP @timestamp, mimecast.userEmailAddress, mimecast.fromUserEmailAddress, mimecast.subject, mimecast.url, result, action, override, mimecast.ttpDefinition, mimecast.route
```
Field names on the Mimecast 2.0 integration (`logs-mimecast.siem_logs-*`) move to `mimecast.log_type == "url protect"` with `mimecast.scan_result` and `mimecast.user_email_address`. Adjust when you migrate.

## Known false positives / exclusions
- Security team sandbox clicks. Exclude the analyst mailbox list.
- Internal route clicks (`mimecast.route == "internal"`) on a malicious verdict still matter: that is an internal account forwarding a phish.

## Triage
- Pull the message, the URL destination (Mimecast rewrite target), and whether the page was credential harvesting.
- Check Entra sign-ins for the user in the next 2 hours (I05, I07) and CrowdStrike for the host (X01).
- If credentials were entered, reset and revoke tokens.

## Test
Send a message with a known EICAR-style test URL from Mimecast's test set and click it from a lab mailbox.
