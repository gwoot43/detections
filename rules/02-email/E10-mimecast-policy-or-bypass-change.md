---
id: E10
name: Mimecast protection policy weakened or bypass created
category: email
status: todo
severity: high
language: esql
index: logs-mimecast.audit_events-*
mitre: [T1562.001, T1685, T1078]
data_source: Mimecast administration audit events
---
## Why this is high fidelity
Adding a permitted sender, creating a bypass policy for URL Protect or Attachment Protect, or disabling Impersonation Protect are the mail-gateway equivalent of turning off the EDR. Mimecast admin changes are low volume and made by a handful of named admins.

## Query
```esql
FROM logs-mimecast.audit_events-* METADATA _id, _index, _version
| EVAL cat = TO_LOWER(mimecast.category), info = TO_LOWER(TO_STRING(mimecast.eventInfo)), atype = TO_LOWER(mimecast.auditType)
| WHERE cat IN ("policy_logs", "account_logs", "gateway_logs")
  AND (
       info LIKE "*bypass*" OR info LIKE "*permitted sender*" OR info LIKE "*permit*"
    OR info LIKE "*url protect*" OR info LIKE "*attachment protect*" OR info LIKE "*impersonation protect*"
    OR info LIKE "*anti-spoofing*" OR info LIKE "*dns authentication*" OR info LIKE "*targeted threat protection*"
    OR atype LIKE "*policy*delet*" OR atype LIKE "*policy*disabl*"
    OR atype LIKE "*admin*logon*" OR atype LIKE "*2fa*" OR atype LIKE "*api*"      // admin auth and API-key events
  )
| KEEP @timestamp, atype, cat, mimecast.user, info, source.ip
```

## Known false positives / exclusions
- Routine permitted-sender additions by the service desk. Route those to a lower-severity queue but keep them visible: repeated permits for the same external domain is a pattern.

## Triage
- Confirm the change with the admin. Check the admin's Mimecast logon source IP against known locations.

## Test
Create and delete a test bypass policy in Mimecast admin console.
