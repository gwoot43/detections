---
id: X02
name: Identity compromise fan-out: risky sign-in then persistence or privilege action
category: correlation
status: todo
severity: critical
language: esql
index: logs-azure.*
mitre: [T1078.004, T1098, T1528, T1114.003]
data_source: Entra sign-in (I07/I08) + Entra audit (C03/C04/C05/E06/I10) joined on user
---
## Why this is high fidelity
A single risky sign-in is a maybe. A risky or device-code sign-in followed within the hour by any of: a new MFA method, an inbox forwarding rule, an app consent, a credential added to an app, or a privileged role assignment, by the same user, is the textbook account-takeover-to-persistence chain. The sequence is what makes it certain.

## Query (pattern)
```esql
FROM logs-azure.auditlogs-*
| WHERE @timestamp > NOW() - 1 hour
| EVAL usr = TO_LOWER(COALESCE(azure.auditlogs.properties.initiated_by.user.userPrincipalName, azure.auditlogs.properties.target_resources.0.user_principal_name)),
       persist_action = TO_LOWER(azure.auditlogs.operation_name)
| WHERE persist_action LIKE "*security info*" OR persist_action LIKE "*inboxrule*" OR persist_action LIKE "*consent*"
     OR persist_action LIKE "*add member to role*" OR persist_action LIKE "*add service principal credentials*"
     OR persist_action LIKE "*add app role assignment*"
| LOOKUP JOIN risky_signins_last_2h ON usr
| WHERE risk_at IS NOT NULL AND @timestamp >= risk_at
| KEEP @timestamp, usr, persist_action, risk_level, risk_detail, source.ip, risk_at
```
Build `risky_signins_last_2h` from I07/I08 (fields: `usr`, `risk_at`, `risk_level`, `risk_detail`). Or implement as an Elastic indicator-match rule: indicator = risky sign-ins, events = the audit persistence actions, match on user, 1-hour look-back.

## Known false positives / exclusions
- A user who genuinely triggers a risk flag (travel) and legitimately registers a new phone in the same window. Rare, and worth the phone call anyway.

## Triage
- Full account-takeover response: revoke sessions and refresh tokens, reset password, remove the attacker's persistence (MFA method, rule, consent, credential, role), and audit what was accessed.

## Test
On a lab account, simulate a risky sign-in then register an MFA method within the hour.
