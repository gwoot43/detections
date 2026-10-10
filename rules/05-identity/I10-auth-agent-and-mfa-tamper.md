---
id: I10
name: MFA method registered from a new context, or authentication policy weakened
category: identity
status: todo
severity: medium
language: esql
index: logs-azure.auditlogs-*
mitre: [T1556.006, T1098.005]
data_source: Entra ID audit logs
suppression:
  fields: [target, op]
  duration: 1h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
After stealing a password, attackers register their own MFA method to gain durable access, or an admin disables security defaults / weakens the authentication methods policy. Self-service MFA registration is normal at onboarding, so the fidelity comes from registration happening right after a risky sign-in, or from admin-level policy changes which are always rare. Routine security-info events (reviewed, deleted, registration started or cancelled) and broad tenant changes such as "Set company information" are left out.

## Query
```esql
FROM logs-azure.auditlogs-* METADATA _id, _index, _version
| EVAL op = TO_LOWER(azure.auditlogs.operation_name),
       actor = TO_LOWER(COALESCE(azure.auditlogs.properties.initiated_by.user.userPrincipalName, azure.auditlogs.properties.initiated_by.app.displayName)),
       target = TO_LOWER(TO_STRING(`azure.auditlogs.properties.target_resources.0.user_principal_name`))
| WHERE event.outcome == "success"                // the integration moves properties.result to event.outcome
  AND (
       op IN ("user registered security info", "admin registered security info")   // a new method on an account
    OR op LIKE "*authentication methods policy*"                                    // tenant-wide method policy changed
    OR op LIKE "*disable strong authentication*"                                    // per-user MFA turned off
    OR op LIKE "*security defaults*"
  )
| KEEP @timestamp, op, actor, target, source.ip,
       azure.auditlogs.properties.additional_details.key, azure.auditlogs.properties.additional_details.value
```
The high-fidelity version joins this to I07: an MFA method registered within an hour of a high-risk sign-in for the same user. Run as a correlation rule once both are live.

## Suppression
Suppress by `target`, `op` for 1h. Alerts missing a key field are not suppressed. Registration flows write several audit records.

## Known false positives / exclusions
- New-hire onboarding registration. Exclude the first registration within N days of account creation, or during the onboarding window.
- Users re-registering after getting a new phone. This is why the standalone rule is medium and the correlation with I07 is high.

## Triage
- Compare the registration IP and the newly added method (phone number, authenticator) against the user's known details. An unknown number is attacker persistence: remove it, reset credentials, revoke sessions.

## Test
Register a new authenticator method on a lab account and confirm it appears.
