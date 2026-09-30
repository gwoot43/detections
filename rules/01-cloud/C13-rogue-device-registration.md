---
id: C13
name: Device registered or joined to Entra right after a risky sign-in
category: cloud
status: todo
severity: high
language: esql
index: logs-azure.auditlogs-*
mitre: [T1098.005, T1078.004]
data_source: Entra ID audit logs (Device registration)
suppression:
  fields: [actor]
  duration: 24h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
Registering an attacker-controlled device gives a long-lived Primary Refresh Token and can satisfy device-based Conditional Access, turning a phished session into durable access. This was a prominent 2026 enrollment-abuse pattern paired with device-code phishing. Registration is normal at onboarding, so fidelity comes from pairing it with a preceding risky or device-code sign-in (see the correlation X02 and the sign-in rules I07/I08).

## Query
```esql
FROM logs-azure.auditlogs-* METADATA _id, _index, _version
| EVAL op = TO_LOWER(azure.auditlogs.operation_name),
       actor = TO_LOWER(TO_STRING(COALESCE(azure.auditlogs.properties.initiated_by.user.userPrincipalName, ""))),
       target = TO_LOWER(TO_STRING(`azure.auditlogs.properties.target_resources.0.display_name`))
| WHERE azure.auditlogs.properties.category == "Device"
  AND (op LIKE "*add registered device*" OR op LIKE "*add device*" OR op LIKE "*register device*")
  AND azure.auditlogs.properties.result == "success"
| KEEP @timestamp, op, actor, target, source.ip
```
Standalone this is medium at best. The high-fidelity form is the correlation: this event within an hour of an I07/I08 hit for the same user. Build it as an enrich-index join like X02.

## Suppression
Suppress by `actor` for 24h. Alerts missing a key field are not suppressed. Onboarding can register a couple of devices in one session; a different user still alerts.

## Known false positives / exclusions
- New-hire and new-device onboarding. This is why the standalone rule is medium; the correlation with a risky sign-in is what makes it high.

## Triage
- Check the registering user's recent sign-ins for risk (I07) or device code (I08). If present, remove the device, revoke the user's sessions and tokens, and reset credentials.

## Test
Register a test device on a lab account and confirm the audit event appears.
