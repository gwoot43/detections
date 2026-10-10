---
id: C13
name: Device registered or joined to Entra right after a risky sign-in
category: cloud
status: todo
severity: high
language: esql
index: logs-azure.signinlogs-*, logs-azure.auditlogs-*
mitre: [T1098.005, T1078.004]
data_source: Entra ID sign-in logs + audit logs (Device registration), joined on user object ID
suppression:
  fields: [uid]
  duration: 24h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
Registering an attacker-controlled device gives a long-lived Primary Refresh Token and can satisfy device-based Conditional Access, turning a phished session into durable access. This was a prominent 2026 enrollment-abuse pattern paired with device-code phishing. Registration on its own is normal: every new phone with Authenticator or Company Portal registers. Fidelity comes from the pairing: a successful sign-in that Entra rated medium or high risk, or a device-code sign-in, followed by a device registration for the same user within the hour.

## Query
Run every 15 minutes with a 1-hour lookback.
```esql
FROM logs-azure.signinlogs-*, logs-azure.auditlogs-*
| WHERE (data_stream.dataset == "azure.signinlogs"
         AND azure.signinlogs.category == "SignInLogs"
         AND TO_STRING(azure.signinlogs.properties.status.error_code) == "0"
         AND (azure.signinlogs.properties.risk_level_during_signin IN ("medium", "high")
              OR TO_LOWER(TO_STRING(azure.signinlogs.properties.authentication_protocol)) == "devicecode"))
     OR (data_stream.dataset == "azure.auditlogs"
         // "Register device" is the user-initiated record; "Add device" is written by the service with no user
         AND azure.auditlogs.operation_name == "Register device"
         AND event.outcome == "success")
| EVAL uid = COALESCE(azure.signinlogs.properties.user_id, azure.auditlogs.properties.initiated_by.user.id),
       upn = TO_LOWER(COALESCE(azure.signinlogs.properties.user_principal_name, azure.auditlogs.properties.initiated_by.user.userPrincipalName)),
       stage = CASE(data_stream.dataset == "azure.signinlogs", "risky", "register"),
       reason = CASE(stage == "register", NULL,
                     TO_LOWER(TO_STRING(azure.signinlogs.properties.authentication_protocol)) == "devicecode", "device code",
                     CONCAT("risk ", azure.signinlogs.properties.risk_level_during_signin))
| WHERE uid IS NOT NULL
| STATS risky_at = MIN(CASE(stage == "risky", @timestamp, NULL)),
        register_at = MAX(CASE(stage == "register", @timestamp, NULL)),
        reasons = VALUES(reason),
        upns = VALUES(upn),
        signin_ips = VALUES(CASE(stage == "risky", source.ip, NULL)),
        signin_asns = VALUES(CASE(stage == "risky", source.as.organization.name, NULL)),
        devices = VALUES(CASE(stage == "register", `azure.auditlogs.properties.target_resources.0.display_name`, NULL))
    BY uid
| WHERE risky_at IS NOT NULL AND register_at IS NOT NULL AND register_at >= risky_at
| EVAL signin_to_register_min = DATE_DIFF("minute", risky_at, register_at)
```
The lookback is the correlation window. Risk levels are only populated with Entra ID P2; without it, the device-code half still works.

## Suppression
Suppress by `uid` for 24h. Alerts missing a key field are not suppressed. Aggregating rule. The same pair re-matches on every run while the lookback overlaps.

## Known false positives / exclusions
- A new hire whose first sign-in is rated risky (new location, new device) and who then enrolls their laptop. Check `reasons` and the device name against the onboarding ticket.
- Sanctioned device-code users (Azure CLI, conference-room devices) who also register a device. Exclude them by object ID.

## Triage
- Check the registering user's sign-ins around `risky_at` (I07 for risk, I08 for device code). If the sign-in IP or ASN is not the user's, delete the device first, then revoke the user's sessions and tokens and reset credentials.
- Check S16, S18 and S20 for the same user: a Hello key, a roadtx fingerprint or a broker token chain confirms the attack.

## Test
In a lab tenant, sign in a test user with the device code flow, then register a test device for that user within the hour.
