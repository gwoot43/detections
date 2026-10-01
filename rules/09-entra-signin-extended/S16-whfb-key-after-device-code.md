---
id: S16
name: Windows Hello for Business key enrolled after a device-code sign-in (PRT phishing chain)
category: entra-signin
status: todo
severity: high
language: esql
index: logs-azure.signinlogs-*, logs-azure.auditlogs-*
mitre: [T1098.005, T1556.006, T1528]
data_source: Entra ID sign-in logs + audit logs, joined on user object ID
references: [https://dirkjanm.io/phishing-for-microsoft-entra-primary-refresh-tokens/, https://dirkjanm.io/borrowing-windows-hello-keys/]
suppression:
  fields: [uid, severity]
  duration: 24h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
Dirk-jan Mollema showed that a device-code phish can be turned into a Primary Refresh Token and then into a Windows Hello for Business key that the attacker owns. The key counts as phishing-resistant MFA and survives password resets and session revocation. The attacker's sequence in the logs is: a device-code sign-in, then often a device registration, then "Add Windows Hello for Business credential" for the same user.

Real Windows Hello enrollment happens on a device during setup, not after a device-code sign-in. A new laptop going through Autopilot produces a device registration followed by a Hello enrollment, so that pair alone is normal and does not alert here. The device-code sign-in is what separates attack from onboarding.

Severity is computed per alert:
- **critical** when the device-code sign-in used the Microsoft Authentication Broker client, or a device was registered in between. Both match the published chain.
- **high** for a device-code sign-in followed by a Hello enrollment.

## Query
Run every 15 minutes with a 1-hour lookback.
```esql
FROM logs-azure.signinlogs-*, logs-azure.auditlogs-*
| WHERE (data_stream.dataset == "azure.signinlogs"
         AND TO_STRING(azure.signinlogs.properties.status.error_code) == "0"
         AND TO_LOWER(TO_STRING(azure.signinlogs.properties.authentication_protocol)) == "devicecode")
     OR (data_stream.dataset == "azure.auditlogs"
         AND event.outcome IN ("success", "Success")
         AND azure.auditlogs.operation_name IN ("Register device", "Add registered owner to device", "Add device", "Add Windows Hello for Business credential"))
| EVAL uid = COALESCE(azure.signinlogs.properties.user_id, azure.auditlogs.properties.initiated_by.user.id),
       upn = TO_LOWER(COALESCE(azure.signinlogs.properties.user_principal_name, azure.auditlogs.properties.initiated_by.user.userPrincipalName)),
       stage = CASE(data_stream.dataset == "azure.signinlogs", "devicecode",
                    azure.auditlogs.operation_name == "Add Windows Hello for Business credential", "whfb",
                    "device"),
       broker = CASE(azure.signinlogs.properties.app_id == "29d9ed98-a469-4536-ade2-f981bc1d605e", 1, 0)   // Microsoft Authentication Broker
| WHERE uid IS NOT NULL
| STATS devicecode_at = MIN(CASE(stage == "devicecode", @timestamp, NULL)),
        device_at = MIN(CASE(stage == "device", @timestamp, NULL)),
        whfb_at = MAX(CASE(stage == "whfb", @timestamp, NULL)),
        broker_used = MAX(broker),
        upns = VALUES(upn),
        ips = VALUES(source.ip),
        asns = VALUES(source.as.organization.name),
        apps = VALUES(azure.signinlogs.properties.app_display_name),
        devices = VALUES(CASE(stage == "device", `azure.auditlogs.properties.target_resources.0.display_name`, NULL))
    BY uid
| WHERE devicecode_at IS NOT NULL AND whfb_at IS NOT NULL AND whfb_at >= devicecode_at
| EVAL severity = CASE(broker_used == 1 OR device_at IS NOT NULL, "critical", "high")
```
Join on the user's object ID rather than the UPN. It is the same in both logs and avoids case and format mismatches.

## Suppression
Suppress by `uid`, `severity` for 24h. Alerts missing a key field are not suppressed. Aggregating rule. Severity is in the key, so a device registration that arrives after the first alert raises a new critical alert.

## Known false positives / exclusions
- A user who legitimately signs in with device code (for example, the Azure CLI) and enrolls Hello on a new laptop in the same hour. This is rare. Exclude sanctioned device-code users (see I08) by object ID.
- Elastic also ships a first-seen rule, "Entra ID Windows Hello for Business Credential Registered", which fires on any Hello enrollment from a new user-and-ASN pair. Enable it as a low-severity companion for enrollments this rule does not chain.

## Triage
- Delete the attacker's devices first, then the Hello credential. The device holds the PRT, so revoking sessions before removing the device leaves access in place.
- Then revoke sessions and refresh tokens, reset the password, and re-enroll the user from a trusted device.
- Find the device-code phish: check the user's mail (E01, E05) and the proxy investigation query in I08 for the lure.
- In hybrid key-trust deployments the attacker's key is synced into on-premises AD by the directory sync account. I12 excludes that account, so this rule is the place it gets caught.

## Test
In a lab tenant, sign in a test user with the device code flow, then enroll Windows Hello for Business on a test device within the hour.
