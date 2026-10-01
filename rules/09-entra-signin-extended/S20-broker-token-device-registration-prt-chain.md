---
id: S20
name: Broker refresh token redeemed for device registration, device registered, then PRT used from an unmanaged device
category: entra-signin
status: todo
severity: critical
language: esql
index: logs-azure.signinlogs-*, logs-azure.auditlogs-*
mitre: [T1098.005, T1550.001, T1528]
data_source: Entra ID sign-in logs + audit logs, joined on user object ID
references: [https://dirkjanm.io/phishing-for-microsoft-entra-primary-refresh-tokens/, https://github.com/dirkjanm/ROADtools]
suppression:
  fields: [uid]
  duration: 24h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
This is the core roadtx path from a stolen refresh token to a Primary Refresh Token:
1. A refresh token is silently redeemed (a non-interactive sign-in) through the Microsoft Authentication Broker client for the device registration service.
2. A device is registered for the same user.
3. That user's PRT is then used from a device that is not managed, by something other than Windows sign-in.

A real Windows join requests the registration token interactively during setup, and its PRT is used by the Windows sign-in component. The silent refresh-token redemption in step 1 and the non-Windows PRT use in step 3 together point to tooling. Unlike S19, the rule does not rely on user agents an operator can change.

## Query
Run every 15 minutes with a 1-hour lookback.
```esql
FROM logs-azure.signinlogs-*, logs-azure.auditlogs-*
| WHERE (data_stream.dataset == "azure.signinlogs"
         AND TO_STRING(azure.signinlogs.properties.status.error_code) == "0"
         AND azure.signinlogs.properties.user_type == "Member"
         AND (
              // step 1: broker redeems a refresh token for the device registration service
              (azure.signinlogs.category == "NonInteractiveUserSignInLogs"
               AND azure.signinlogs.properties.app_id == "29d9ed98-a469-4536-ade2-f981bc1d605e"
               AND azure.signinlogs.properties.resource_display_name == "Device Registration Service"
               AND azure.signinlogs.properties.incoming_token_type == "refreshToken")
              OR
              // step 3: PRT used from an unmanaged device, not by Windows sign-in
              (azure.signinlogs.properties.incoming_token_type == "primaryRefreshToken"
               AND azure.signinlogs.properties.resource_display_name != "Device Registration Service"
               AND COALESCE(TO_STRING(azure.signinlogs.properties.device_detail.is_managed), "false") != "true"
               AND azure.signinlogs.properties.app_display_name != "Windows Sign In"
               AND COALESCE(TO_STRING(user_agent.original), "") != "Windows-AzureAD-Authentication-Provider/1.0")))
     OR (data_stream.dataset == "azure.auditlogs"
         // step 2: device registered
         AND azure.auditlogs.operation_name IN ("Register device", "Add device")
         AND event.outcome IN ("success", "Success"))
| EVAL uid = TO_STRING(COALESCE(azure.signinlogs.properties.user_id, azure.auditlogs.properties.initiated_by.user.id)),
       upn = TO_LOWER(TO_STRING(COALESCE(azure.signinlogs.properties.user_principal_name, azure.auditlogs.properties.initiated_by.user.userPrincipalName))),
       stage = CASE(data_stream.dataset == "azure.auditlogs", "register",
                    azure.signinlogs.properties.incoming_token_type == "primaryRefreshToken", "prt_use",
                    "drs_token")
| WHERE uid IS NOT NULL
| STATS drs_at = MIN(CASE(stage == "drs_token", @timestamp, NULL)),
        register_at = MIN(CASE(stage == "register", @timestamp, NULL)),
        prt_at = MAX(CASE(stage == "prt_use", @timestamp, NULL)),
        prt_resources = VALUES(CASE(stage == "prt_use", azure.signinlogs.properties.resource_display_name, NULL)),
        devices = VALUES(CASE(stage == "register", `azure.auditlogs.properties.target_resources.0.display_name`, NULL)),
        upns = VALUES(upn),
        ips = VALUES(source.ip),
        asns = VALUES(source.as.organization.name),
        uas = VALUES(user_agent.original)
    BY uid
| WHERE drs_at IS NOT NULL AND register_at IS NOT NULL AND prt_at IS NOT NULL
  AND drs_at <= register_at AND register_at <= prt_at
```
To tighten it further, also require `azure.signinlogs.properties.token_protection_status_details.sign_in_session_status == "unbound"` on step 1, if your integration version has that field. Elastic's prebuilt rule "Entra ID AiTM Phishing-Kit Chain Detected" is an EQL sequence of the same chain with a 3-minute window.

## Suppression
Suppress by `uid` for 24h. Alerts missing a key field are not suppressed. Aggregating rule. The same chain re-matches on every run while the lookback overlaps.

## Known false positives / exclusions
- A device registered moments before Intune enrollment completes can briefly use its PRT while unmanaged. A real join does not redeem a refresh token silently for registration (step 1), so this is unusual. If it appears, exclude the provisioning flow by the registration user agent, not by user.

## Triage
- Treat as account takeover with device persistence. Delete the registered device first, which kills the PRT. Then revoke sessions and refresh tokens and reset credentials.
- Find where the original refresh token came from, usually a device-code phish (I08) or an adversary-in-the-middle kit. Check what the PRT reached (`prt_resources`).

## Test
In a lab tenant, use roadtx to redeem a refresh token for the device registration service, register a device and request a PRT.
