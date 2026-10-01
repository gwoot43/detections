---
id: S17
name: Device-less Windows Hello or passkey sign-in followed by device registration (borrowed Hello key)
category: entra-signin
status: todo
severity: high
language: esql
index: logs-azure.signinlogs-*, logs-azure.auditlogs-*
mitre: [T1550, T1098.005]
data_source: Entra ID sign-in logs + audit logs, joined on user object ID
references: [https://dirkjanm.io/borrowing-windows-hello-keys/]
suppression:
  fields: [uid]
  duration: 24h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
In August 2026 Dirk-jan Mollema showed that malware already running in a signed-in Windows session can ask Windows to sign an Entra ID challenge with the user's Windows Hello key. It needs no PIN, no biometric prompt, and no key extraction, even on TPM-backed devices. The challenge is not bound to a session, so the signature can be used from another host. The attacker then registers a device they control to get a long-lived Primary Refresh Token.

The trace in the logs is a Windows Hello or passkey sign-in with no device ID, followed shortly by a device registration for the same user. A normal Hello sign-in comes from the enrolled device and carries its device ID, so a device-less one is unusual. Mollema's own guidance is to monitor exactly these two signals.

## Query
Run every 10 minutes with a 30-minute lookback.
```esql
FROM logs-azure.signinlogs-*, logs-azure.auditlogs-*
| WHERE (data_stream.dataset == "azure.signinlogs"
         AND TO_STRING(azure.signinlogs.properties.status.error_code) == "0"
         AND azure.signinlogs.properties.user_type == "Member"
         AND azure.signinlogs.properties.cross_tenant_access_type == "none"
         AND COALESCE(TO_STRING(azure.signinlogs.properties.device_detail.device_id), "") == "")
     OR (data_stream.dataset == "azure.auditlogs"
         AND event.outcome IN ("success", "Success")
         AND azure.auditlogs.operation_name IN ("Register device", "Add registered owner to device", "Add device"))
| EVAL uid = COALESCE(azure.signinlogs.properties.user_id, azure.auditlogs.properties.initiated_by.user.id),
       upn = TO_LOWER(COALESCE(azure.signinlogs.properties.user_principal_name, azure.auditlogs.properties.initiated_by.user.userPrincipalName)),
       stage = CASE(data_stream.dataset == "azure.signinlogs", "signin", "register"),
       auth_method = FIELD_EXTRACT(azure.signinlogs.properties.authentication_details, "authentication_method")
// keep registrations, and sign-ins whose only method was Windows Hello or a FIDO2 / passkey credential
| WHERE uid IS NOT NULL
  AND (stage == "register"
       OR (MV_COUNT(auth_method) == 1
           AND (auth_method == "Windows Hello for Business" OR TO_LOWER(auth_method) LIKE "fido2*" OR TO_LOWER(auth_method) LIKE "*passkey*")))
| STATS first_signin = MIN(CASE(stage == "signin", @timestamp, NULL)),
        last_register = MAX(CASE(stage == "register", @timestamp, NULL)),
        methods = VALUES(auth_method),
        upns = VALUES(upn),
        signin_ips = VALUES(CASE(stage == "signin", source.ip, NULL)),
        apps = VALUES(azure.signinlogs.properties.app_display_name),
        user_agents = VALUES(user_agent.original),
        devices = VALUES(CASE(stage == "register", `azure.auditlogs.properties.target_resources.0.display_name`, NULL))
    BY uid
| WHERE first_signin IS NOT NULL AND last_register IS NOT NULL AND last_register >= first_signin
| EVAL signin_to_register_min = DATE_DIFF("minute", first_signin, last_register)
```
The sign-in must come before the registration and both fall inside the 30-minute lookback. Elastic's prebuilt rule, "Entra ID Deviceless Windows Hello Sign-in Followed by Device Registration", tightens this to 15 minutes but uses newer ES|QL commands (`INLINE STATS`, `LIMIT ... BY`). Use theirs if your cluster supports them; this version runs on more releases.

`FIELD_EXTRACT` reads the method out of the sign-in's authentication details, the same way Elastic's rule does. If your version lacks it, copy `authentication_details[].authentication_method` into a keyword field in the ingest pipeline and match on that.

## Suppression
Suppress by `uid` for 24h. Alerts missing a key field are not suppressed. Aggregating rule. One attack produces several sign-ins and registration events across overlapping runs.

## Known false positives / exclusions
- Security keys or passkeys used from a browser on an unmanaged machine, followed by that user registering a new device. This is uncommon within half an hour. Review it rather than excluding it.
- A user setting up a new phone with a passkey and joining it. If your rollout causes noise, exclude the onboarding window, not the user.

## Triage
- Find the device that holds the user's Hello key, the one they normally sign in from. Treat it as compromised, since the malware runs there. Isolate it in Falcon and hunt for the process that made the signing request.
- Delete the newly registered device first, then revoke sessions and refresh tokens. Removing the device breaks the PRT.
- Check for further methods added after the registration (I10, S16) and for persistence in mail (E06) and apps (C05).

## Test
Validate on historical data. Reproducing the technique needs code execution in a lab user's session and Mollema's published tooling.
