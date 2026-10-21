---
id: S18
name: Device registered with roadtx default fingerprint or a non-standard registration client
category: entra-signin
status: todo
language: esql
index: logs-azure.auditlogs-*
mitre: [T1098.005]
data_source: Entra ID audit logs (device registration)
references: [https://github.com/dirkjanm/ROADtools]
suppression:
  fields: [azure.correlation_id]
  duration: 24h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
roadtx registers fake devices in Entra ID so it can obtain a Primary Refresh Token. Unless the operator overrides them, it uses a fixed OS build (`10.0.19041.928`) and a `DESKTOP-` plus random-characters device name. Real Windows devices report their actual, current build. Separately, genuine Entra joins come from the Windows registration client (`Dsreg...` or `DeviceRegistrationClient` user agents) or Android. A join made by any other client is scripted.

One registration writes several records with the same correlation ID: "Add device" (Core Directory, written by the service, no user), "Register device" (the user, the join type and the client user agent) and the owner records. The rule groups them per registration, so the device properties from one record and the user from another end up in the same alert.

The `finding` column says which:
- **`roadtx_default_fingerprint`** when the roadtx default build and name both match.
- **`nonstandard_registration_client`** when only the registration client is non-standard.

## Query
Run every 15 minutes with a 1-hour lookback.
```esql
FROM logs-azure.auditlogs-*
| WHERE azure.auditlogs.operation_name IN ("Add device", "Register device")
  AND event.outcome == "success"
| EVAL device = TO_LOWER(TO_STRING(`azure.auditlogs.properties.target_resources.0.display_name`)),
       // device properties sit at fixed positions; concatenate a few so a shifted position still matches
       props = CONCAT(
         COALESCE(TO_STRING(`azure.auditlogs.properties.target_resources.0.modified_properties.2.new_value`), ""), "|",
         COALESCE(TO_STRING(`azure.auditlogs.properties.target_resources.0.modified_properties.3.new_value`), ""), "|",
         COALESCE(TO_STRING(`azure.auditlogs.properties.target_resources.0.modified_properties.4.new_value`), ""), "|",
         COALESCE(TO_STRING(`azure.auditlogs.properties.target_resources.0.modified_properties.5.new_value`), "")),
       // additional details are key/value lists; keys and values are stored as separate sorted lists, so read them as strings
       detail_keys = TO_LOWER(COALESCE(MV_CONCAT(azure.auditlogs.properties.additional_details.key, "|"), "")),
       detail_values = TO_LOWER(COALESCE(MV_CONCAT(azure.auditlogs.properties.additional_details.value, "|"), "")),
       is_register = CASE(azure.auditlogs.operation_name == "Register device", 1, 0)
| EVAL fingerprint = CASE(props LIKE "*10.0.19041.928*" AND device LIKE "desktop-*", 1, 0),
       odd_client = CASE(is_register == 1
                         AND detail_values LIKE "*azure ad join*"
                         AND detail_keys LIKE "*user-agent*"
                         AND NOT (detail_values LIKE "*dsreg*" OR detail_values LIKE "*deviceregistrationclient*" OR detail_values LIKE "*dalvik*"), 1, 0)
| STATS default_fingerprint = MAX(fingerprint),
        nonstandard_client = MAX(odd_client),
        uid = VALUES(azure.auditlogs.properties.initiated_by.user.id),
        upn = VALUES(azure.auditlogs.properties.initiated_by.user.userPrincipalName),
        devices = VALUES(device),
        ips = VALUES(source.ip),
        details = VALUES(CASE(is_register == 1, detail_values, NULL)),
        first_seen = MIN(@timestamp)
    BY azure.correlation_id
| WHERE default_fingerprint == 1 OR nonstandard_client == 1
| EVAL finding = CASE(default_fingerprint == 1, "roadtx_default_fingerprint", "nonstandard_registration_client")
```
The user agent is read from `additional_details` rather than `properties.userAgent`, which is not in the integration's field list and exists only if your data has carried it.

## Suppression
Suppress by `azure.correlation_id` for 24h. Alerts missing a key field are not suppressed. Aggregating rule. One registration is one alert; overlapping lookbacks re-match it, and a different registration still alerts.

## Known false positives / exclusions
- An old, never-updated Windows 10 20H1 image with a default `DESKTOP-` name can match the fingerprint. Real devices of that age are rare on a managed estate; check the device's later sign-ins before closing.
- Device management or provisioning tools that join devices on behalf of users. Exclude their service accounts by object ID.

## Triage
- Check who registered it and from where (`ips`, `initiated_by.user.ipAddress`), and whether that user had a device-code or risky sign-in just before (C11, I07, X02, S16).
- If unexpected, delete the device first, then revoke the user's sessions and refresh tokens and reset credentials. Deleting the device invalidates its PRT.

## Test
Validate on historical data, or register a device with roadtx in a lab tenant.
