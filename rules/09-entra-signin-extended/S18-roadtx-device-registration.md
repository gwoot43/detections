---
id: S18
name: Device registered with roadtx default fingerprint or a non-standard registration client
category: entra-signin
status: todo
severity: high
language: esql
index: logs-azure.auditlogs-*
mitre: [T1098.005]
data_source: Entra ID audit logs (device registration)
references: [https://github.com/dirkjanm/ROADtools]
suppression:
  fields: [uid, device]
  duration: 24h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
roadtx registers fake devices in Entra ID so it can obtain a Primary Refresh Token. Unless the operator overrides them, it uses a fixed OS build (`10.0.19041.928`) and a `DESKTOP-` plus random-characters device name. Real Windows devices report their actual, current build. Separately, genuine Entra joins come from the Windows registration client (`Dsreg...` or `DeviceRegistrationClient` user agents) or Android. A join made by any other client is scripted.

Severity is computed per alert:
- **high** when the roadtx default build and name both match.
- **medium** when only the registration client is non-standard.

## Query
```esql
FROM logs-azure.auditlogs-* METADATA _id, _index, _version
| WHERE data_stream.dataset == "azure.auditlogs"
  AND azure.auditlogs.operation_name IN ("Add device", "Register device")
  AND event.outcome IN ("success", "Success")
| EVAL uid = TO_STRING(azure.auditlogs.properties.initiated_by.user.id),
       upn = TO_LOWER(TO_STRING(azure.auditlogs.properties.initiated_by.user.userPrincipalName)),
       device = TO_LOWER(TO_STRING(`azure.auditlogs.properties.target_resources.0.display_name`)),
       // device properties sit at fixed positions; concatenate a few so a shifted position still matches
       props = CONCAT(
         COALESCE(TO_STRING(`azure.auditlogs.properties.target_resources.0.modified_properties.2.new_value`), ""), "|",
         COALESCE(TO_STRING(`azure.auditlogs.properties.target_resources.0.modified_properties.3.new_value`), ""), "|",
         COALESCE(TO_STRING(`azure.auditlogs.properties.target_resources.0.modified_properties.4.new_value`), ""), "|",
         COALESCE(TO_STRING(`azure.auditlogs.properties.target_resources.0.modified_properties.5.new_value`), "")),
       ua = TO_LOWER(COALESCE(TO_STRING(azure.auditlogs.properties.userAgent), "")),
       join_type = TO_LOWER(COALESCE(MV_CONCAT(TO_STRING(azure.auditlogs.properties.additional_details.value), ","), ""))
| EVAL default_fingerprint = props LIKE "*10.0.19041.928*" AND device LIKE "desktop-*",
       nonstandard_client = azure.auditlogs.operation_name == "Register device"
                            AND join_type LIKE "*azure ad join*"
                            AND ua != ""
                            AND NOT (ua LIKE "dsreg*" OR ua LIKE "deviceregistrationclient*" OR ua LIKE "dalvik*")
| WHERE default_fingerprint OR nonstandard_client
| EVAL severity = CASE(default_fingerprint, "high", "medium")
| KEEP @timestamp, uid, upn, device, azure.auditlogs.operation_name, ua, join_type, props, default_fingerprint, nonstandard_client, severity
```

## Suppression
Suppress by `uid`, `device` for 24h. Alerts missing a key field are not suppressed. One registration writes both "Add device" and "Register device"; a different device still alerts.

## Known false positives / exclusions
- An old, never-updated Windows 10 20H1 image with a default `DESKTOP-` name can match the fingerprint. Real devices of that age are rare on a managed estate; check the device's later sign-ins before closing.
- Device management or provisioning tools that join devices on behalf of users. Exclude their service accounts by object ID.

## Triage
- Check who registered it and from where (`initiated_by.user.ipAddress`), and whether that user had a device-code or risky sign-in just before (I08, I07, S16).
- If unexpected, delete the device first, then revoke the user's sessions and refresh tokens and reset credentials. Deleting the device invalidates its PRT.

## Test
Validate on historical data, or register a device with roadtx in a lab tenant.
