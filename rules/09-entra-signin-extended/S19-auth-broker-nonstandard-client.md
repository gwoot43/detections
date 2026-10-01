---
id: S19
name: Microsoft Authentication Broker sign-in from a non-standard client
category: entra-signin
status: todo
severity: high
language: esql
index: logs-azure.signinlogs-*
mitre: [T1550.001, T1528, T1078.004]
data_source: Entra ID sign-in logs (interactive and non-interactive)
references: [https://github.com/dirkjanm/ROADtools]
suppression:
  fields: [uid, ua]
  duration: 24h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
The Microsoft Authentication Broker client is what Windows, Android and iOS use for device registration and PRT flows, so it is allowed to request tokens for the device registration service. roadtx impersonates it for exactly that reason. Legitimate broker sign-ins come from the Windows authentication provider, a browser, Android or iOS, and each has a recognisable user agent. A broker sign-in from a script or HTTP library is tooling.

Severity is computed per alert:
- **high** when the token is for the device registration service, the step before registering a fake device.
- **medium** for any other resource.

## Query
```esql
FROM logs-azure.signinlogs-* METADATA _id, _index, _version
| WHERE data_stream.dataset == "azure.signinlogs"
  AND TO_STRING(azure.signinlogs.properties.status.error_code) == "0"
  AND azure.signinlogs.properties.app_id == "29d9ed98-a469-4536-ade2-f981bc1d605e"   // Microsoft Authentication Broker
| EVAL uid = TO_STRING(azure.signinlogs.properties.user_id),
       upn = TO_LOWER(TO_STRING(azure.signinlogs.properties.user_principal_name)),
       ua = COALESCE(TO_STRING(user_agent.original), ""),
       resource = TO_STRING(azure.signinlogs.properties.resource_display_name)
| WHERE ua != ""
  AND NOT (ua LIKE "Mozilla*" OR ua LIKE "Dalvik*" OR ua LIKE "*CFNetwork*"
           OR ua LIKE "Windows-AzureAD-Authentication-Provider*" OR ua LIKE "Java*ThinkPad*")
| EVAL severity = CASE(resource == "Device Registration Service", "high", "medium")
| KEEP @timestamp, uid, upn, ua, resource, severity, source.ip, source.as.organization.name, source.geo.country_iso_code,
       azure.signinlogs.category, azure.signinlogs.properties.incoming_token_type, azure.signinlogs.properties.authentication_protocol
```
An operator can set a browser or Windows user agent in roadtx, which this rule then misses. S20 does not depend on the user agent and covers that case.

## Suppression
Suppress by `uid`, `ua` for 24h. Alerts missing a key field are not suppressed. A tool session makes repeated token requests; a different user agent still alerts.

## Known false positives / exclusions
- Uncommon but legitimate broker hosts, such as some Linux or enterprise device agents with their own user agent. Review the first hits, then exclude exact user agent strings, never patterns.

## Triage
- Look at the source IP and ASN and at what the token was for. A device registration service token from a hosting provider is the start of a fake-device chain: check S18 and S20 for the same user.
- Revoke the user's sessions and refresh tokens. The refresh token used here was most likely phished (I08).

## Test
Request a broker token with roadtx from a lab machine without overriding the user agent.
