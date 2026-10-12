---
id: I07
name: Entra impossible travel, risky sign-in, or session token replay
category: identity
status: todo
severity: high
language: esql
index: logs-azure.signinlogs-*
mitre: [T1078.004, T1550.001, T1621]
data_source: Entra ID sign-in logs (Identity Protection risk fields)
suppression:
  fields: [usr, source.ip]
  duration: 24h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
Microsoft's own risk engine gives a strong post-phishing signal. The rule keeps high-risk sign-ins and the risk detections that point at token replay or a hostile source (anomalous token, token issuer anomaly, malicious IP, impossible travel, password spray). Medium risk and `unfamiliarFeatures` alone are left out: they fire on every new device or travel and are too noisy to page on. This is the cloud side of the X01 correlation. Session reuse across countries or networks without a risk flag (no Identity Protection licence needed) is S08.

## Query
```esql
FROM logs-azure.signinlogs-* METADATA _id, _index, _version
| WHERE event.dataset == "azure.signinlogs"
| EVAL risk = TO_LOWER(TO_STRING(azure.signinlogs.properties.risk_level_during_signin)),
       risk_state = TO_LOWER(TO_STRING(azure.signinlogs.properties.risk_state)),
       detail = TO_LOWER(MV_CONCAT(TO_STRING(azure.signinlogs.properties.risk_event_types_v2), ",")),   // multi-valued list
       outcome = TO_STRING(azure.signinlogs.properties.status.error_code),
       usr = TO_LOWER(user.name)
| WHERE outcome == "0"
  AND (risk == "high"
       OR detail LIKE "*anomaloustoken*" OR detail LIKE "*maliciousipaddress*"
       OR detail LIKE "*impossibletravel*" OR detail LIKE "*tokenissueranomaly*" OR detail LIKE "*passwordspray*")
| KEEP @timestamp, usr, source.ip, source.geo.country_iso_code, source.as.organization.name,
       azure.signinlogs.properties.app_display_name, azure.signinlogs.properties.authentication_requirement, risk, detail, _id, _version, _index
```

## Suppression
Suppress by `usr`, `source.ip` for 24h. Alerts missing a key field are not suppressed. Token refreshes repeat the same risky sign-in. A new IP still alerts.

## Known false positives / exclusions
- VPN exits and mobile roaming create false impossible-travel. Exclude your corporate VPN egress ranges and known travel corridors.
- `authentication_requirement == "singleFactorAuthentication"` on a resource that should require MFA is itself worth flagging (Conditional Access gap).

## Triage
- Revoke sessions, require password reset and MFA re-registration. Check for device-code sign-ins (C11), session reuse across networks (S08) and consent grants (C05) from the same user.

## Test
Validate on historical data; simulate with a VPN exit in another country against a lab account.
