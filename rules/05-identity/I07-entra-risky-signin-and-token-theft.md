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
---
## Why this is high fidelity
Microsoft's own risk engine, combined with a same-user two-country rule and a check for sign-ins that satisfied MFA without a fresh MFA event (token replay / AiTM), gives a strong post-phishing signal. This is the cloud side of the X01 correlation.

## Query
```esql
FROM logs-azure.signinlogs-* METADATA _id, _index, _version
| WHERE event.dataset == "azure.signinlogs"
| EVAL risk = TO_LOWER(TO_STRING(azure.signinlogs.properties.risk_level_during_signin)),
       risk_state = TO_LOWER(TO_STRING(azure.signinlogs.properties.risk_state)),
       detail = TO_LOWER(TO_STRING(azure.signinlogs.properties.risk_event_types_v2)),
       outcome = TO_STRING(azure.signinlogs.properties.status.error_code),
       usr = TO_LOWER(user.name)
| WHERE outcome == "0"
  AND (risk IN ("high", "medium")
       OR detail LIKE "*unfamiliarfeatures*" OR detail LIKE "*anomaloustoken*" OR detail LIKE "*maliciousipaddress*"
       OR detail LIKE "*impossibletravel*" OR detail LIKE "*tokenissueranomaly*" OR detail LIKE "*aadanomaly*" OR detail LIKE "*passwordspray*")
| KEEP @timestamp, usr, source.ip, source.geo.country_iso_code, source.as.organization.name,
       azure.signinlogs.properties.app_display_name, azure.signinlogs.properties.authentication_requirement, risk, detail
```
Companion same-user two-country query (works without Identity Protection licensing):
```esql
FROM logs-azure.signinlogs-*
| WHERE event.dataset == "azure.signinlogs" AND TO_STRING(azure.signinlogs.properties.status.error_code) == "0"
| STATS countries = COUNT_DISTINCT(source.geo.country_iso_code), where = VALUES(source.geo.country_iso_code), ips = VALUES(source.ip)
    BY TO_LOWER(user.name), BUCKET(@timestamp, 2 hours)
| WHERE countries >= 2
```

## Known false positives / exclusions
- VPN exits and mobile roaming create false impossible-travel. Exclude your corporate VPN egress ranges and known travel corridors.
- `authentication_requirement == "singleFactorAuthentication"` on a resource that should require MFA is itself worth flagging (Conditional Access gap).

## Triage
- Revoke sessions, require password reset and MFA re-registration. Check for device-code sign-ins (I08) and consent grants (C05) from the same user.

## Test
Validate on historical data; simulate with a VPN exit in another country against a lab account.
