---
id: S03
name: Privileged account signed in with a single factor to an admin surface
category: entra-signin
status: todo
severity: high
language: esql
index: logs-azure.signinlogs-*
mitre: [T1078.004, T1556.006]
data_source: Entra ID sign-in logs
---
## Why this is high fidelity
Every admin sign-in to the Azure portal, Entra admin centre, Graph, Exchange admin or Azure management should require MFA. A privileged account that satisfies the sign-in with a single factor means a Conditional Access gap or an exclusion an attacker is riding. The population is your admin accounts, which you know by name or by role membership.

## Query
```esql
FROM logs-azure.signinlogs-* METADATA _id, _index, _version
| WHERE TO_STRING(azure.signinlogs.properties.status.error_code) == "0"
| EVAL req = TO_LOWER(TO_STRING(azure.signinlogs.properties.authentication_requirement)),
       usr = TO_LOWER(user.name),
       res = TO_LOWER(TO_STRING(azure.signinlogs.properties.resource_display_name)),
       app = TO_LOWER(TO_STRING(azure.signinlogs.properties.app_display_name))
| WHERE req == "singlefactorauthentication"
  AND (usr LIKE "adm-*" OR usr LIKE "*-admin@*" OR usr LIKE "*.adm@*")     // your admin naming convention, or swap for a lookup of role members
  AND (res LIKE "*azure service management*" OR res LIKE "*microsoft graph*" OR res LIKE "*azure portal*"
       OR app LIKE "*azure portal*" OR app LIKE "*entra*" OR app LIKE "*exchange*admin*" OR app LIKE "*security*center*" OR app LIKE "*intune*" OR app LIKE "*azure cli*" OR app LIKE "*azure powershell*")
| KEEP @timestamp, usr, app, res, req, source.ip, source.geo.country_iso_code, azure.signinlogs.properties.conditional_access_status, azure.signinlogs.properties.device_detail.trust_type
```
Better than name patterns: export Global/Privileged Role Administrator, Security Administrator and Exchange Administrator members to a lookup index nightly and join on it.

## Known false positives / exclusions
- Sign-ins from a compliant, hybrid-joined PAW where CA grants access on device compliance instead of MFA. Decide whether that is acceptable policy; if it is, exclude `trust_type == "Hybrid Azure AD joined" AND is_compliant == true`.

## Triage
- Confirm which CA policy applied (the sign-in record lists applied policies). Close the gap. If the sign-in is from an unfamiliar IP, treat as compromise.

## Test
Sign in to the Azure portal with a test admin account that is temporarily excluded from the MFA policy.
