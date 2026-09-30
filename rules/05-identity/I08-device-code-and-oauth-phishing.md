---
id: I08
name: Device code authentication or suspicious OAuth flow
category: identity
status: todo
severity: high
language: esql
index: logs-azure.signinlogs-*
mitre: [T1528, T1621, T1078.004]
data_source: Entra ID sign-in logs (including non-interactive)
suppression:
  fields: [user.name, source.ip]
  duration: 24h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
Device code phishing was the breakout identity attack of 2025 to 2026 (STORM-2372, then the EvilTokens / ConsentFix phishing-as-a-service kits). The device code grant is rarely used legitimately outside a few IoT and CLI scenarios, so a device-code sign-in to Office, Teams or Azure Management, especially from a hosting ASN or a country the user is not in, is a strong signal.

## Query
```esql
FROM logs-azure.signinlogs-* METADATA _id, _index, _version
| WHERE event.dataset == "azure.signinlogs"
| EVAL proto = TO_LOWER(TO_STRING(azure.signinlogs.properties.authentication_protocol)),
       grant = TO_LOWER(TO_STRING(azure.signinlogs.properties.incoming_token_type)),
       flow = TO_LOWER(TO_STRING(azure.signinlogs.properties.original_transfer_method)),
       app = TO_LOWER(TO_STRING(azure.signinlogs.properties.app_display_name)),
       outcome = TO_STRING(azure.signinlogs.properties.status.error_code)
| WHERE (proto == "devicecode" OR grant LIKE "*devicecode*" OR flow LIKE "*devicecode*")
| WHERE outcome == "0"
| KEEP @timestamp, user.name, app, source.ip, source.geo.country_iso_code, source.as.organization.name, proto, grant
```
If the device-code fields are not populated in your integration version, detect the pattern instead: an authorization request (error 50199 / 70016 device-code pending) followed by a success for the same user from a different IP within 15 minutes.

## Suppression
Suppress by `user.name`, `source.ip` for 24h. Alerts missing a key field are not suppressed. A phished token keeps refreshing from the same IP. A new IP still alerts.

## Known false positives / exclusions
- Legitimate device-code use: Azure CLI on servers, conference-room devices, PowerShell with `-UseDeviceAuthentication`. Inventory these users and hosts and exclude them.

## Triage
- If the sign-in IP does not match the user's location or is a hosting provider, treat as token theft. Revoke sessions and refresh tokens, reset password. Password reset alone does not evict a stolen token, so revocation is mandatory.

## Test
Run `az login --use-device-code` from a lab machine and confirm it appears.

## Investigation: find the devicelogin visit in proxy/web logs
When a device-code sign-in fires, pivot to the user's web traffic around the sign-in time to see the lure. The victim visits `microsoft.com/devicelogin` (a legitimate Microsoft URL) and enters the attacker's code, so the visit itself is not malicious; the value is the timing and the referrer, which points back to the phishing page.

```esql
FROM logs-proxy-*
| WHERE user.name == "<user>"
  AND @timestamp >= "<signin - 15m>" AND @timestamp <= "<signin + 2m>"
| WHERE (url.domain IN ("microsoft.com", "www.microsoft.com", "login.microsoftonline.com",
                        "aka.ms", "login.microsoft.com", "microsoft.com")
         OR url.domain LIKE "*.microsoftonline.com")
  AND (url.path LIKE "*devicelogin*" OR url.path LIKE "*deviceauth*" OR url.path LIKE "*/device*")
| KEEP @timestamp, url.domain, url.path, http.request.referrer
| SORT @timestamp ASC
```

Syntax notes:
- `url.domain IN (...)` is exact-match and is the right choice for a known host list; it is faster than `LIKE`. Use `LIKE` only for wildcards.
- `IN ("microsoft.com")` does **not** match `login.microsoft.com`. To catch subdomains, add a `LIKE "*.microsoftonline.com"` branch (shown) or list each host explicitly.
- `microsoft.com/devicelogin` is the path `devicelogin` on domain `microsoft.com`, so the `url.path LIKE "*devicelogin*"` filter already covers it; you do not need a separate domain entry for the path.
- The `http.request.referrer` is the payoff: if it is an external or newly registered domain rather than an Outlook/Teams deep link, that referrer is the phishing page. Block it and sweep other users for visits to it.
- Replace `logs-proxy-*` with your Zscaler index (`logs-zscaler.zia_web-*`); the field names align with N07-N09.
