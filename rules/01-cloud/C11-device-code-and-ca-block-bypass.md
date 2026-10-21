---
id: C11
name: Device code auth outcomes, and Conditional Access block followed by success (bypass)
category: cloud
status: todo
language: esql
index: logs-azure.signinlogs-*
mitre: [T1621, T1528, T1078.004, T1556.009]
data_source: Entra ID sign-in logs (interactive and non-interactive)
suppression:
  fields: [azure.signinlogs.properties.user_principal_name, outcome]
  duration: 24h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
Two related detections in one file.

Rule A scores device code sign-in outcomes per user. Device code phishing was the breakout identity attack of 2025 to 2026 (STORM-2372, then the EvilTokens / ConsentFix phishing-as-a-service kits), and the device code grant is rarely used legitimately outside a few IoT and CLI scenarios, so every successful device-code sign-in to Office, Teams or Azure Management is worth validating, especially from a hosting ASN or a country the user is not in. a Conditional Access block (error 53003) followed by a success is the strongest signal, because it means the principal was stopped, changed something, and still got a token. A plain success on the device code flow is worth validating, and a block on its own means a user was phished but contained.

Rule B generalises the bypass pattern to every flow. Error 53003 is the generic "blocked by Conditional Access" result, not a device-code code. It fires for unmanaged devices, blocked locations, legacy auth and unmet device grants, so on its own it is high volume and low value. The signal is the transition, made precise: the same user, from the same IP, is blocked by CA for an app and then gets a token for that same app from a device that is not registered. A user who fixes a blocked sign-in does so from a managed device; an attacker who gets around the policy (spoofed device platform, different client, policy gap) does it from their own unregistered machine.

## Rule A: device code outcomes
```esql
FROM logs-azure.signinlogs-*
| WHERE event.dataset == "azure.signinlogs"
  AND azure.signinlogs.category == "SignInLogs"
  AND TO_LOWER(TO_STRING(azure.signinlogs.properties.authentication_protocol)) == "devicecode"
  // exclude known legit device-code users here, e.g. Azure CLI on servers, conference-room devices
  // AND TO_LOWER(azure.signinlogs.properties.user_principal_name) NOT IN ("svc-azcli@yourtenant.onmicrosoft.com")
| EVAL ec        = TO_STRING(azure.signinlogs.properties.status.error_code),
       is_success = CASE(ec == "0", 1, 0),
       is_ca_block = CASE(ec == "53003", 1, 0)
| STATS successes  = SUM(is_success),
        ca_blocks  = SUM(is_ca_block),
        first_success = MIN(CASE(is_success == 1, @timestamp, NULL)),
        first_block   = MIN(CASE(is_ca_block == 1, @timestamp, NULL)),
        ips        = COUNT_DISTINCT(source.ip),
        apps       = COUNT_DISTINCT(azure.signinlogs.properties.app_id),
        countries  = COUNT_DISTINCT(source.geo.country_iso_code),
        where_from = VALUES(source.geo.country_iso_code),
        asns       = VALUES(source.as.organization.name),
        first_seen      = MIN(@timestamp),
        last_seen       = MAX(@timestamp)
    BY azure.signinlogs.properties.user_principal_name
| EVAL outcome = CASE(
      ca_blocks > 0 AND successes > 0 AND first_block <= first_success, "blocked, then got through", // likely bypass
      ca_blocks > 0 AND successes > 0,                                  "success, then blocked",     // validate ordering
      successes > 0,                                                    "success",                   // validate
      ca_blocks > 0,                                                    "blocked",                   // phished but contained: notify user
      NULL)
| WHERE outcome IS NOT NULL
```
The device code step is an interactive sign-in, so only `SignInLogs` is read. The `first_block <= first_success` guard stops a normal successful device-code sign-in earlier in the window plus an unrelated later block from scoring as a bypass.

Device code is read from `authentication_protocol`. `incoming_token_type` is not checked: its values (`none`, `primaryRefreshToken`, `refreshToken`, `saml11`, `saml20`, `remoteDesktopToken`) never name the device code grant, so a `*devicecode*` match on it adds nothing. Entra's `originalTransferMethod` (`deviceCodeFlow`) is not used either: the Elastic Azure integration does not define `azure.signinlogs.properties.original_transfer_method` (it is in neither the field list nor the ingest pipeline), and an ES|QL query fails if it names a field that is not mapped. If `authentication_protocol` is not populated in your integration version, detect the pattern instead: an authorization request (error 50199 / 70016 device-code pending) followed by a success for the same user from a different IP within 15 minutes.

## Rule B: Conditional Access block then unregistered success for the same app and IP
Run every 15 minutes with a 1-hour lookback.
```esql
FROM logs-azure.signinlogs-*
| WHERE azure.signinlogs.category IN ("SignInLogs", "NonInteractiveUserSignInLogs")
| EVAL ec = TO_STRING(azure.signinlogs.properties.status.error_code),
       trust = COALESCE(TO_STRING(azure.signinlogs.properties.device_detail.trust_type), ""),
       is_ca_block = CASE(ec == "53003", 1, 0),
       is_unreg_success = CASE(ec == "0" AND trust == "", 1, 0)
| WHERE is_ca_block == 1 OR is_unreg_success == 1
| STATS blocks        = SUM(is_ca_block),
        successes     = SUM(is_unreg_success),
        first_block   = MIN(CASE(is_ca_block == 1, @timestamp, NULL)),
        last_success  = MAX(CASE(is_unreg_success == 1, @timestamp, NULL)),
        asns          = VALUES(source.as.organization.name),
        countries     = VALUES(source.geo.country_iso_code),
        user_agents   = VALUES(user_agent.original)
    BY azure.signinlogs.properties.user_principal_name, source.ip, azure.signinlogs.properties.app_display_name
| WHERE blocks > 0 AND successes > 0 AND last_success >= first_block
| EVAL outcome = "blocked, then got through"
```
The rule window replaces a fixed one-hour `BUCKET`, so a block at 10:55 and a success at 11:05 are still paired. `outcome` is set here so both rules share one suppression key.

## Suppression
Suppress by `azure.signinlogs.properties.user_principal_name`, `outcome` for 24h. Alerts missing a key field are not suppressed. Aggregating rule. `outcome` is in the key so a user who was only blocked and then gets through raises a new alert.

## Known false positives / exclusions
- Rule B: a browser that sends no device information (Chrome without the Microsoft extension, a private window) is blocked by a compliant-device policy, and the user then completes the same sign-in in a browser that does send it. That success carries a trust type and does not count. If a specific app keeps producing hits, check its policy scope before excluding it.
- Sanctioned device-code users for Rule A: Azure CLI service accounts and servers, conference-room and IoT devices, PowerShell with `-UseDeviceAuthentication`. Inventory them and exclude by UPN.
- Continuous Access Evaluation can produce block-then-allow transitions during token refresh. Exclude CAE-driven events if your logs flag them.

## Triage
- Rule A `blocked, then got through`, or a Rule B hit: confirm the success IP, ASN and country against the user's norm (I07). Compare the user agents: a platform that changes between block and success is a spoofed device platform. A hosting-provider or foreign IP after a block is token theft or an AiTM proxy. Revoke sessions and refresh tokens, reset the password, and check for a newly registered MFA method (I10) and app consent (C05). Password reset alone does not evict a stolen refresh token.
- Rule A `blocked` (block only): notify the user, confirm they were the target of a device-code lure, no further access granted.
- Rule A with a device-code success (`success`, `success, then blocked` or `blocked, then got through`): if the sign-in IP does not match the user's location or is a hosting provider, treat it as token theft and revoke, as above. Find the lure with the investigation query below.

### Investigation query: find the devicelogin visit in proxy/web logs
When Rule A fires on a successful device-code sign-in, pivot to the user's web traffic around the sign-in time to see the lure. The victim visits `microsoft.com/devicelogin` (a legitimate Microsoft URL) and enters the attacker's code, so the visit itself is not malicious; the value is the timing and the referrer, which points back to the phishing page.

```esql
FROM logs-zscaler_zia.web-*
| WHERE user.email == "<upn>"
  AND @timestamp >= "<signin - 15m>" AND @timestamp <= "<signin + 2m>"
| WHERE (url.domain IN ("microsoft.com", "www.microsoft.com", "login.microsoftonline.com",
                        "aka.ms", "login.microsoft.com")
         OR url.domain LIKE "*.microsoftonline.com")
  AND (url.path LIKE "*devicelogin*" OR url.path LIKE "*deviceauth*" OR url.path LIKE "*/device*")
| KEEP @timestamp, user.email, url.domain, url.path, http.request.referrer, zscaler_zia.web.ssl_decrypted
| SORT @timestamp ASC
```

Syntax notes:
- `url.domain IN (...)` is exact-match and is the right choice for a known host list; it is faster than `LIKE`. Use `LIKE` only for wildcards.
- `IN ("microsoft.com")` does **not** match `login.microsoft.com`. To catch subdomains, add a `LIKE "*.microsoftonline.com"` branch (shown) or list each host explicitly.
- `microsoft.com/devicelogin` is the path `devicelogin` on domain `microsoft.com`, so the `url.path LIKE "*devicelogin*"` filter already covers it; you do not need a separate domain entry for the path.
- The `http.request.referrer` is the payoff: if it is an external or newly registered domain rather than an Outlook/Teams deep link, that referrer is the phishing page. Block it and sweep other users for visits to it.
- The index is the Elastic Zscaler ZIA web data stream, `logs-zscaler_zia.web-*`.
- Match the user on `user.email`, not `user.name`. In this integration `user.email` is the full Zscaler login, while `user.name` is only the part before the @. Entra `user.name` is the full UPN. Paste the UPN from the sign-in alert as `<upn>`, and confirm that your Zscaler login is the UPN and not an alias.
- `url.path` is probably only filled in when Zscaler inspected the TLS session (unverified). If `zscaler_zia.web.ssl_decrypted` is "No" for Microsoft login traffic and the path is empty, drop the `url.path` filter and rely on the timing.
- Zscaler records `http.request.referrer` without the scheme, for example `contoso-docs.example/share`.

## Test
Rule A: run `az login --use-device-code` from a machine that a CA policy blocks, then from a compliant one, as a lab account. Rule B: in a lab tenant, trigger a CA block for a lab user on one app, then let the same user complete a sign-in to that app from an unregistered lab machine on the same network within the hour (for example, by temporarily excluding the lab user from the policy).
