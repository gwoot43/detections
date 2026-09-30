---
id: C11
name: Device code auth outcomes, and Conditional Access block followed by success (bypass)
category: cloud
status: todo
severity: high
language: esql
index: logs-azure.signinlogs-*
mitre: [T1621, T1528, T1078.004, T1556.009]
data_source: Entra ID sign-in logs (interactive and non-interactive)
---
## Why this is high fidelity
Two related detections in one file.

Rule A scores device code sign-in outcomes per user: a Conditional Access block (error 53003) followed by a success is the strongest signal, because it means the principal was stopped, changed something, and still got a token. A plain success on the device code flow is worth validating, and a block on its own means a user was phished but contained.

Rule B generalises the bypass pattern to every flow. Error 53003 is the generic "blocked by Conditional Access" result, not a device-code code. It fires for unmanaged devices, blocked locations, legacy auth and unmet MFA grants, so on its own it is high volume and low value. The signal is the transition: the same principal is blocked by CA and then succeeds within a short window. That one rule covers device code, adversary-in-the-middle, unmanaged-device pivots and legacy-auth fallback without you writing a rule per flow.

## Rule A: device code outcomes (your query, refined)
```esql
FROM logs-azure.signinlogs-*
| WHERE event.dataset == "azure.signinlogs"
  AND TO_LOWER(TO_STRING(azure.signinlogs.properties.authentication_protocol)) == "devicecode"
  // exclude known legit device-code apps/users here, e.g. Azure CLI on servers, conference-room devices
  // | WHERE NOT (TO_LOWER(azure.signinlogs.properties.user_principal_name) IN ("svc-azcli@yourtenant.onmicrosoft.com"))
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
        first      = MIN(@timestamp),
        last       = MAX(@timestamp)
    BY azure.signinlogs.properties.user_principal_name
| EVAL severity = CASE(
      ca_blocks > 0 AND successes > 0 AND first_block <= first_success, "high",   // blocked, then got through: likely bypass
      ca_blocks > 0 AND successes > 0,                                  "medium", // both seen but success came first: validate ordering
      successes > 0,                                                    "medium", // successful device code, validate
      ca_blocks > 0,                                                    "low",    // phished but contained: reset/notify user
      "info")
| WHERE severity != "info"
```
The `first_block <= first_success` guard is the one change from your version: without it a normal successful device-code sign-in earlier in the window plus an unrelated later block would score as a bypass. Ordering the two timestamps removes that.

## Rule B: Conditional Access block then success, any flow
```esql
FROM logs-azure.signinlogs-*
| WHERE event.dataset == "azure.signinlogs"
| EVAL ec = TO_STRING(azure.signinlogs.properties.status.error_code),
       is_success  = CASE(ec == "0", 1, 0),
       is_ca_block = CASE(ec == "53003", 1, 0)
| WHERE is_success == 1 OR is_ca_block == 1
| STATS blocks       = SUM(is_ca_block),
        successes     = SUM(is_success),
        first_block   = MIN(CASE(is_ca_block == 1, @timestamp, NULL)),
        first_success = MIN(CASE(is_success == 1, @timestamp, NULL)),
        blocked_apps  = VALUES(CASE(is_ca_block == 1, azure.signinlogs.properties.app_display_name, NULL)),
        ips           = COUNT_DISTINCT(source.ip),
        asns          = VALUES(source.as.organization.name)
    BY azure.signinlogs.properties.user_principal_name, BUCKET(@timestamp, 1 hour)
| WHERE blocks > 0 AND successes > 0 AND first_block <= first_success
```
Run this hourly with a 1-hour bucket. It is deliberately flow-agnostic. Tighten it by requiring the success and the block to share an app, or by requiring the success IP to differ from the blocked IP, once you see the baseline volume.

## Known false positives / exclusions
- A user who legitimately fails a CA grant (forgot the compliant device, off VPN), fixes it, and signs in. Common. Reduce it by requiring the success from a different IP or ASN than the block, or by scoping Rule B to sensitive apps (Azure Management, Exchange Online) first.
- Sanctioned device-code users for Rule A: Azure CLI service accounts, conference-room and IoT devices. Exclude by UPN.
- Continuous Access Evaluation can produce block-then-allow transitions during token refresh. Exclude CAE-driven events if your logs flag them.

## Triage
- Rule A high or Rule B hit: confirm the success IP, ASN and country against the user's norm (I07). A hosting-provider or foreign IP after a block is token theft or an AiTM proxy. Revoke sessions and refresh tokens, reset the password, and check for a newly registered MFA method (I10) and app consent (C05). Password reset alone does not evict a stolen refresh token.
- Rule A low (block only): notify the user, confirm they were the target of a device-code lure, no further access granted.

## Test
Rule A: run `az login --use-device-code` from a machine that a CA policy blocks, then from a compliant one, as a lab account. Rule B: trigger any CA block for a lab user, then have them satisfy the grant and sign in within the hour.
