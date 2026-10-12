---
id: S02
name: Successful legacy authentication, ROPC flow, or known spray-tool user agent
category: entra-signin
status: todo
severity: high
language: esql
index: logs-azure.signinlogs-*
mitre: [T1078.004, T1110.003, T1556.006]
data_source: Entra ID sign-in logs
suppression:
  fields: [user.name, client]
  duration: 24h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
Legacy protocols (IMAP, POP, SMTP AUTH, ActiveSync basic, EWS basic) and the ROPC grant cannot do MFA. If your Conditional Access blocks legacy auth, any success is a policy gap being exploited. The `BAV2ROPC` user agent is what Exchange Online shows when it converts a basic-auth logon to ROPC, and it is the fingerprint of the common spray tooling; `fasthttp` is the client behind the 2025 high-speed Microsoft 365 brute-force campaigns. Generic HTTP libraries (`python-requests`, `curl`, `axios`, `Go-http-client`) were dropped: MSAL-based developer tools and internal scripts use them every day, so they flag automation, not compromise.

## Query
```esql
FROM logs-azure.signinlogs-* METADATA _id, _index, _version
| WHERE azure.signinlogs.category IN ("SignInLogs", "NonInteractiveUserSignInLogs")
  AND TO_STRING(azure.signinlogs.properties.status.error_code) == "0"
| EVAL client = TO_LOWER(TO_STRING(azure.signinlogs.properties.client_app_used)),
       proto  = TO_LOWER(TO_STRING(azure.signinlogs.properties.authentication_protocol)),
       ua     = TO_LOWER(COALESCE(user_agent.original, ""))
| WHERE client IN ("authenticated smtp", "exchange activesync", "imap4", "pop3", "other clients", "exchange web services",
                   "outlook anywhere (rpc over http)", "autodiscover", "offline address book")
   OR proto == "ropc"
   OR ua LIKE "bav2ropc*" OR ua LIKE "fasthttp*"
| KEEP @timestamp, user.name, client, proto, ua, source.ip, source.geo.country_iso_code, source.as.organization.name, azure.signinlogs.properties.app_display_name, _id, _version, _index
```

## Suppression
Suppress by `user.name`, `client` for 24h. Alerts missing a key field are not suppressed. Mail clients poll every few minutes. This suppression is essential.

## Known false positives / exclusions
- Legitimate SMTP AUTH relay accounts (scanners, apps sending mail). Inventory them, exclude by UPN, and move them to OAuth or a relay connector over time.
- Internal automation using ROPC against a test tenant. Exclude by app ID.
- iOS and macOS native mail using ActiveSync with modern authentication can still be labelled "Exchange ActiveSync". If those dominate, require `proto == "ropc"` or the `BAV2ROPC` user agent for that client value.

## Triage
- A legacy-protocol success for a human user means their password is known to an attacker and MFA never ran. Reset, revoke sessions, and close the CA gap that allowed the protocol.

## Test
Attempt an IMAP basic-auth login against a lab account with legacy auth permitted for that account only.
