---
id: S08
name: One sign-in session used from multiple countries or networks
category: entra-signin
status: todo
language: esql
index: logs-azure.signinlogs-*
mitre: [T1550.004, T1539, T1078.004]
data_source: Entra ID interactive and non-interactive sign-in logs (session ID)
suppression:
  fields: [usr, sid]
  duration: 24h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
A stolen session cookie or refresh token produces a signature the password never can: the same Entra session identifier issuing tokens from two different countries or autonomous systems. Legitimate sessions move with one device on one network at a time (mobile roaming aside). This catches token theft even when the risk engine stays quiet.

## Query
Run hourly with a 24-hour lookback.
```esql
FROM logs-azure.signinlogs-*
| WHERE TO_STRING(azure.signinlogs.properties.status.error_code) == "0"
  AND azure.signinlogs.category IN ("SignInLogs", "NonInteractiveUserSignInLogs")
  // Microsoft's own network: first-party services redeem tokens on the user's behalf from Azure
  AND (source.as.number IS NULL OR source.as.number != 8075)
| EVAL sid = TO_STRING(azure.signinlogs.properties.session_id), usr = TO_LOWER(user.name)
| WHERE sid IS NOT NULL AND sid != ""
| STATS countries = COUNT_DISTINCT(source.geo.country_iso_code), where_from = VALUES(source.geo.country_iso_code),
        asns = COUNT_DISTINCT(source.as.number), asn_list = VALUES(source.as.organization.name),
        ips = VALUES(source.ip), apps = VALUES(azure.signinlogs.properties.app_display_name), n = COUNT(*)
    BY usr, sid
| WHERE countries >= 2 OR asns >= 3
```
`session_id` is not in the integration's field list. It exists only once real sign-in data has carried `sessionId`, and the query fails with "Unknown column" until then. Check it in Discover before enabling. `correlation_id` is not a substitute: it identifies one sign-in flow, not the session. Without a session ID, fall back to the two-country rule in I07.

Sign-ins from Microsoft's ASN are excluded because Exchange, Teams and other services refresh tokens server-side from Azure, which puts a second "country" on almost every session. The rule window replaces a fixed daily `BUCKET`, so a session that crosses midnight is still one row.

## Suppression
Suppress by `usr`, `sid` for 24h. Alerts missing a key field are not suppressed. Aggregating rule. The 24-hour lookback re-evaluates the same session every hour.

## Known false positives / exclusions
- Mobile devices switching between Wi-Fi and cellular. The ASN threshold is set to 3 for that reason; country is the stronger signal. Exclude known carrier ASN pairs if they dominate.
- A user on a flight or crossing a border with a laptop that keeps its session. Check the timing between countries before escalating.
- An attacker on an Azure VM is hidden by the Microsoft ASN exclusion. S07 does not cover Azure either, because Windows 365 and Azure Virtual Desktop users share that ASN.

## Triage
- Same response as S07: revoke sessions and tokens, then hunt the persistence that usually follows.

## Test
Validate on historical data, or replay a lab session cookie from a second network.
