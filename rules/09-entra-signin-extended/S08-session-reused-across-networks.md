---
id: S08
name: One sign-in session used from multiple countries or networks
category: entra-signin
status: todo
severity: high
language: esql
index: logs-azure.signinlogs-*
mitre: [T1550.004, T1539, T1078.004]
data_source: Entra ID interactive and non-interactive sign-in logs (session ID)
---
## Why this is high fidelity
A stolen session cookie or refresh token produces a signature the password never can: the same Entra session identifier issuing tokens from two different countries or autonomous systems. Legitimate sessions move with one device on one network at a time (mobile roaming aside). This catches token theft even when the risk engine stays quiet.

## Query
```esql
FROM logs-azure.signinlogs-*
| WHERE TO_STRING(azure.signinlogs.properties.status.error_code) == "0"
  AND azure.signinlogs.category IN ("SignInLogs", "NonInteractiveUserSignInLogs")
| EVAL sid = TO_STRING(azure.signinlogs.properties.session_id), usr = TO_LOWER(user.name)
| WHERE sid IS NOT NULL AND sid != ""
| STATS countries = COUNT_DISTINCT(source.geo.country_iso_code), where_from = VALUES(source.geo.country_iso_code),
        asns = COUNT_DISTINCT(source.as.organization.name), asn_list = VALUES(source.as.organization.name),
        ips = VALUES(source.ip), apps = VALUES(azure.signinlogs.properties.app_display_name), n = COUNT(*)
    BY usr, sid, BUCKET(@timestamp, 24 hours)
| WHERE countries >= 2 OR asns >= 3
```
Confirm the session identifier field name in your integration version (`session_id` under `properties`, or `correlation_id` as a weaker fallback). Without it, fall back to the two-country rule in I07.

## Known false positives / exclusions
- Mobile devices switching between Wi-Fi and cellular. The ASN threshold is set to 3 for that reason; country is the stronger signal. Exclude known carrier ASN pairs if they dominate.

## Triage
- Same response as S07: revoke sessions and tokens, then hunt the persistence that usually follows.

## Test
Validate on historical data, or replay a lab session cookie from a second network.
