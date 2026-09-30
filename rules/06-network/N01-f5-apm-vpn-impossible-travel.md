---
id: N01
name: F5 APM VPN successful logon showing impossible travel or two countries
category: network
status: todo
severity: high
language: esql
index: logs-f5.apm-*
mitre: [T1133, T1078]
data_source: F5 APM access logs (syslog; custom ingest pipeline)
---
## Why this is high fidelity
APM is your VPN, so a successful session is remote access to the corporate network. One user succeeding from two countries inside a few hours, or from a country the workforce is not in, is stolen credentials or a stolen session. Because APM is VPN-only, the legitimate population is your own staff and their known locations.

## Query
```esql
FROM logs-f5.apm-*
| WHERE TO_LOWER(f5.apm.result) IN ("allow", "successful", "success") OR event.outcome == "success"
| EVAL usr = TO_LOWER(COALESCE(user.name, f5.apm.username))
| STATS countries = COUNT_DISTINCT(source.geo.country_iso_code),
        where_from = VALUES(source.geo.country_iso_code),
        ips = VALUES(source.ip),
        asns = VALUES(source.as.organization.name),
        sessions = COUNT(*)
    BY usr, BUCKET(@timestamp, 4 hours)
| WHERE countries >= 2
```
Field names depend on how you parse the APM syslog. Map the username, result and client IP in the ingest pipeline to `user.name`, `event.outcome` and `source.ip`, then GeoIP enriches `source.geo`.

## Known false positives / exclusions
- Users behind carrier-grade NAT or mobile networks that geolocate inconsistently. Exclude specific ASNs after review.
- A user on VPN and also authenticating from a mobile app. Scope to APM sessions only.

## Triage
- Confirm with the user. If unexpected, terminate the APM session, disable the account, and check what the session reached on the internal network.

## Test
Validate on historical APM logs, or connect to the VPN through an exit node in another country with a lab account.
