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
suppression:
  fields: [usr]
  duration: 24h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
APM is your VPN, so a successful session is remote access to the corporate network. One user succeeding from two countries inside a few hours, or from a country the workforce is not in, is stolen credentials or a stolen session. Because APM is VPN-only, the legitimate population is your own staff and their known locations.

## Prerequisite
The stock Elastic F5 BIG-IP integration (`f5_bigip`, data stream `logs-f5_bigip.log-*`) cannot feed this query as written:
- It parses APM only from F5 Telemetry Streaming JSON (`telemetryEventCategory: APM`). APM syslog lines such as "Access policy result: Network_Access" are not parsed. They fail the JSON step, so the document gets `event.kind: pipeline_error` and the raw line is kept only in `event.original`. There is no `message` field.
- APM events have no username field.
- The client IP and the policy result are on separate records. Request records carry the client IP (`source.ip`, with GeoIP in `source.geo` and `source.as`). Session records carry `f5_bigip.log.session.id`, `f5_bigip.log.access.profile` and the result in `f5_bigip.log.access.policy_result` (for example `Logon_Deny`).
- The integration never sets `event.outcome` on APM events.

This rule needs a custom ingest pipeline (`logs-f5_bigip.log@custom`, which can parse `event.original`) or a custom syslog integration. That parser has to put the session ID, user, client IP and policy result on each APM event. The index and field names in the query are the target names for that parser: `logs-f5.apm-*`, `f5.apm.result`, `f5.apm.username`/`user.name`, `event.outcome` and `source.ip`, with GeoIP filling `source.geo.*` and `source.as.*`. If you use the `@custom` pipeline, the data stays in `logs-f5_bigip.log-*`, so change the `FROM` line to match.

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

## Suppression
Suppress by `usr` for 24h. Alerts missing a key field are not suppressed. Aggregating rule. One trip produces the same finding all day.

## Known false positives / exclusions
- Users behind carrier-grade NAT or mobile networks that geolocate inconsistently. Exclude specific ASNs after review.
- A user on VPN and also authenticating from a mobile app. Scope to APM sessions only.

## Triage
- Confirm with the user. If unexpected, terminate the APM session, disable the account, and check what the session reached on the internal network.

## Test
Validate on historical APM logs, or connect to the VPN through an exit node in another country with a lab account.
