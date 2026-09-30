---
id: X07
name: Directory persistence written shortly after the actor gained privileged access
category: correlation
status: todo
severity: critical
language: esql
index: logs-windows.security-*
mitre: [T1098, T1078.002]
data_source: Windows Security events, joining a Tier-0 elevation (I02/I06) to a persistence write (I11-I14, WE03)
suppression:
  fields: [actor]
  duration: 1h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
Any one directory persistence write (I11-I14, WE03) is already high fidelity. Linking it to the same actor having just gained privileged access, by being added to a Tier-0 group or logging on to a domain controller in the previous hour, upgrades it to a near-certain attack chain and gives the analyst the whole story in one alert.

## Query (pattern)
```esql
FROM logs-windows.security-* METADATA _id, _index, _version
| WHERE @timestamp > NOW() - 1 hour AND event.code == "5136"
| EVAL actor = TO_LOWER(COALESCE(winlog.event_data.SubjectUserName, "")),
       attr = TO_LOWER(TO_STRING(winlog.event_data.AttributeLDAPDisplayName)),
       dn = TO_LOWER(TO_STRING(winlog.event_data.ObjectDN))
| WHERE attr IN ("msds-keycredentiallink", "serviceprincipalname", "msds-allowedtoactonbehalfofotheridentity")
     OR dn LIKE "cn=adminsdholder,cn=system,*"
| LOOKUP JOIN privileged_elevations_last_2h ON actor
| WHERE elevated_at IS NOT NULL AND @timestamp >= elevated_at
| KEEP @timestamp, actor, attr, dn, elevation_type, elevated_at
```
Build `privileged_elevations_last_2h` from I02 (added to a Tier-0 group) and I06 (privileged logon to a DC), keyed on the actor (fields `actor`, `elevated_at`, `elevation_type`). Implement as an indicator-match rule if LOOKUP JOIN is unavailable.

## Suppression
Suppress by `actor` for 1h. Alerts missing a key field are not suppressed. Correlation rule; suppression stops overlapping lookbacks from re-alerting on the same chain.

## Known false positives / exclusions
- An AD engineer legitimately elevating and then doing directory work. Rare, and worth a look each time given the severity. Exclude named break-glass procedures during a ticketed window only.

## Triage
- This is an active privilege-escalation-to-persistence chain. Reverse the persistence (per the underlying I11-I14 or WE03 rule), disable the actor, and begin AD compromise assessment.

## Test
In a lab, add a test account to a Tier-0 group, then have it write an SPN to a user within the hour.
