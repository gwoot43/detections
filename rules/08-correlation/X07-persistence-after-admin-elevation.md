---
id: X07
name: Directory persistence written shortly after the actor gained privileged access
category: correlation
status: todo
language: esql
index: logs-system.security*, logs-windows.forwarded*
mitre: [T1098, T1078.002]
data_source: Windows Security events on DCs, joining a Tier-0 group addition (I02) to a persistence write (I11-I14, WE03) on the account SID
suppression:
  fields: [actor_sid]
  duration: 2h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
Any one directory persistence write (I11-I14, WE03) is already high fidelity. Linking it to the same account having just been added to a Tier-0 group upgrades it to a near-certain attack chain and gives the analyst the whole story in one alert.

## Prerequisite
- DCs audit **Security Group Management** (4728, 4732, 4756) and **Directory Service Changes** (5136, with the SACLs I11-I14 need).
- The join is on the SID. A group-add event names the new member by DN (`MemberName`) and SID (`MemberSid`). A 5136 names the writer by sAMAccountName and SID (`SubjectUserSid`). Only the SID is in both.

## Query
```esql
FROM logs-system.security*, logs-windows.forwarded*
| WHERE @timestamp > NOW() - 2 hours AND event.code IN ("4728", "4732", "4756", "5136")
| EVAL grp = TO_LOWER(winlog.event_data.TargetUserName),
       attr = TO_LOWER(winlog.event_data.AttributeLDAPDisplayName),
       dn = TO_LOWER(winlog.event_data.ObjectDN),
       op = TO_LOWER(winlog.event_data.OperationType)
// elevation: an account added to a Tier-0 group (add your named Tier-0 groups)
| EVAL elevated = event.code IN ("4728", "4732", "4756")
         AND (grp IN ("domain admins", "enterprise admins", "schema admins", "administrators", "account operators",
                      "backup operators", "server operators", "dnsadmins", "group policy creator owners",
                      "enterprise key admins", "key admins")
              OR grp LIKE "*tier0*" OR grp LIKE "*tier-0*"),
// persistence: a value added to a shadow-credential, SPN or RBCD attribute, or any change to AdminSDHolder
       persisted = event.code == "5136" AND op IN ("value added", "%%14674")
         AND (attr IN ("msds-keycredentiallink", "serviceprincipalname", "msds-allowedtoactonbehalfofotheridentity")
              OR dn LIKE "cn=adminsdholder,cn=system,*")
| WHERE elevated OR persisted
| EVAL actor_sid = CASE(elevated, winlog.event_data.MemberSid, winlog.event_data.SubjectUserSid),
       elev_ts = CASE(elevated, @timestamp, NULL),
       persist_ts = CASE(persisted, @timestamp, NULL),
       elev_group = CASE(elevated, grp, NULL),
       added_by = CASE(elevated, TO_LOWER(winlog.event_data.SubjectUserName), NULL),
       actor_name = CASE(persisted, TO_LOWER(winlog.event_data.SubjectUserName), NULL),
       persist_attr = CASE(persisted, COALESCE(attr, "adminsdholder"), NULL),
       persist_dn = CASE(persisted, dn, NULL)
| WHERE actor_sid IS NOT NULL
| STATS first_elevation = MIN(elev_ts), last_persistence = MAX(persist_ts),
        actor = VALUES(actor_name), groups = VALUES(elev_group), added_by = VALUES(added_by),
        attributes = VALUES(persist_attr), objects = VALUES(persist_dn)
    BY actor_sid
| WHERE first_elevation IS NOT NULL AND last_persistence IS NOT NULL AND last_persistence >= first_elevation
| EVAL minutes_elevation_to_persistence = DATE_DIFF("minute", first_elevation, last_persistence)
| KEEP actor_sid, actor, first_elevation, last_persistence, minutes_elevation_to_persistence, groups, added_by, attributes, objects
```
Run every 15 minutes. The 2-hour lookback is the correlation window: the persistence write must come after the group addition.

Notes:
- `OperationType` is "Value Added" after the System and Windows integrations translate it (`%%14674` raw). Deletions are cleanup and don't count.
- A "logon to a domain controller" branch was considered and left out. Every 5136 is written by a DC for an account that just authenticated to it, so that branch would pair with every directory write.

## Suppression
Suppress by `actor_sid` for 2h, the length of the lookback. Alerts missing a key field are not suppressed. Correlation rule; suppression stops overlapping lookbacks from re-alerting on the same chain. A new write by the same account after that raises a new alert.

## Known false positives / exclusions
- An AD engineer legitimately elevating and then doing directory work. Rare, and worth a look each time given what's at stake. Exclude named break-glass procedures during a ticketed window only.
- `administrators` also matches a local Administrators group change on a member server (4732). It only pairs if the same SID then writes one of these attributes in AD, which is rare.
- A group nested into a Tier-0 group has the group's SID as the member, so a user inheriting rights that way is not paired.

## Triage
- This is an active privilege-escalation-to-persistence chain. Reverse the persistence (per the underlying I11-I14 or WE03 rule), disable the actor, and begin AD compromise assessment.

## Test
In a lab, add a test account to a Tier-0 group, then have it write an SPN to a user within the hour.
