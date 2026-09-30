---
id: I02
name: Membership change to a Tier-0 / privileged group
category: identity
status: todo
severity: critical
language: esql
index: logs-windows.security-*
mitre: [T1098, T1078.002]
data_source: Windows Security events 4728/4732/4756 (and removals 4729/4733/4757)
suppression: none
---
## Why this is high fidelity
Additions to Domain Admins, Enterprise Admins, Schema Admins, Administrators, and the other Tier-0 groups are rare and always planned. DnsAdmins and Backup Operators are included because they are privilege-escalation paths to Domain Admin.

## Query
```esql
FROM logs-windows.security-* METADATA _id, _index, _version
| WHERE event.code IN ("4728", "4732", "4756", "4729", "4733", "4757")
| EVAL grp = TO_LOWER(winlog.event_data.TargetUserName),
       actor = TO_LOWER(COALESCE(winlog.event_data.SubjectUserName, user.name)),
       member = TO_LOWER(COALESCE(winlog.event_data.MemberName, "")),
       added = CASE(event.code IN ("4728", "4732", "4756"), "added", "removed")
| WHERE grp IN ("domain admins", "enterprise admins", "schema admins", "administrators", "account operators",
                "backup operators", "server operators", "print operators", "dnsadmins", "group policy creator owners",
                "enterprise key admins", "key admins", "cert publishers", "domain controllers", "read-only domain controllers",
                "protected users")
   OR grp LIKE "*tier0*" OR grp LIKE "*tier-0*" OR grp LIKE "*admin*"       // add your named privileged groups
| KEEP @timestamp, host.name, added, grp, member, actor, winlog.event_data.MemberSid
```
Curate the final group list against your own Tier-0 definitions and remove the broad `*admin*` wildcard once the explicit list is complete, or it will match delegated app-admin groups.

## Suppression
None. Every privileged group change is a distinct action. Suppressing would hide a second account added.

## Known false positives / exclusions
- Planned privileged access management (PAM) group shuffles. Suppress by (actor, group) during a ticketed window, do not permanently allowlist.

## Triage
- Confirm the change against change control. An add to Domain Admins with no ticket is an incident. Check the actor's recent logons (I06) and whether they were themselves recently added (chained escalation).

## Test
Add and remove a test account to a lab Tier-0 group.
