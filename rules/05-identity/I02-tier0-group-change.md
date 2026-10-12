---
id: I02
name: Membership change to a Tier-0 / privileged group
category: identity
status: todo
severity: critical
language: esql
index: logs-system.security*, logs-windows.forwarded*
mitre: [T1098, T1078.002]
data_source: Windows Security events 4728/4732/4756 (member added) and 4729 (member removed from Protected Users)
suppression: none
---
## Why this is high fidelity
Additions to Domain Admins, Enterprise Admins, Schema Admins, Administrators, and the other Tier-0 groups are rare and always planned. DnsAdmins and Backup Operators are included because they are privilege-escalation paths to Domain Admin. Removals are left out because they reduce privilege, except removal from Protected Users, which strips that account's credential protections.

The built-in groups (Administrators, Account Operators and the other operators) also exist as local groups on every member server and workstation, where local admin changes are routine. They count only when the event comes from a domain controller.

## Query
```esql
FROM logs-system.security*, logs-windows.forwarded* METADATA _id, _index, _version
| WHERE event.code IN ("4728", "4732", "4756", "4729")
| EVAL grp = TO_LOWER(winlog.event_data.TargetUserName),
       grp_domain = TO_LOWER(COALESCE(winlog.event_data.TargetDomainName, "")),
       actor = TO_LOWER(COALESCE(winlog.event_data.SubjectUserName, user.name)),
       member = TO_LOWER(COALESCE(winlog.event_data.MemberName, "")),
       host_key = TO_LOWER(MV_FIRST(SPLIT(winlog.computer_name, "."))),
       change = CASE(event.code == "4729", "removed", "added")
| EVAL on_dc = host_key LIKE "dc*" OR host_key LIKE "*-dc*"           // your DC naming
| WHERE (change == "added"
         AND (grp IN ("domain admins", "enterprise admins", "schema admins", "dnsadmins", "group policy creator owners",
                      "enterprise key admins", "key admins", "cert publishers", "domain controllers",
                      "read-only domain controllers")
              OR grp LIKE "*tier0*" OR grp LIKE "*tier-0*"              // your named Tier-0 groups
              OR (grp_domain == "builtin" AND on_dc
                  AND grp IN ("administrators", "account operators", "backup operators", "server operators", "print operators"))))
   OR (change == "removed" AND grp == "protected users")
| KEEP @timestamp, winlog.computer_name, change, grp, member, actor, winlog.event_data.MemberSid, _id, _version, _index
```
Add your own Tier-0 groups by exact name. Set the DC naming in `on_dc`, or the built-in groups never match.

## Suppression
None. Every privileged group change is a distinct action. Suppressing would hide a second account added.

## Known false positives / exclusions
- Planned privileged access management (PAM) or just-in-time grants. Exclude the PAM service account as `actor` only if every grant it makes is ticketed; never exclude by group.
- Adding a computer to Cert Publishers or Domain Controllers when a CA or DC is built. Confirm against the build ticket.

## Triage
- Confirm the change against change control. An add to Domain Admins with no ticket is an incident. Check the actor's recent logons (I06) and whether they were themselves recently added (chained escalation).

## Test
Add and remove a test account to a lab Tier-0 group.
