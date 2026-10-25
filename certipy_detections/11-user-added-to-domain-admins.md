---
id: ACCOUNTS-01
name: Member added to Domain Admins, matched by the group's SID (-512), not its name
language: esql
index: logs-yourorg-microsoft-windows*
mitre: [T1098.007, T1078.002]
data_source: Windows Security 4728 on the domain controllers
suppression:
  fields: [winevt.event_data.member_sid]
  duration: 1h
  missing_fields: do_not_suppress
---
Anyone added to Domain Admins. The group is matched by its SID, not its name: every domain's Domain Admins SID is the domain SID followed by `-512`, so a renamed or localised group, or a lookalike called "Domain Admins", makes no difference. Adds to Domain Admins are rare enough that every one is worth a look.

Domain Admins is a global group, so the add is event 4728. `target_sid` is the group, `member_sid` and `member_name` the account added, `subject_user_name` who added it.

Run every 5 minutes over the last 10.
```esql
FROM logs-yourorg-microsoft-windows* METADATA _id, _index, _version
// Filter for members added to Domain Admins: a domain SID (S-1-5-21-...) ending in -512
| WHERE event.code == "4728" AND winevt.event_data.target_sid LIKE "S-1-5-21-*-512"
// Display results
| KEEP @timestamp, host.name, winevt.event_data.target_user_name, winevt.event_data.target_sid,
       winevt.event_data.member_name, winevt.event_data.member_sid, winevt.event_data.subject_user_name,
       winevt.event_data.subject_user_sid, _id, _index, _version
```
No LogScale version: the DCs' logs are in Elastic. Suppress by the member's SID for an hour.

The `-512` is preceded by the dash, so it only matches a RID of exactly 512, never a group whose RID ends in 512 (`-1512`).

## The other Tier-0 groups
The same approach works for every built-in privileged group. Enterprise Admins and Schema Admins are universal groups (4756) and the built-in ones are local (4732), so widen the event codes with them:
```esql
FROM logs-yourorg-microsoft-windows* METADATA _id, _index, _version
// Filter for members added to a privileged group, by SID
| WHERE event.code IN ("4728", "4732", "4756")
  AND (winevt.event_data.target_sid LIKE "S-1-5-21-*-512"      // Domain Admins
       OR winevt.event_data.target_sid LIKE "S-1-5-21-*-518"   // Schema Admins
       OR winevt.event_data.target_sid LIKE "S-1-5-21-*-519"   // Enterprise Admins
       OR winevt.event_data.target_sid LIKE "S-1-5-21-*-520"   // Group Policy Creator Owners
       OR winevt.event_data.target_sid LIKE "S-1-5-21-*-526"   // Key Admins
       OR winevt.event_data.target_sid LIKE "S-1-5-21-*-527"   // Enterprise Key Admins
       OR winevt.event_data.target_sid IN ("S-1-5-32-544",     // Administrators
                                           "S-1-5-32-548",     // Account Operators
                                           "S-1-5-32-549",     // Server Operators
                                           "S-1-5-32-550",     // Print Operators
                                           "S-1-5-32-551"))    // Backup Operators
| KEEP @timestamp, host.name, event.code, winevt.event_data.target_user_name, winevt.event_data.target_sid,
       winevt.event_data.member_name, winevt.event_data.member_sid, winevt.event_data.subject_user_name, _id, _index, _version
```
DnsAdmins has no fixed SID; add yours to the `IN` list if you want it.

## Before turning it on
- Check the field names against a 4728 in Discover: `target_sid`, `member_sid`, `member_name`, `subject_user_name` are guesses at your pipeline's snake_case.
- If a privileged-access tool grants Domain Admins just in time, every grant will alert. Don't exclude the tool's account on its own: it's exactly the account an attacker wants. If the volume needs it, exclude the tool's account only together with the admin accounts it's expected to grant.

## What it misses
- Rights that make an account an admin without the group: ACL changes on the domain root or AdminSDHolder, or DCSync rights (AD02 covers those).
- A member added through a nested group (an account added to a group that is itself in Domain Admins): the 4728 names the nested group, not Domain Admins.
- A DC whose Security log isn't collected.

## When it fires
Ask whoever is in `subject_user_name` whether the change was planned. If not: remove the member, then treat both the member and the account that added it as compromised. Look at the adder's logons on the DCs just before (4624, which address it came from) and at what the new admin did since (4624 and 4769 by `member_sid`).
