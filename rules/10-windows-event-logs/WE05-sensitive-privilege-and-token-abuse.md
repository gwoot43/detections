---
id: WE05
name: Sensitive privilege assigned or special logon to a non-admin account
category: windows-events
status: todo
severity: medium
language: esql
index: logs-windows.security-*
mitre: [T1134, T1078.002, T1068]
data_source: Windows Security events 4672 (special privileges) and 4673/4674 (privileged service)
suppression:
  fields: [acct, host.name]
  duration: 24h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
Event 4672 fires when an account logs on with admin-equivalent privileges (SeDebugPrivilege, SeTcbPrivilege, SeBackupPrivilege and similar). It is normal for admins and services; it is a strong signal when it happens for an account that should never hold those rights. Scope to accounts outside your admin and service population and this becomes a clean privilege-abuse indicator.

## Query
```esql
FROM logs-windows.security-* METADATA _id, _index, _version
| WHERE event.code == "4672"
| EVAL acct = TO_LOWER(COALESCE(winlog.event_data.SubjectUserName, "")),
       privs = TO_LOWER(TO_STRING(winlog.event_data.PrivilegeList))
| WHERE NOT (acct LIKE "*$") AND acct != "system" AND acct != "" AND acct != "local service" AND acct != "network service"
  AND NOT (acct LIKE "adm-*" OR acct LIKE "*-admin" OR acct LIKE "svc-*")   // your admin / service naming, or a lookup of privileged accounts
  AND (privs LIKE "*sedebugprivilege*" OR privs LIKE "*setcbprivilege*" OR privs LIKE "*sebackupprivilege*"
       OR privs LIKE "*serestoreprivilege*" OR privs LIKE "*setakeownershipprivilege*" OR privs LIKE "*seloaddriverprivilege*"
       OR privs LIKE "*secreatetokenprivilege*" OR privs LIKE "*seimpersonateprivilege*" OR privs LIKE "*seassignprimarytokenprivilege*")
| KEEP @timestamp, host.name, acct, privs
```
The most reliable version replaces the name patterns with a lookup of accounts that are expected to hold these privileges, and alerts on everyone else.

## Suppression
Suppress by `acct`, `host.name` for 24h. Alerts missing a key field are not suppressed. Event 4672 fires on every logon of the account. This suppression is essential.

## Known false positives / exclusions
- Backup agents, monitoring and EDR service accounts hold these privileges legitimately. Exclude by service account, ideally via the lookup.

## Triage
- A standard user account logging on with SeDebugPrivilege is either a token-manipulation attack or a misconfigured right assignment. Investigate the host and how the account obtained the privilege.

## Test
Grant SeDebugPrivilege to a lab standard account and log on.
