---
id: WE05
name: Sensitive privilege assigned or special logon to a non-admin account
category: windows-events
status: todo
severity: medium
language: esql
index: logs-system.security*, logs-windows.forwarded*
mitre: [T1134, T1078.002, T1068]
data_source: Windows Security event 4672 (special privileges assigned to new logon)
suppression:
  fields: [acct, host_key]
  duration: 24h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
Event 4672 fires when an account logs on with admin-equivalent privileges (SeDebugPrivilege, SeTcbPrivilege, SeBackupPrivilege and similar). It is normal for admins and services; it is a strong signal when it happens for an account that should never hold those rights. Scope to accounts outside your admin and service population and this becomes a clean privilege-abuse indicator.

SeImpersonatePrivilege and SeAssignPrimaryTokenPrivilege are left out: every service identity holds them (IIS application pools, SQL Server and other virtual service accounts), so they say nothing about abuse. The built-in service domains (NT AUTHORITY, NT SERVICE, IIS APPPOOL, Window Manager, Font Driver Host) are excluded for the same reason.

## Query
```esql
FROM logs-system.security*, logs-windows.forwarded* METADATA _id, _index, _version
| WHERE event.code == "4672"
| EVAL acct = TO_LOWER(COALESCE(winlog.event_data.SubjectUserName, "")),
       acct_domain = TO_LOWER(COALESCE(winlog.event_data.SubjectDomainName, "")),
       privs = TO_LOWER(MV_CONCAT(winlog.event_data.PrivilegeList, " ")),     // multi-valued: one value per privilege
       host_key = TO_LOWER(MV_FIRST(SPLIT(winlog.computer_name, ".")))
| WHERE acct != "" AND NOT (acct LIKE "*$")
  AND acct_domain NOT IN ("nt authority", "nt service", "iis apppool", "window manager", "font driver host")
  AND NOT (acct LIKE "adm-*" OR acct LIKE "*-admin" OR acct LIKE "svc-*")   // your admin / service naming
  AND (privs LIKE "*sedebugprivilege*" OR privs LIKE "*setcbprivilege*" OR privs LIKE "*sebackupprivilege*"
       OR privs LIKE "*serestoreprivilege*" OR privs LIKE "*setakeownershipprivilege*" OR privs LIKE "*seloaddriverprivilege*"
       OR privs LIKE "*secreatetokenprivilege*")
| KEEP @timestamp, host_key, winlog.computer_name, acct, acct_domain, privs
```
The most reliable version replaces the name patterns with an inline list of the accounts expected to hold these privileges, and alerts on everyone else.

## Suppression
Suppress by `acct`, `host_key` for 24h. Alerts missing a key field are not suppressed. Event 4672 fires on every logon of the account. This suppression is essential.

## Known false positives / exclusions
- Backup agents, monitoring and EDR service accounts hold these privileges legitimately. Exclude them by account name.
- Members of Backup Operators get SeBackupPrivilege and SeRestorePrivilege by design. Exclude the named backup operators, and alert on new members through I02.

## Triage
- A standard user account logging on with SeDebugPrivilege is either a token-manipulation attack or a misconfigured right assignment. Investigate the host and how the account obtained the privilege.

## Test
Grant SeDebugPrivilege to a lab standard account and log on.
