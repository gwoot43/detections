---
id: SWEEP-01
name: BloodHound / SharpHound collection sweep - one account reaching 50+ computers in an hour (Kerberos tickets or IPC$)
language: esql
index: logs-yourorg-microsoft-windows*
mitre: [T1087.002, T1069.002, T1018, T1049]
data_source: Windows Security 4769 (DCs) and 5140 (targets)
suppression:
  fields: [source.ip, user.name]
  duration: 6h
  missing_fields: do_not_suppress
---
SharpHound's session, local-admin and group collection connects to every computer it can reach. Each connection leaves:
- **a service ticket on the DC (4769)** for that computer's account (`name$`), when the collector runs on a domain-joined host;
- **an IPC$ connection on the target (5140)**, for the SMB/RPC calls (srvsvc, samr, lsarpc).

So one account reaching 50+ different computers in an hour is the sweep. The rule reads only the Windows events; which host and process sent the requests comes from Falcon afterwards, with the pivot query below, for the one address that alerted.

Run hourly over the last hour.
```esql
FROM logs-yourorg-microsoft-windows*
// Filter for tickets to computer accounts and IPC$ connections, by user accounts
| WHERE (event.code == "4769" AND winevt.event_data.status == "0x0"
         AND ENDS_WITH(winevt.event_data.service_name, "$")
         AND NOT ENDS_WITH(user.name, "$") AND NOT user.name LIKE "*$@*")
     OR (event.code == "5140" AND winevt.event_data.share_name == "\\\\*\\IPC$" AND NOT ENDS_WITH(user.name, "$"))
// The address (without the ::ffff: DCs put in front of IPv4), the account without @DOMAIN (4769 has it, 5140
// doesn't), and the computer reached each way
| EVAL ip = REPLACE(TO_STRING(source.ip), "^::ffff:", ""),
       account = TO_LOWER(MV_FIRST(SPLIT(user.name, "@"))),
       krb_target = CASE(event.code == "4769", TO_LOWER(winevt.event_data.service_name), null),
       ipc_target = CASE(event.code == "5140", TO_LOWER(host.name), null)
| WHERE ip IS NOT NULL AND NOT ip IN ("::1", "127.0.0.1")
// Group by address and account: how many computers it reached each way
| STATS krb_targets = COUNT_DISTINCT(krb_target), ipc_targets = COUNT_DISTINCT(ipc_target),
        target_sample = TOP(krb_target, 20, "asc"), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
    BY source.ip = ip, user.name = account
// Sanctioned collectors and scanners, as account + address pairs, so the same account used from anywhere else
// still alerts (placeholders)
| WHERE NOT (user.name == "<sanctioned_bloodhound_account>" AND source.ip IN ("<sanctioned_collector_ip>"))
// One account reaching 50+ computers in the hour. Source: baseline on two days: the sanctioned BloodHound
// collector reached 920 (tickets) and 132 (IPC$); every other account above 50 is a known scanner or management
// account (excluded above); the next highest was about 38.
| WHERE krb_targets >= 50 OR ipc_targets >= 50
```
No LogScale version: the Windows logs are in Elastic. Suppress by address and account for 6h.

## Which host and process sent it
Falcon, for the alert's address only, so it's cheap. No rows means the address isn't a managed host: the attacker's own machine, or a device behind a proxy (check 05 on the hosts around it). SharpHound's SMB goes through the Windows kernel and shows as `System`; its LDAP connections (389) show the tool itself, `sharphound.exe` or `powershell.exe`.
```esql
FROM logs-yourorg-crowdstrike-data-default*
// Which managed host and process talked to AD from the alert's address
| WHERE event.action == "networkconnectip4" AND source.ip == "<source.ip>"
  AND destination.port IN (88, 389, 445, 636, 3268, 3269, 9389)
| STATS connections = COUNT(*), ports = VALUES(destination.port), first_seen = MIN(@timestamp)
    BY host.name, data.ContextBaseFileName
```
```logscale
#event_simpleName=NetworkConnectIP4 LocalAddressIP4="<source.ip>" RemotePort=/^(88|389|445|636|3268|3269|9389)$/
| default(field=ContextBaseFileName, value="unknown")
| groupBy([aid, ContextBaseFileName], function=[count(as=connections), collect([RemotePort])], limit=max)
| match(file="aid_master_main.csv", field=aid, include=[ComputerName], strict=false)
```

## Baseline
One query over the last 7 days: the rule's filter, per account, address and hour, keeping only the busy hours. Accounts peaking at 50+ go into the exclusion as pairs; the threshold sits above the highest of the rest. If it's heavy, drop the 5140 line first, or run it through the async API (`POST /_query/async`).
```esql
FROM logs-yourorg-microsoft-windows*
// Tickets to computer accounts and IPC$ connections, by user accounts (the rule's filter)
| WHERE (event.code == "4769" AND winevt.event_data.status == "0x0"
         AND ENDS_WITH(winevt.event_data.service_name, "$")
         AND NOT ENDS_WITH(user.name, "$") AND NOT user.name LIKE "*$@*")
     OR (event.code == "5140" AND winevt.event_data.share_name == "\\\\*\\IPC$" AND NOT ENDS_WITH(user.name, "$"))
// The address, the account without @DOMAIN, the hour, and the computer reached each way
| EVAL ip = REPLACE(TO_STRING(source.ip), "^::ffff:", ""),
       account = TO_LOWER(MV_FIRST(SPLIT(user.name, "@"))),
       hour = DATE_TRUNC(1 hour, @timestamp),
       krb_target = CASE(event.code == "4769", TO_LOWER(winevt.event_data.service_name), null),
       ipc_target = CASE(event.code == "5140", TO_LOWER(host.name), null)
// Computers each account reached from each address in each hour
| STATS krb_targets = COUNT_DISTINCT(krb_target, 1000), ipc_targets = COUNT_DISTINCT(ipc_target, 1000)
    BY account, ip, hour
// Keep only the busy hours
| WHERE krb_targets >= 20 OR ipc_targets >= 20
// second STATS, baseline only: per account and address, its peak hour and how many hours went over 20
| STATS peak_krb = MAX(krb_targets), peak_ipc = MAX(ipc_targets), busy_hours = COUNT(*),
        first_busy = MIN(hour), last_busy = MAX(hour)
    BY account, ip
| SORT peak_krb DESC
```
The cheapest alternative is to let the rule baseline itself: deploy it at `>= 20` with no notifications for a week, then read its alerts.

## Before turning it on
- Put every account from the baseline that legitimately crosses 50 (the sanctioned collector, scanners, management tools) into the exclusion as account + address pairs. A Kibana rule exception works too, but give it both fields: the sanctioned BloodHound account is exactly the account an attacker would like to borrow.
- Check the 4769 `user.name` format. If computer accounts arrive as `name$@DOMAIN`, the `*$@*` line is what keeps them out.
- 5140 needs "Audit File Share" on the targets, and only the targets whose Security logs you collect count towards `ipc_targets`. With workstation logs missing, the 4769 side does the work.

## What it misses
- SharpHound from the attacker's own machine over NTLM, or `bloodhound.py` without `-k`: no 4769, and 5140 only on the targets you collect. 05 sees the proxy on the pivot.
- LDAP-only collection (`-c DCOnly`) and Stealth collection, which skip most computers.
- A sweep throttled under 50 computers an hour. A second copy over 24 hours with a higher threshold catches slow ones; baseline it the same way.

## When it fires
Run the pivot query for the address. A managed host with `sharphound.exe`, `powershell.exe` or an unknown binary on 389 is the collector; look on it for the output, a zip of JSON files, and treat the account as compromised until the run is explained. No managed host means the attacker's machine or a proxy: check 05 on the hosts around it.
