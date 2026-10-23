---
id: SWEEP-01
name: BloodHound / SharpHound collection sweep - one account reaching 50+ computers in an hour (Kerberos tickets or IPC$), with the client's process from Falcon
language: esql
index: logs-yourorg-microsoft-windows*, logs-yourorg-crowdstrike-data-default*
mitre: [T1087.002, T1069.002, T1018, T1049]
data_source: Windows Security 4769 (DCs) and 5140 (targets); CrowdStrike FDR NetworkConnectIP4
suppression:
  fields: [source.ip, user.name]
  duration: 6h
  missing_fields: do_not_suppress
---
SharpHound's session, local-admin and group collection connects to every computer it can reach. Each connection leaves:
- **a service ticket on the DC (4769)** for that computer's account (`name$`), when the collector runs on a domain-joined host;
- **an IPC$ connection on the target (5140)**, for the SMB/RPC calls (srvsvc, samr, lsarpc).

So one account reaching 50+ different computers in an hour is the sweep. Falcon adds which process on the client talked to AD. SharpHound's SMB goes through the Windows kernel (`System`, excluded), so what Falcon credits to the tool is its LDAP connections (389): `sharphound.exe:389` or `powershell.exe:389`.

Run hourly over the last hour.
```esql
FROM logs-yourorg-microsoft-windows*, logs-yourorg-crowdstrike-data-default*
// Filter for tickets to computer accounts and IPC$ connections, by user accounts, and for connections to AD and
// SMB ports from processes other than the ones that normally make them (Falcon, for the client's process)
| WHERE (event.code == "4769" AND winevt.event_data.status == "0x0"
         AND ENDS_WITH(winevt.event_data.service_name, "$")
         AND NOT ENDS_WITH(user.name, "$") AND NOT user.name LIKE "*$@*")
     OR (event.code == "5140" AND winevt.event_data.share_name == "\\\\*\\IPC$" AND NOT ENDS_WITH(user.name, "$"))
     OR (event.action == "networkconnectip4" AND data.event_platform == "Win"
         AND destination.port IN (88, 389, 445, 636, 3268, 3269, 9389)
         AND NOT data.ContextBaseFileName IN ("lsass.exe", "svchost.exe", "WmiPrvSE.exe", "taskhostw.exe", "cscript.exe",
               "certutil.exe", "CcmExec.exe", "dsregcmd.exe", "<internal_tool>.exe", "explorer.exe", "System"))
// The client address (without the ::ffff: DCs put in front of IPv4, so it matches Falcon's), the account
// without @DOMAIN (4769 has it, 5140 doesn't), the computer reached, and the Falcon context
| EVAL ip = REPLACE(TO_STRING(source.ip), "^::ffff:", ""),
       is_cs = event.action == "networkconnectip4",
       account = CASE(is_cs, null, TO_LOWER(MV_FIRST(SPLIT(user.name, "@")))),
       krb_target = CASE(event.code == "4769", TO_LOWER(winevt.event_data.service_name), null),
       ipc_target = CASE(event.code == "5140", TO_LOWER(host.name), null),
       cs_host = CASE(is_cs, host.name, null),
       odd_proc = CASE(is_cs, CONCAT(TO_LOWER(data.ContextBaseFileName), ":", TO_STRING(destination.port)), null)
| WHERE ip IS NOT NULL AND NOT ip IN ("::1", "127.0.0.1")
// Group by client address and account: how many computers it reached each way
| STATS krb_targets = COUNT_DISTINCT(krb_target), ipc_targets = COUNT_DISTINCT(ipc_target),
        target_sample = TOP(krb_target, 20, "asc"), cs_host = VALUES(cs_host), odd_procs = VALUES(odd_proc),
        first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
    BY source.ip = ip, user.name = account
// Attach the client's Falcon context (its rows have no account) to each account row from that address
| INLINE STATS cs_host = VALUES(cs_host), odd_procs = VALUES(odd_procs) BY source.ip
| WHERE user.name IS NOT NULL
// Sanctioned collectors and scanners, as account + address pairs, so the same account used from anywhere else
// still alerts (placeholders)
| WHERE NOT (user.name == "<sanctioned_bloodhound_account>" AND source.ip IN ("<sanctioned_collector_ip>"))
// One account reaching 50+ computers in the hour. Source: baseline on two days: the sanctioned BloodHound
// collector reached 920 (tickets) and 132 (IPC$); every other account above 50 is a known scanner or management
// account (excluded above); the next highest was about 38.
| WHERE krb_targets >= 50 OR ipc_targets >= 50
```
No LogScale version: the Windows logs are in Elastic. Suppress by address and account for 6h.

## Before turning it on
- Put every account from the baseline that legitimately crosses 50 (the sanctioned collector, scanners, management tools) into the exclusion as account + address pairs. A Kibana rule exception works too, but give it both fields: the sanctioned BloodHound account is exactly the account an attacker would like to borrow.
- Check the 4769 `user.name` format. If computer accounts arrive as `name$@DOMAIN`, the `*$@*` line is what keeps them out.
- 5140 needs "Audit File Share" on the targets, and only the targets whose Security logs you collect count towards `ipc_targets`. With workstation logs missing, the 4769 side does the work.
- The baseline covers two days. A week, including a patch window, is a safer base for the 50.

## What it misses
- SharpHound from the attacker's own machine over NTLM, or `bloodhound.py` without `-k`: no 4769, and 5140 only on the targets you collect. 05 sees the proxy on the pivot.
- LDAP-only collection (`-c DCOnly`) and Stealth collection, which skip most computers.
- A sweep throttled under 50 computers an hour. A second copy over 24 hours with a higher threshold catches slow ones; baseline it the same way.

## When it fires
`cs_host` and `odd_procs` name the client and the tool: `sharphound.exe:389`, `powershell.exe:389` or a renamed binary. No `cs_host` means the address isn't a managed host: the attacker's machine, or one behind a proxy (check 05 on the hosts around it). Look on the client for the collector's output, a zip of JSON files, and treat the account as compromised until the run is explained.
