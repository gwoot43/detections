---
id: SWEEP-01
name: BloodHound / SharpHound collection sweep - one account asks the DC for a ticket to 50+ computers
language: esql
index: logs-yourorg-microsoft-windows*
mitre: [T1087.002, T1069.002, T1018, T1049]
data_source: Windows Security 4769 (DCs); optional 5140 (targets)
suppression:
  fields: [source.ip, user.name]
  duration: 6h
  missing_fields: do_not_suppress
---
SharpHound's session, local-admin and group collection connects to every computer it can reach, and on a domain-joined host each connection first asks the DC for that computer's Kerberos service ticket. So **one account asking for tickets to 50+ different computer accounts in the window** is the sweep - a single event type, a single count, a single threshold.

The ticket request is a **4769** whose service name ends in `$` (a computer account). User accounts only: a machine requesting host tickets is normal, so the requester must not be a `name$@DOMAIN` account.

Run hourly over the last hour.
```esql
FROM logs-yourorg-microsoft-windows*
// 4769 for a computer-account service ticket (service name ends in $), requested by a user account.
// The NOT ... LIKE "*$@*" wildcard drops machine requesters (name$@DOMAIN), which ask for host tickets by design.
| WHERE event.code == "4769" AND winevt.event_data.status == "0x0"
  AND ENDS_WITH(winevt.event_data.service_name, "$") AND NOT user.name LIKE "*$@*"
| EVAL account = TO_LOWER(user.name)
// one account reaching 50+ distinct computers in the window is the sweep (starting value - baseline below)
| STATS computers = COUNT_DISTINCT(winevt.event_data.service_name),
        sample = TOP(winevt.event_data.service_name, 20, "asc"),
        first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
    BY account, source.ip
// sanctioned collectors and scanners, as account + address pairs (placeholders)
| WHERE NOT (account == "<sanctioned_account>" AND source.ip IN ("<sanctioned_collector_ip>"))
| WHERE computers >= 50
```
No LogScale version: the Windows logs are in Elastic. Suppress by address and account for 6h. (`source.ip` may carry a `::ffff:` prefix on IPv4 - cosmetic, it still groups per host.)

## Optional: the target side (5140)
If you collect **Audit File Share** (5140) from your servers and workstations, the same sweep shows there as IPC$ opened on many computers - and it also catches a collector running over NTLM, which raises no 4769. Run it the same way; it only counts targets whose Security log you actually collect, so with workstation logs missing the 4769 side does the work.
```esql
FROM logs-yourorg-microsoft-windows*
// IPC$ opened on many computers by one user account (LIKE, so the \\host\ part is a wildcard)
| WHERE event.code == "5140" AND winevt.event_data.share_name LIKE "\\\\*\\IPC$" AND NOT user.name LIKE "*$"
| EVAL account = TO_LOWER(user.name)
| STATS computers = COUNT_DISTINCT(host.name), sample = TOP(host.name, 20, "asc"),
        first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
    BY account, source.ip
// same 50-computer threshold as the 4769 rule - baseline it the same way
| WHERE computers >= 50
```

## Which host and process sent it
Falcon, for the alert's address only, so it's cheap. No rows means the address isn't a managed host (the attacker's own machine, or a device behind a proxy - check 05 on the hosts around it). SharpHound's SMB goes through the kernel and shows as `System`; its LDAP (389/9389) shows the tool, `sharphound.exe` or `powershell.exe` - which 24 catches as a directory sweep.
```esql
FROM logs-yourorg-crowdstrike-data-default*
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
One query over the last 7 days: the rule's filter, per account, address and hour, keeping the busy hours. Accounts that peak at 50+ go into the exclusion as pairs; set the threshold above the highest of the rest.
```esql
FROM logs-yourorg-microsoft-windows*
// the rule's filter (the "*$@*" wildcard drops machine requesters), per account, address and hour
| WHERE event.code == "4769" AND winevt.event_data.status == "0x0"
  AND ENDS_WITH(winevt.event_data.service_name, "$") AND NOT user.name LIKE "*$@*"
| EVAL account = TO_LOWER(user.name), hour = DATE_TRUNC(1 hour, @timestamp)
| STATS computers = COUNT_DISTINCT(winevt.event_data.service_name, 2000) BY account, source.ip, hour
| WHERE computers >= 20
// second STATS, baseline only: per account and address, its peak hour and how many hours ran hot
| STATS peak = MAX(computers), busy_hours = COUNT(*), first_busy = MIN(hour), last_busy = MAX(hour)
    BY account, source.ip
| SORT peak DESC
```
The cheapest alternative is to let the rule baseline itself: deploy it at `>= 20` with no notifications for a week, then read its alerts. Set the threshold above your busiest legitimate account (a scanner or management account) and well below a real collection run, which reaches hundreds.

## Before turning it on
- Put every account from the baseline that legitimately crosses 50 (scanners, management tools, any sanctioned collector) into the exclusion as account + address pairs - give it both fields, since a sanctioned collector account is exactly the one an attacker would borrow.
- Check the 4769 `user.name` format. If computer accounts arrive as `name$@DOMAIN`, the `*$@*` line is what keeps them out.

## What it misses
- SharpHound from the attacker's own machine over NTLM, or `bloodhound.py` without `-k`: no 4769. The optional 5140 companion catches it where you audit file shares; 05 sees the proxy on the pivot; 24 sees the LDAP/ADWS collection.
- LDAP-only (`-c DCOnly`) and Stealth collection, which skip most computers - 24 covers the directory read.
- A sweep throttled under 50 computers an hour. A second copy over 24 hours with a higher threshold catches slow ones; baseline it the same way.

## When it fires
Run the pivot query for the address. A managed host with `sharphound.exe`, `powershell.exe` or an unknown binary on 389/9389 is the collector; look on it for the output (a zip of JSON) and treat the account as compromised until the run is explained. No managed host means the attacker's machine or a proxy: check 05 on the hosts around it.
