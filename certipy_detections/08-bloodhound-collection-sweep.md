---
id: SMBENUM-01
name: SMB enumeration fan-out - one account opening srvsvc, samr or wkssvc pipes on 15+ hosts in minutes
language: esql
index: logs-yourorg-microsoft-windows*
mitre: [T1087.002, T1069.002, T1018, T1049]
data_source: Windows Security 5145 (Audit Detailed File Share) on the hosts you audit
suppression:
  fields: [user.name]
  duration: 6h
  missing_fields: do_not_suppress
---
**Catches the collection itself, not its side effects.** SharpHound's session, logged-on and local-admin collection is three RPC calls repeated host by host - `NetSessionEnum` over the **srvsvc** pipe, `NetWkstaUserEnum` over **wkssvc**, `NetLocalGroupGetMembers` over **samr** - and every one of those opens a named pipe on `\\host\IPC$`. So the sweep leaves a row per host in 5145, written by the host that was interrogated, naming the pipe that was opened and the account that opened it.

The behaviour is the fan-out: **one account opening those pipes on 15+ different hosts inside a few minutes**. A person does not read fifteen servers' session tables in a quarter hour; `net view \\host` or browsing a share is a single row on a single host, and the admin tools that do touch many hosts use `svcctl`/`atsvc` (15's territory) rather than the enumeration pipes.

It also catches a collector over **NTLM** as well as Kerberos, because 5145 records the pipe access however the client authenticated - which is exactly what a Kerberos ticket count cannot see.

## Reading a 5145
- **`winevt.event_data.share_name`** is the share, and Windows masks the server: it arrives as `\\*\IPC$`, not `\\fileserver\IPC$` (Microsoft's 5145 sample shows `\\*\Documents`).
- **`winevt.event_data.relative_target_name`** is what was opened on that share - a file name on a data share, the **pipe name** on IPC$. That field is what says whether this was a session query, a group query or a registry read.
- **`user.name`** is the account that opened it, **`source.ip`** the client, **`host.name`** the host being interrogated. If your pipeline leaves the subject only in `winevt.event_data.subject_user_name` / `winevt.event_data.ip_address`, as 15 uses, swap those two field names and nothing else changes.

Run every 5 minutes over the last 15. The window is the rate control: an admin who genuinely works through fifteen hosts does it over an afternoon, not inside a quarter hour.

## Query
```esql
FROM logs-yourorg-microsoft-windows*
// 5145 on IPC$ = a named pipe was opened. srvsvc = sessions, wkssvc = logged-on users, samr = local
// groups, winreg = the registry collection.
| WHERE event.code == "5145"
// Leading wildcard on purpose: ShareName is logged as \\*\IPC$ with the server masked, so there is no
// prefix to index. If your pipeline lowercases it, add the lowercase variant of this pattern.
  AND winevt.event_data.share_name LIKE "*\\IPC$"
  AND winevt.event_data.relative_target_name IN ("srvsvc", "samr", "wkssvc", "winreg")
// Machine accounts talk to these pipes as normal service traffic (monitoring, backup, inventory agents),
// and nothing in 5145 says "machine account", so this is a leading-wildcard test on purpose.
// IS NULL keeps a row whose subject is missing instead of dropping it silently.
  AND (user.name IS NULL
       OR (NOT user.name LIKE "*$" AND NOT user.name LIKE "*$@*"))
// Sanctioned inventory / monitoring account, as an account + address pair (placeholders, repeat per pair).
// Both fields, so the same account driven from anywhere else still alerts.
  AND NOT (user.name == "<inventory_account>" AND source.ip == "<inventory_ip>")
| EVAL user.name = TO_LOWER(COALESCE(user.name, "unknown-user"))
// One row per account over the whole window - no time bucket, so a sweep that straddles a boundary is
// not split into two halves that each sit under the threshold.
| STATS hosts_touched = COUNT_DISTINCT(host.name),
        pipes = COUNT_DISTINCT(winevt.event_data.relative_target_name),
        pipes_seen = MV_SLICE(VALUES(winevt.event_data.relative_target_name), 0, 8),
        hosts_seen = TOP(host.name, 10, "asc"),
        addrs = COUNT_DISTINCT(source.ip),
        first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
    BY user.name
// Label, not a filter: -c Session alone touches srvsvc only and is still collection, but a single pipe
// across many hosts is also what an inventory script looks like, so the analyst has to see which this is.
| EVAL pattern = CASE(pipes >= 2, "multi-pipe collection", "single-pipe sweep")
// 15 hosts in 15 minutes is a starting value - a collection run reaches hundreds, a person reaches a
// handful. Replace it with the p99 from the Baseline query below.
| WHERE hosts_touched >= 15
| EVAL span_s = DATE_DIFF("second", first_seen, last_seen)
| SORT hosts_touched DESC
| LIMIT 100
```
`hosts_seen` and `pipes_seen` are bounded and alphabetical, not "the most interesting ten"; the pivot in **When it fires** finds the rest. `pattern` answers the first triage question: `multi-pipe collection` with `samr` in the set is local-admin collection, which is the step before an attacker knows what is worth stealing.

## Baseline
One query over the last 7 days at the rule's window. Nothing is filtered before the second `STATS` on purpose - a pre-filter would hide every account whose peak sits under the threshold, which is exactly the population the threshold has to clear. Percentiles are over **active** buckets only: a quarter hour with none of this traffic produces no row.
```esql
FROM logs-yourorg-microsoft-windows*
// the rule's gate, unchanged (including the leading-wildcard IPC$ test)
| WHERE event.code == "5145"
  AND winevt.event_data.share_name LIKE "*\\IPC$"
  AND winevt.event_data.relative_target_name IN ("srvsvc", "samr", "wkssvc", "winreg")
  AND (user.name IS NULL
       OR (NOT user.name LIKE "*$" AND NOT user.name LIKE "*$@*"))
| EVAL user.name = TO_LOWER(COALESCE(user.name, "unknown-user")),
       bucket = DATE_TRUNC(15 minutes, @timestamp)
| STATS hosts = COUNT_DISTINCT(host.name) BY user.name, bucket
// this is the baseline: no threshold on `hosts` here, because filtering first would hide the accounts
// this query exists to measure
| STATS active_buckets = COUNT(*),
        p50 = PERCENTILE(hosts, 50),
        p95 = PERCENTILE(hosts, 95),
        p99 = PERCENTILE(hosts, 99),
        peak = MAX(hosts),
        hot_buckets = COUNT(*) WHERE hosts >= 15
    BY user.name
| SORT peak DESC
| LIMIT 50
```
An account with `p99` of 1-2 and a `peak` in the hundreds is a collector: find out what it is, then exclude it as an account + address pair. An account whose `peak` is 200+ every day is an inventory or monitoring product, and belongs in the exclusion with its address - not the rule switched off.

## Before turning it on
- **Audit Detailed File Share (5145) must be on for every host you want to count**, not just servers. The rule cannot count what it cannot see, so a workstation-only collection shows only its server touches - coverage sets the usable threshold, and partial coverage is the difference between this rule firing and staying silent.
- Check which pipes your estate actually opens on IPC$, and from which accounts:
```esql
FROM logs-yourorg-microsoft-windows*
// leading wildcard here for the same reason as the rule: ShareName masks the server name
| WHERE event.code == "5145" AND winevt.event_data.share_name LIKE "*\\IPC$"
| STATS n = COUNT(*), hosts = COUNT_DISTINCT(host.name) BY winevt.event_data.relative_target_name
| SORT n DESC
| LIMIT 25
```
- Check the subject field name: `user.name` (ECS) or `winevt.event_data.subject_user_name` (what 15 uses). Machine accounts should dominate; if a **user** account appears in the top rows, put that account and its address in the exclusion.
- 5145 is a high-volume event. If ingest cost is the objection, keep the `IN` list rather than dropping the collection - that is what makes the query cheap.
- Suppress by `user.name`: it is the entity that survives the `STATS`, and a re-run of the same sweep folds into one alert.

## What it misses
- **Collection that never touches SMB.** `-c DCOnly`, `bloodhound.py` and ADExplorer read the directory over LDAP or ADWS and open no pipe - **08b** catches the LDAP security-descriptor read, **24** catches one process fanning out across DCs on 389/636/3268/9389.
- **Hosts whose 5145 you don't collect.** A server-only audit makes a workstation sweep look small; 24 is the transport-independent backstop.
- **A sweep split across several accounts or several collector hosts**, each staying under the threshold. The entity is the account, so this needs a destination-side view (5156 on the targets, or `host.name` grouped across accounts).
- **Single-pipe fan-out at low volume** - an inventory script that only reads `srvsvc` looks like `-c Session`. That is what `pattern` and the per-account baseline are for.
- **Remote-registry collection** also lands in `winreg`, which 15 alerts on per host. Both firing means a full collection run; 15 names the moment.

## When it fires
Take `user.name` and identify it: a normal user account means the collector ran with that user's token, so either the user ran it or the credential is stolen - treat the second as the assumption until proven otherwise.

Then name the host and the binary. SharpHound's pipe traffic is SMB through the kernel, so Falcon shows the process as `System`; the LDAP half of the same run shows `sharphound.exe` or `powershell.exe`, which 24 catches. Run this for one address from `addrs`:
```esql
FROM logs-yourorg-crowdstrike-data-default*
// one address from the alert; no leading wildcard, this one is an equality on an indexed field
| WHERE event.action == "networkconnectip4" AND source.ip == "<source.ip>"
  AND destination.port IN (88, 389, 445, 636, 3268, 3269, 9389)
| STATS connections = COUNT(*), ports = VALUES(destination.port), first_seen = MIN(@timestamp)
    BY host.name, data.ContextBaseFileName
```
```logscale
#event_simpleName=NetworkConnectIP4 LocalAddressIP4="<source.ip>" RemotePort=in([88, 389, 445, 636, 3268, 3269, 9389])
| default(field=ContextBaseFileName, value="unknown")
| groupBy([aid, ContextBaseFileName], function=[count(as=connections), collect([RemotePort], limit=10)], limit=max)
| match(file="aid_master_main.csv", field=aid, include=[ComputerName])
| select([ComputerName, ContextBaseFileName, connections, _collect])
```
No rows means the address is not a managed host: the attacker's own machine, or a device behind a proxy - check 05 on the hosts around it.

## Why not the ticket-count version
An earlier version of this rule counted Kerberos service-ticket requests (4769) per account. That measured a **consequence**: every SMB session needs a ticket, so ticket breadth is shared with any busy admin, backup job or vulnerability scanner, and the number had to sit high enough to clear them. The pipe is the action the tool takes, it carries the collection method in `relative_target_name`, and it shows even when the client authenticated over NTLM. 08b covers the directory-side read that neither sees.
