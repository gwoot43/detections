---
id: SMBENUM-01
name: BloodHound / SharpHound SMB enumeration - several directory interfaces opened across many hosts
language: esql
index: logs-yourorg-microsoft-windows*
mitre: [T1087.002, T1069.002, T1018, T1049]
data_source: Windows Security 5145 (Audit Detailed File Share) on the hosts you audit
suppression:
  fields: [user.name]
  duration: 6h
  missing_fields: do_not_suppress
---
**BloodHound's directory collection over SMB, by the interfaces it opens.** SharpHound asks each host three questions, each through its own RPC interface - `NetSessionEnum` over **srvsvc**, `NetWkstaUserEnum` over **wkssvc**, `NetLocalGroupGetMembers` over **samr**, and the registry collection over **winreg** - and every one is a named pipe opened on `\\host\IPC$`. The host that was interrogated writes a 5145 naming the pipe, the account and the client.

One event type, one count: **one account opening these interfaces on ten or more hosts, using two or more different interfaces, inside a quarter hour**. An inventory script or a `net view \\host` sweep uses a single interface; SharpHound's default collection uses three.

## What this is not
- **Not Snaffler** - it reads **files** on real shares and touches none of these pipes. That is **10**.
- **Not remote execution** - `svcctl`, `atsvc`, `remcom_*` belong to **15** and are deliberately left out of the pipe list here.
- **Not the LDAP half** - `-c DCOnly`, `bloodhound.py` and ADExplorer open no pipe: **08b** sees their security-descriptor reads, **24** their fan-out across DCs.

## Reading a 5145
- **`winevt.event_data.share_name`** is the share, with the server masked by Windows: `\\*\IPC$` (Microsoft's 5145 sample shows `\\*\Documents`).
- **`winevt.event_data.relative_target_name`** is what was opened on it - on IPC$, the **pipe name**. That field is the detection.
- **`user.name`** is the account, **`source.ip`** the client, **`host.name`** the host interrogated. If your pipeline keeps the subject only in `winevt.event_data.subject_user_name` / `winevt.event_data.ip_address`, as 15 uses, change those two names and nothing else.

Run every 5 minutes over the last 15. The window is the rate control.

## Query
```esql
FROM logs-yourorg-microsoft-windows*
// 5145 on IPC$ = a named pipe was opened. These are the directory-enumeration interfaces:
// srvsvc = sessions, wkssvc = logged-on users, samr = local group members, winreg = registry.
| WHERE event.code == "5145"
// Leading wildcard on purpose: ShareName is logged as \\*\IPC$ with the server masked, so there is no
// prefix to index. If your pipeline lowercases it, add the lowercase variant of this pattern.
  AND winevt.event_data.share_name LIKE "*\\IPC$"
  AND winevt.event_data.relative_target_name IN ("srvsvc", "samr", "wkssvc", "winreg")
// Machine accounts run these pipes as normal service traffic, and nothing in 5145 says "machine account",
// so this is a leading-wildcard test on purpose. IS NULL keeps a row whose subject is missing.
  AND (user.name IS NULL
       OR (NOT user.name LIKE "*$" AND NOT user.name LIKE "*$@*"))
// Sanctioned inventory / monitoring account, as an account + address pair (placeholders, repeat per pair).
// Both fields, so the same account driven from anywhere else still alerts.
  AND NOT (user.name == "<inventory_account>" AND source.ip == "<inventory_ip>")
| EVAL user.name = TO_LOWER(COALESCE(user.name, "unknown-user"))
// One row per account: how many hosts it touched, and how many different interfaces it used.
| STATS hosts = COUNT_DISTINCT(host.name),
        pipes = COUNT_DISTINCT(winevt.event_data.relative_target_name),
        pipes_seen = MV_SLICE(VALUES(winevt.event_data.relative_target_name), 0, 4),
        addrs = COUNT_DISTINCT(source.ip),
        first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
    BY user.name
// 10 hosts and 2 interfaces in 15 minutes are starting values - a collection run reaches hundreds of hosts
// and three interfaces, an admin working by hand does neither. Measure with the Baseline query below.
| WHERE hosts >= 10 AND pipes >= 2
| SORT hosts DESC
| LIMIT 100
```
`pipes` is counted **across the window, not per host**. For SharpHound that costs nothing - it uses the same three interfaces on every host it visits - and it keeps the rule to one reduce. A tool that used one interface per host would slip past; that is the trade, and 24 covers the same activity from the network side.

`pipes_seen` names the interfaces, which is the triage detail: `samr` means local-group collection (who is a local admin where, the step before lateral movement), `wkssvc` means logged-on users, `srvsvc` means sessions.

## Baseline
Over 7 days at the rule's window, same gate, nothing filtered before the last `STATS` - a pre-filter would hide every account the threshold has to clear. Percentiles over active buckets only.
```esql
FROM logs-yourorg-microsoft-windows*
// the rule's gate, unchanged (including the leading-wildcard IPC$ and machine-account tests)
| WHERE event.code == "5145"
  AND winevt.event_data.share_name LIKE "*\\IPC$"
  AND winevt.event_data.relative_target_name IN ("srvsvc", "samr", "wkssvc", "winreg")
  AND (user.name IS NULL
       OR (NOT user.name LIKE "*$" AND NOT user.name LIKE "*$@*"))
| EVAL user.name = TO_LOWER(COALESCE(user.name, "unknown-user")),
       bucket = DATE_TRUNC(15 minutes, @timestamp)
| STATS hosts = COUNT_DISTINCT(host.name), pipes = COUNT_DISTINCT(winevt.event_data.relative_target_name)
    BY user.name, bucket
| WHERE pipes >= 2
// this is the baseline: no threshold on `hosts` here, because filtering first would hide the accounts
// this query exists to measure
| STATS active_buckets = COUNT(*), p50 = PERCENTILE(hosts, 50), p99 = PERCENTILE(hosts, 99),
        peak = MAX(hosts), hot_buckets = COUNT(*) WHERE hosts >= 10
    BY user.name
| SORT peak DESC
| LIMIT 50
```
`p99` of 1-2 with a `peak` in the hundreds is a collector. A `peak` of 100+ every day is an inventory or monitoring product - exclude it as an account + address pair, and note that your estate opens these interfaces routinely.

## Before turning it on
- **Audit Detailed File Share (5145) must be on for every host you want to count** - workstations as well as servers, or a workstation sweep only shows its server touches.
- Check the interface mix your estate actually produces:
```esql
FROM logs-yourorg-microsoft-windows*
// leading wildcard for the same reason as the rule: ShareName masks the server name
| WHERE event.code == "5145" AND winevt.event_data.share_name LIKE "*\\IPC$"
| STATS n = COUNT(*), hosts = COUNT_DISTINCT(host.name) BY winevt.event_data.relative_target_name
| SORT n DESC
| LIMIT 25
```
- Check the subject field name: `user.name` (ECS) or `winevt.event_data.subject_user_name` (what 15 uses). If your monitoring product runs as a **user** account it will be in the baseline's top rows - exclude that account plus its address rather than raising the threshold.
- Suppress by `user.name`: it is the entity the rule decides on, and a re-run of the same sweep folds into one alert.

## What it misses
- **A single-interface sweep** - `-c Session` only touches `srvsvc`. Drop `pipes >= 2` and keep `hosts >= 15` for that, as a separate rule rather than widening this one.
- **Hosts whose 5145 you do not collect** - 24 is the transport-independent backstop, 08b the directory-side one.
- **A sweep split across accounts or collector hosts**, each under the threshold. The entity is the account; that needs a destination-side view (5156 on the targets).
- **SOAPHound and ADWS-based collection**, which may open no SMB pipe at all - 24 flags `directory_sweep_adws`.

## When it fires
Identify `user.name` first: a normal user account means the collector ran with that user's token - the user ran it, or the credential is stolen. Assume the second until it is explained. Then read `pipes_seen` for which collection methods ran, and name the host and binary with Falcon for one address from `addrs`:
```esql
FROM logs-yourorg-crowdstrike-data-default*
// one address from the alert; no leading wildcard, this is an equality on an indexed field
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
SharpHound's pipe traffic is SMB through the kernel, so the process shows as `System`; the LDAP half of the same run is what 24 and 08b see. No rows means the address is not a managed host - the attacker's own machine or a proxy; check 05 on the hosts around it.
