---
id: SMBENUM-01
name: BloodHound / SharpHound SMB enumeration - several directory interfaces opened per host, across many hosts
language: esql
index: logs-yourorg-microsoft-windows*
mitre: [T1087.002, T1069.002, T1018, T1049]
data_source: Windows Security 5145 (Audit Detailed File Share) on the hosts you audit
suppression:
  fields: [user.name]
  duration: 6h
  missing_fields: do_not_suppress
---
**BloodHound's directory collection over SMB, by the interfaces it opens.** SharpHound asks each host three questions, each through its own RPC interface: `NetSessionEnum` over the **srvsvc** pipe, `NetWkstaUserEnum` over **wkssvc**, `NetLocalGroupGetMembers` over **samr**, and the registry collection over **winreg**. Every one of those is a named pipe opened on `\\host\IPC$`, so the host that was interrogated writes a 5145 naming the pipe, the account and the client.

The fingerprint is **several of those interfaces on the same host, then the same thing on the next host**: per host `pipes_on_host >= 2`, and ten or more such hosts by one account in a quarter hour.

## What this is not
- **Not Snaffler.** Snaffler reads **files** - it opens real shares and walks directories looking for secrets. It touches none of these pipes, and its detection is **10** (data shares opened on many computers). A 08 alert with no data-share activity in the window is confirmation rather than a gap: the collector was asking the directory who is logged on, not reading data.
- **Not remote execution.** `svcctl`, `atsvc` and `remcom_*` are **15**'s pipes. This rule excludes them, so a psexec loop does not look like a collection sweep.
- **Not the LDAP half.** `-c DCOnly`, `bloodhound.py` and ADExplorer never open a pipe: **08b** catches their security-descriptor requests, **24** their fan-out across DCs.

One interface per host is what ordinary management looks like - an inventory script, `net view \\host`, a monitoring agent. Several interfaces per host, on host after host, is a graph being built.

## Reading a 5145
- **`winevt.event_data.share_name`** is the share, with the server masked by Windows: `\\*\IPC$` (Microsoft's own 5145 sample shows `\\*\Documents`).
- **`winevt.event_data.relative_target_name`** is what was opened on it - on IPC$, the **pipe name**. That field is the whole detection.
- **`user.name`** is the account, **`source.ip`** the client, **`host.name`** the host interrogated. If your pipeline keeps the subject only in `winevt.event_data.subject_user_name` / `winevt.event_data.ip_address`, as 15 uses, change those two field names and nothing else.

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
// Reduce per host first: which interfaces did this account open on ONE host? A collector opens several;
// an inventory script or `net view` opens one.
| STATS pipes_on_host = COUNT_DISTINCT(winevt.event_data.relative_target_name),
        sessions = COUNT(*) WHERE winevt.event_data.relative_target_name == "srvsvc",
        logged_on = COUNT(*) WHERE winevt.event_data.relative_target_name == "wkssvc",
        local_admin = COUNT(*) WHERE winevt.event_data.relative_target_name == "samr",
        registry = COUNT(*) WHERE winevt.event_data.relative_target_name == "winreg"
    BY user.name, host.name
// 2 interfaces on one host is a starting value: SharpHound's default collection opens three, a management
// script opens one. Confirm what your estate does with the probe in Before turning it on.
| WHERE pipes_on_host >= 2
// Second STATS on purpose: the fan-out is the sweep, and only hosts that passed the interface test count.
| STATS hosts_enumerated = COUNT(*),
        hosts_sessions = COUNT(*) WHERE sessions > 0,
        hosts_logged_on = COUNT(*) WHERE logged_on > 0,
        hosts_local_admin = COUNT(*) WHERE local_admin > 0,
        hosts_registry = COUNT(*) WHERE registry > 0,
        sample_hosts = TOP(host.name, 10, "asc"),
        first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
    BY user.name
// 10 hosts in 15 minutes is a starting value - a collection run reaches hundreds, an admin working by hand
// does not open two interfaces on ten hosts. Replace it with the p99 from the Baseline query below.
| WHERE hosts_enumerated >= 10
| EVAL span_s = DATE_DIFF("second", first_seen, last_seen)
| SORT hosts_enumerated DESC
| LIMIT 100
```
The four `hosts_*` counts are the collection methods, read straight off the alert: `hosts_local_admin` is `NetLocalGroupGetMembers` (who is a local admin where), `hosts_logged_on` is `NetWkstaUserEnum` (where is the target user logged on), `hosts_sessions` is `NetSessionEnum`, `hosts_registry` the registry read. All four high means `-c All`; `hosts_local_admin` alone is the collection that precedes lateral-movement planning.

`sample_hosts` is bounded and alphabetical, not "the most interesting ten"; the pivot in **When it fires** lists the rest.

## If you also need `-c Session`
A session-only run opens one interface per host, so it fails the per-host test. Drop that stage and keep the fan-out, which costs precision - `net view` sweeps and inventory scripts look the same:
```esql
| STATS hosts_enumerated = COUNT(*), sample_hosts = TOP(host.name, 10, "asc"),
        first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
    BY user.name
| WHERE hosts_enumerated >= 15
```
Run it as a second rule rather than widening this one: two questions, two thresholds, and the analyst can tell which fired.

## Baseline
Over 7 days at the rule's window, same two stages, nothing filtered before the last `STATS` - a pre-filter would hide every account the threshold has to clear. Percentiles over active buckets only.
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
| STATS pipes_on_host = COUNT_DISTINCT(winevt.event_data.relative_target_name) BY user.name, host.name, bucket
| WHERE pipes_on_host >= 2
// second STATS: hosts per account per quarter hour, the metric the rule's threshold is set on
| STATS hosts = COUNT(*) BY user.name, bucket
// this is the baseline: no threshold on `hosts` here, because filtering first would hide the accounts
// this query exists to measure
| STATS active_buckets = COUNT(*), p50 = PERCENTILE(hosts, 50), p99 = PERCENTILE(hosts, 99),
        peak = MAX(hosts), hot_buckets = COUNT(*) WHERE hosts >= 10
    BY user.name
| SORT peak DESC
| LIMIT 50
```
`p50` and `p99` at 1-2 with a `peak` in the hundreds is a collector. A `peak` of 100+ every day is an inventory or monitoring product: exclude it as an account + address pair - and note that it means your estate opens these interfaces routinely, which is worth knowing on its own.

## Before turning it on
- **Audit Detailed File Share (5145) must be on for every host you want to count** - workstations as well as servers. The rule cannot count what it cannot see, and a server-only audit makes a workstation sweep look small.
- Check the interface mix your estate actually produces:
```esql
FROM logs-yourorg-microsoft-windows*
// leading wildcard for the same reason as the rule: ShareName masks the server name
| WHERE event.code == "5145" AND winevt.event_data.share_name LIKE "*\\IPC$"
| STATS n = COUNT(*), hosts = COUNT_DISTINCT(host.name) BY winevt.event_data.relative_target_name
| SORT n DESC
| LIMIT 25
```
- Check the subject field name: `user.name` (ECS) or `winevt.event_data.subject_user_name` (what 15 uses).
- The machine-account exclusion is what keeps agents out. If your monitoring product runs as a **user** account, it will be in the baseline's top rows - exclude that account plus its address rather than raising the threshold.
- Suppress by `user.name`: it is the entity that survives both reduces, and a re-run of the same sweep folds into one alert.

## What it misses
- **`-c Session` alone** (one interface per host) - the variant above. Deliberately out of this rule.
- **Hosts whose 5145 you do not collect** - 24 is the transport-independent backstop, 08b the directory-side one.
- **A sweep split across accounts or collector hosts**, each under the threshold. The entity is the account; that case needs a destination-side view (5156 on the targets).
- **SOAPHound and any ADWS-based collector**: it may open no SMB pipe at all and may not appear as an LDAP search - 24 flags `directory_sweep_adws` for that path.
- **Collection through a share you already alert on**: Snaffler-class file hunting is 10. The two rules should not both fire for one activity; if they do, the actor was doing both.

## When it fires
1. Identify `user.name`: a normal user account means the collector ran with that user's token - the user ran it, or the credential is stolen. Assume the second until it is explained.
2. Read the four `hosts_*` counts for which collection methods ran, and `sample_hosts` for whether it was the server tier or the whole estate.
3. Name the host and binary with Falcon for one address; SharpHound's pipe traffic is SMB through the kernel, so the process shows as `System`. The LDAP half of the same run is what 24 and 08b see.
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
No rows means the address is not a managed host: the attacker's own machine, or a device behind a proxy - check 05 on the hosts around it.
