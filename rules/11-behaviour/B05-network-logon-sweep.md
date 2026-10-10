---
id: B05
name: Network logon sweep - catches CrackMapExec, NetExec and pass-the-hash lateral movement by behaviour
category: behaviour
status: todo
severity: high
language: esql
index: logs-system.security*, logs-windows.forwarded*
mitre: [T1021.002, T1550.002, T1078]
data_source: Windows Security event 4624 (logon type 3)
suppression:
  fields: [acct]
  duration: 2h
  missing_fields: do_not_suppress
---
## Why this is behavioural and high fidelity
The authentication side of a lateral sweep. CrackMapExec, NetExec, Impacket and pass-the-hash tooling authenticate one account against many machines quickly, which shows as network logons (type 3) for one account landing on many distinct destination hosts in a short window. Counting distinct destinations per account catches the behaviour regardless of the tool, and complements the network view in B04. A user account normally authenticates to a stable handful of servers.

## Query
Run every 10 minutes with a 15-minute lookback.
```esql
FROM logs-system.security*, logs-windows.forwarded*
| WHERE event.code == "4624" AND winlog.event_data.LogonType == "3"
| EVAL acct = TO_LOWER(winlog.event_data.TargetUserName),
       // with event forwarding host.name is the collector; the logging machine is in winlog.computer_name
       host_key = TO_LOWER(MV_FIRST(SPLIT(winlog.computer_name, ".")))
| WHERE NOT (acct LIKE "*$") AND acct NOT IN ("anonymous logon", "")
// add service and scanner accounts that legitimately fan out, e.g. AND acct NOT IN ("svc-scanner", "svc-backup")
| STATS dest_hosts = COUNT_DISTINCT(host_key),
        hosts = VALUES(host_key),
        src_ips = VALUES(source.ip),
        src_workstations = VALUES(source.domain)
    BY acct, BUCKET(@timestamp, 10 minutes)
| WHERE dest_hosts >= 15
```
This counts the distinct destination hosts (the machines logging the 4624) a single account reached. The System integration moves the source address to `source.ip` and the source workstation to `source.domain`. Exclude service accounts that legitimately fan out by name, inline.

## Suppression
Suppress by `acct` for 2h. Alerts missing a key field are not suppressed. Aggregating rule. A sweep spans buckets; a different account still alerts.

## Known false positives / exclusions
- Service and scanner accounts that authenticate broadly (vulnerability scanners, backup, monitoring). Exclude them inline by account name; machine accounts are already dropped.
- Admin accounts doing legitimate wide administration from a jump host. Correlate with B04 from the same source before escalating.

## Triage
- A normal user account authenticating to 15+ hosts in ten minutes is credential misuse. Reset the account, revoke sessions, and check the source host for credential dumping (B08) and the destinations for remote execution (W08).

## Test
Run an authentication sweep across lab hosts with one account and confirm the distinct-host count fires.
