---
id: B01
name: Horizontal network scan (one host reaching many hosts)
category: behaviour
status: todo
severity: high
language: esql
index: logs-crowdstrike.fdr-*
mitre: [T1046, T1018]
data_source: CrowdStrike FDR network connection events
suppression:
  fields: [host.name, process.name]
  duration: 1h
  missing_fields: do_not_suppress
---
## Why this is behavioural and high fidelity
This does not look for a tool name. It looks for the shape of scanning: one process on one host opening connections to a large number of distinct destinations in a short window. That shape is the same whether the operator runs nmap, masscan, rustscan, a renamed binary, or a custom script, so renaming the tool does not evade it. Ordinary clients talk to a handful of servers in five minutes, not a hundred.

## Query
Run every 5 minutes with a 10-minute lookback.
```esql
FROM logs-crowdstrike.fdr-*
| WHERE event.category == "network" AND network.direction IN ("egress", "outbound")
  AND destination.ip IS NOT NULL
| STATS dst_hosts = COUNT_DISTINCT(destination.ip),
        dst_ports = COUNT_DISTINCT(destination.port),
        conns = COUNT(*),
        sample_ports = VALUES(destination.port)
    BY host.name, process.name, user.name, BUCKET(@timestamp, 5 minutes)
| WHERE dst_hosts >= 100
```
Confirm the connection event name your CrowdStrike feed uses (often `NetworkConnectIP4`) and that `network.direction` is populated; if not, filter on the connect `event.action` instead. Tune the threshold to your largest legitimate fan-out.

## Suppression
Suppress by `host.name`, `process.name` for 1h. Alerts missing a key field are not suppressed. Aggregating rule. A scan spans several buckets, and a different host or process still alerts.

## Known false positives / exclusions
- Vulnerability scanners, asset discovery and monitoring. These are few and named; exclude them by `host.name` and `process.name` written inline in the WHERE clause, not a lookup.
- Load balancers, proxies and backup servers that fan out by design. Exclude those hosts the same way.

## Triage
- Identify the process and user. A browser or system service is likely benign fan-out; a shell, script interpreter or an unsigned binary scanning 100+ hosts is reconnaissance.
- Check the destination ports: a single port across many hosts is service discovery; many ports is a full scan. Pivot to the host for how the process got there.

## Test
Run a scan of a lab subnet from a lab host and confirm the rule fires on the connection count.
