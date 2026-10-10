---
id: B01
name: Horizontal network scan - catches nmap, masscan, rustscan by behaviour
category: behaviour
status: todo
severity: high
language: esql
index: logs-crowdstrike.fdr-*
mitre: [T1046, T1018]
data_source: CrowdStrike FDR network connection events
suppression:
  fields: [host.id, process.name]
  duration: 1h
  missing_fields: do_not_suppress
---
## Why this is behavioural and high fidelity
This does not look for a tool name. It looks for the shape of scanning: one process on one host opening connections to a large number of distinct internal destinations in a short window. That shape is the same whether the operator runs nmap, masscan, rustscan, a renamed binary, or a custom script, so renaming the tool does not evade it. Ordinary clients talk to a handful of servers in five minutes, not a hundred.

## Query
Run every 5 minutes with a 10-minute lookback.
```esql
FROM logs-crowdstrike.fdr-*
| WHERE event.action == "NetworkConnectIP4" AND destination.ip IS NOT NULL
  // internal targets only: browsers and SaaS clients reach hundreds of internet addresses in minutes
  AND CIDR_MATCH(destination.ip, "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
| EVAL process.name = TO_LOWER(COALESCE(process.name, "unknown"))
// exclude vulnerability scanners, discovery and monitoring servers here, e.g. AND host.name NOT IN ("nessus01", "prtg01")
| STATS dst_hosts = COUNT_DISTINCT(destination.ip),
        dst_ports = COUNT_DISTINCT(destination.port),
        conns = COUNT(*),
        sample_ports = VALUES(destination.port),
        host.name = VALUES(host.name)
    BY host.id, process.name, BUCKET(@timestamp, 5 minutes)
| WHERE dst_hosts >= 100
```
FDR connection events name the process only on sensors that send `ContextBaseFileName`; otherwise `process.name` reads `unknown` and the row covers every process on the host. Tune the threshold to your largest legitimate internal fan-out.

## Suppression
Suppress by `host.id`, `process.name` for 1h. Alerts missing a key field are not suppressed. Aggregating rule. A scan spans several buckets, and a different host or process still alerts. `host.id` is the Falcon agent ID and is always present; `host.name` is filled only when the integration's host metadata enrichment is on, so it is an output column, not a key.

## Known false positives / exclusions
- Vulnerability scanners, asset discovery and monitoring. These are few and named; exclude them by host and `process.name` written inline in the WHERE clause, not a lookup.
- Load balancers, proxies and backup servers that fan out by design. Exclude those hosts the same way.

## Triage
- Identify the process and user. A browser or system service is likely benign fan-out; a shell, script interpreter or an unsigned binary scanning 100+ hosts is reconnaissance.
- Check the destination ports: a single port across many hosts is service discovery; many ports is a full scan. Pivot to the host for how the process got there.

## Test
Run a scan of a lab subnet from a lab host and confirm the rule fires on the connection count.
