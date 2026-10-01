---
id: B02
name: Vertical port scan - catches nmap and other port scanners by behaviour
category: behaviour
status: todo
severity: medium
language: esql
index: logs-crowdstrike.fdr-*
mitre: [T1046]
data_source: CrowdStrike FDR network connection events
suppression:
  fields: [host.name, destination.ip]
  duration: 1h
  missing_fields: do_not_suppress
---
## Why this is behavioural and high fidelity
The companion to B01. Instead of many hosts, this is many ports against one target: the pattern of enumerating a single machine's services before attacking it. It is defined by the count of distinct destination ports from one process to one destination, so it catches any scanner by behaviour.

## Query
Run every 5 minutes with a 10-minute lookback.
```esql
FROM logs-crowdstrike.fdr-*
| WHERE event.category == "network" AND network.direction IN ("egress", "outbound")
  AND destination.ip IS NOT NULL AND destination.port IS NOT NULL
| STATS dst_ports = COUNT_DISTINCT(destination.port),
        conns = COUNT(*),
        ports = VALUES(destination.port)
    BY host.name, process.name, user.name, destination.ip, BUCKET(@timestamp, 5 minutes)
| WHERE dst_ports >= 50
```

## Suppression
Suppress by `host.name`, `destination.ip` for 1h. Alerts missing a key field are not suppressed. Aggregating rule. A sweep spans buckets; a new target still alerts.

## Known false positives / exclusions
- Monitoring that probes many ports on a host it watches. Exclude the monitoring host and process inline.
- Some applications open many ephemeral ports to one server; those are high ports in a tight range rather than the low, well-known ports a scanner walks. If this causes noise, add `AND destination.port < 10000` to focus on service ports.

## Triage
- Confirm the process and whether the target is a server the host should be talking to at all. Combine with B01: a host doing both horizontal and vertical scans is active reconnaissance.

## Test
Run a full-port scan against one lab host from a lab machine.
