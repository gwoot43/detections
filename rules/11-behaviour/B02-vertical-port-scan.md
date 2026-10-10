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
  fields: [host.id, destination.ip]
  duration: 1h
  missing_fields: do_not_suppress
---
## Why this is behavioural and high fidelity
The companion to B01. Instead of many hosts, this is many ports against one target: the pattern of enumerating a single machine's services before attacking it. It is defined by the count of distinct destination ports from one process to one destination, so it catches any scanner by behaviour.

## Query
Run every 5 minutes with a 10-minute lookback.
```esql
FROM logs-crowdstrike.fdr-*
| WHERE event.action == "NetworkConnectIP4" AND destination.ip IS NOT NULL AND destination.port IS NOT NULL
  AND CIDR_MATCH(destination.ip, "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
  // service ports only: RPC dynamic ports, FTP passive data ports and backup data movers use high ranges
  AND destination.port < 10000
| EVAL process.name = TO_LOWER(COALESCE(process.name, "unknown"))
| STATS dst_ports = COUNT_DISTINCT(destination.port),
        conns = COUNT(*),
        ports = VALUES(destination.port),
        host.name = VALUES(host.name)
    BY host.id, process.name, destination.ip, BUCKET(@timestamp, 5 minutes)
| WHERE dst_ports >= 50
```
FDR connection events name the process only on sensors that send `ContextBaseFileName`; otherwise `process.name` reads `unknown` and the row covers every process on the host.

## Suppression
Suppress by `host.id`, `destination.ip` for 1h. Alerts missing a key field are not suppressed. Aggregating rule. A sweep spans buckets; a new target still alerts. `host.id` is the Falcon agent ID and is always present; `host.name` is filled only when the integration's host metadata enrichment is on, so it is an output column, not a key.

## Known false positives / exclusions
- Monitoring that probes many ports on a host it watches. Exclude the monitoring host and process inline.
- Applications that open many high ports to one server (RPC dynamic ports, FTP passive mode, backup data movers) are excluded by counting only ports below 10000. A backup proxy that still trips this is excluded by host.

## Triage
- Confirm the process and whether the target is a server the host should be talking to at all. Combine with B01: a host doing both horizontal and vertical scans is active reconnaissance.

## Test
Run a full-port scan against one lab host from a lab machine.
