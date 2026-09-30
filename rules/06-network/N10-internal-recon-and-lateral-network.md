---
id: N10
name: External scanning against the F5/Imperva edge, or internal port-scan fan-out
category: network
status: todo
severity: medium
language: esql
index: logs-*
mitre: [T1595.001, T1046, T1210]
data_source: F5/Imperva edge logs and internal firewall/flow logs
suppression:
  fields: [src]
  duration: 1h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
Two branches. External: a single source touching many distinct URIs or hostnames on the edge in a short window is reconnaissance ahead of exploitation. Internal: one internal host connecting to many distinct internal hosts on the same port in a short window is lateral scanning, which precedes lateral movement (W08).

## Query (internal fan-out; adjust index to your firewall/flow data)
```esql
FROM logs-*
| WHERE event.category == "network" AND destination.ip IS NOT NULL AND network.direction IN ("internal", "ingress", "egress")
| EVAL src = source.ip
// keep RFC1918 to RFC1918 only
| WHERE CIDR_MATCH(source.ip, "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
  AND CIDR_MATCH(destination.ip, "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
| STATS dst_hosts = COUNT_DISTINCT(destination.ip), ports = VALUES(destination.port), conns = COUNT(*)
    BY src, destination.port, BUCKET(@timestamp, 10 minutes)
| WHERE dst_hosts >= 50
```
External edge branch:
```esql
FROM logs-imperva.waf-*
| STATS uris = COUNT_DISTINCT(url.path), hosts = COUNT_DISTINCT(url.domain), hits = COUNT(*)
    BY source.ip, BUCKET(@timestamp, 5 minutes)
| WHERE hits >= 200 AND uris >= 100
```

## Suppression
Suppress by `src` for 1h. Alerts missing a key field are not suppressed. Aggregating rule. A scan spans many ports and buckets.

## Known false positives / exclusions
- Vulnerability scanners (Tenable, Qualys) and monitoring probes. Exclude their source IPs.
- Load balancers and legitimate service discovery. Exclude by source.

## Triage
- Internal fan-out from a workstation is never normal. Map the source IP to the host and user, isolate, and check for W08/W09 on that host.

## Test
Run a controlled `nmap` sweep from a lab host against a lab subnet.
