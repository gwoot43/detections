---
id: N10
name: External scanning against the F5/Imperva edge, or internal port-scan fan-out
category: network
status: todo
severity: medium
language: esql
index: logs-zscaler_zia.firewall-*, logs-imperva_cloud_waf.event-*
mitre: [T1595.001, T1046, T1210]
data_source: Zscaler ZIA firewall logs (internal branch; add internal firewall/flow logs) and Imperva Cloud WAF events (edge branch)
suppression:
  fields: [src]
  duration: 1h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
Two branches. External: a single source touching many distinct URIs or hostnames on the edge in a short window is reconnaissance ahead of exploitation. Internal: one internal host connecting to many distinct internal hosts on the same port in a short window is lateral scanning, which precedes lateral movement (W08).

## Query (internal fan-out)
```esql
FROM logs-zscaler_zia.firewall-*   // ZIA only logs traffic forwarded to Zscaler: add your internal firewall/flow data streams here
| WHERE event.category == "network" AND destination.ip IS NOT NULL
| EVAL src = source.ip,
       // Zscaler firewall appends both the client-side and server-side destination port (cdport, sdport),
       // so destination.port can be multi-valued; take one value so each connection is counted once
       dport = MV_MIN(destination.port)
// keep RFC1918 to RFC1918 only
| WHERE CIDR_MATCH(source.ip, "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
  AND CIDR_MATCH(destination.ip, "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
| STATS dst_hosts = COUNT_DISTINCT(destination.ip), conns = COUNT(*)
    BY src, dport, BUCKET(@timestamp, 10 minutes)
| WHERE dst_hosts >= 50
```
There is no `network.direction` filter. None of the Zscaler ZIA data streams set `network.direction`, so filtering on it dropped every event. The RFC1918-to-RFC1918 `CIDR_MATCH` is what scopes the query to internal traffic.

External edge branch:
```esql
FROM logs-imperva_cloud_waf.event-*
| EVAL src = source.ip
| STATS uris = COUNT_DISTINCT(url.path), hosts = COUNT_DISTINCT(url.domain), hits = COUNT(*)
    BY src, BUCKET(@timestamp, 5 minutes)
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
