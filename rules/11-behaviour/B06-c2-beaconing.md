---
id: B06
name: C2 beaconing (regular outbound callbacks to one destination)
category: behaviour
status: todo
severity: high
language: esql
index: logs-crowdstrike.fdr-*
mitre: [T1071, T1573, T1095]
data_source: CrowdStrike FDR network connection events
suppression:
  fields: [host.name, process.name, destination.ip]
  duration: 24h
  missing_fields: do_not_suppress
---
## Why this is behavioural and high fidelity
Command-and-control implants call home on a schedule. Cobalt Strike, Sliver, Mythic, Havoc and similar frameworks differ in signatures but share the behaviour: the same process on the same host connects to one external destination repeatedly, spread evenly across time, with low variation between connections. This rule approximates that cadence from connection counts per time bucket, so it does not depend on a signature or a destination reputation list.

## Query
Run hourly with a 3-hour lookback.
```esql
FROM logs-crowdstrike.fdr-*
| WHERE event.category == "network" AND network.direction IN ("egress", "outbound")
  AND destination.ip IS NOT NULL
  AND NOT CIDR_MATCH(destination.ip, "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8")
| EVAL minute = DATE_TRUNC(1 minute, @timestamp)
| STATS conns = COUNT(*),
        active_minutes = COUNT_DISTINCT(minute),
        min_ts = MIN(@timestamp),
        max_ts = MAX(@timestamp),
        total_bytes = SUM(destination.bytes)
    BY host.name, process.name, destination.ip, destination.port
| WHERE conns >= 30 AND active_minutes >= 20
| EVAL span_minutes = (max_ts::long - min_ts::long) / 60000
| WHERE span_minutes >= 60
| EVAL beacon_regularity = active_minutes::double / conns,
       coverage = active_minutes::double / span_minutes
| WHERE beacon_regularity >= 0.6
```
The idea: a beacon produces roughly one connection per interval, so `active_minutes` is close to `conns` (regularity near 1), and the connections cover most of the window (`coverage` high) rather than clustering. Tune the thresholds on your own traffic. This is an approximation, not a true jitter analysis; a long-interval or high-jitter beacon can still slip under it.

## Suppression
Suppress by `host.name`, `process.name`, `destination.ip` for 24h. Alerts missing a key field are not suppressed. Aggregating rule. A beacon runs for days; a new destination still alerts.

## Known false positives / exclusions
- Software update checks, telemetry, monitoring agents and chat clients poll on a schedule and look like beacons. These are few and signed; exclude them inline by process name. A browser is noisy; consider excluding `chrome.exe`, `msedge.exe` and `firefox.exe` or scoping to non-browser processes.
- SaaS keepalives from legitimate apps. Exclude by destination domain once identified.

## Triage
- Look at the process and destination. An unsigned binary or a script interpreter beaconing to a hosting or newly registered domain is C2. Pivot to Zscaler (N07) for the destination reputation and isolate the host.

## Test
Run a benign agent that connects to a lab server every 30 seconds for an hour and confirm the regularity branch fires.
