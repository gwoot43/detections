---
id: B06
name: C2 beaconing - catches Cobalt Strike, Sliver, Mythic, Havoc, Brute Ratel by behaviour
category: behaviour
status: todo
severity: high
language: esql
index: logs-crowdstrike.fdr-*
mitre: [T1071, T1573, T1095]
data_source: CrowdStrike FDR network connection events
suppression:
  fields: [host.id, process.name, destination.ip]
  duration: 24h
  missing_fields: do_not_suppress
---
## Why this is behavioural and high fidelity
Command-and-control implants call home on a schedule. Cobalt Strike, Sliver, Mythic, Havoc and similar frameworks differ in signatures but share the behaviour: the same process on the same host connects to one external destination repeatedly, spread evenly across time, with low variation between connections. This rule approximates that cadence from connection counts per time bucket, so it does not depend on a signature or a destination reputation list.

## Query
Run hourly with a 3-hour lookback.
```esql
FROM logs-crowdstrike.fdr-*
| WHERE event.action IN ("NetworkConnectIP4", "NetworkConnectIP6") AND destination.ip IS NOT NULL
  // DNS and NTP poll public servers on a fixed schedule by design
  AND destination.port NOT IN (53, 123)
  AND NOT CIDR_MATCH(destination.ip, "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "100.64.0.0/10",
                     "224.0.0.0/4", "::1/128", "fc00::/7", "fe80::/10")
| EVAL process.name = TO_LOWER(COALESCE(process.name, "unknown"))
// browsers, Microsoft 365 clients and security agents poll the same endpoints all day
| WHERE process.name NOT IN ("chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "msedgewebview2.exe",
                             "teams.exe", "ms-teams.exe", "outlook.exe", "onedrive.exe",
                             "csfalconservice.exe", "mssense.exe", "msmpeng.exe", "falcon-sensor")
| EVAL minute = DATE_TRUNC(1 minute, @timestamp)
| STATS conns = COUNT(*),
        active_minutes = COUNT_DISTINCT(minute),
        min_ts = MIN(@timestamp),
        max_ts = MAX(@timestamp),
        host.name = VALUES(host.name)
    BY host.id, process.name, destination.ip, destination.port
| WHERE conns >= 30 AND active_minutes >= 20
| EVAL span_minutes = (max_ts::long - min_ts::long) / 60000
| WHERE span_minutes >= 60
| EVAL beacon_regularity = active_minutes::double / conns,
       avg_interval_minutes = span_minutes::double / conns
| WHERE beacon_regularity >= 0.6
```
The idea: a beacon produces roughly one connection per interval, so `active_minutes` is close to `conns` (regularity near 1) and the connections are spread over at least an hour rather than clustered. `avg_interval_minutes` gives the analyst the approximate sleep time. Tune the thresholds on your own traffic. This is an approximation, not a true jitter analysis; a long-interval or high-jitter beacon can still slip under it.

FDR connection events name the process only on sensors that send `ContextBaseFileName`. Otherwise `process.name` reads `unknown`, every process on the host is counted together for that destination, and the name exclusions above cannot apply.

## Suppression
Suppress by `host.id`, `process.name`, `destination.ip` for 24h. Alerts missing a key field are not suppressed. Aggregating rule. A beacon runs for days; a new destination still alerts. `host.id` is the Falcon agent ID and is always present; `host.name` is filled only when the integration's host metadata enrichment is on.

## Known false positives / exclusions
- Software update checks, telemetry, monitoring agents and chat clients poll on a schedule and look like beacons. Browsers, Microsoft 365 clients and the Falcon and Defender agents are excluded by name above; add your own monitoring agents the same way. DNS and NTP are excluded by port.
- SaaS keepalives from legitimate apps. Exclude by destination domain once identified.

## Triage
- Look at the process and destination. An unsigned binary or a script interpreter beaconing to a hosting or newly registered domain is C2. Pivot to Zscaler (N07) for the destination reputation and isolate the host.

## Test
Run a benign agent that connects to a lab server every 30 seconds for an hour and confirm the regularity branch fires.
