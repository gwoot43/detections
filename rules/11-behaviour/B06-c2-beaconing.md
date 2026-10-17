---
id: B06
name: C2 beaconing - catches Cobalt Strike, Sliver, Mythic, Havoc, Brute Ratel by behaviour
category: behaviour
status: todo
severity: high
language: esql
index: logs-crowdstrike.fdr-*
mitre: [T1071.001, T1573, T1095]
data_source: CrowdStrike FDR network connection events
suppression:
  fields: [host.id, process.name, destination.ip]
  duration: 24h
  missing_fields: do_not_suppress
---
## Why this is behavioural and high fidelity
An implant calls home on a schedule: the same process on the same host connects to one external address again and again, spread evenly across time, whatever framework built it. The rule measures that cadence on the endpoint, so it needs no signature or reputation list.

- **Anchor:** outbound connections to public addresses, leaving out DNS and NTP (they poll on a schedule by design) and browsers. Browser traffic is judged at the proxy by B10, which sees the URL.
- **Corroborating property:** regularity. 30 or more connections over at least an hour, filling most of the minutes they could.
- **Exclusion by rarity:** the address must be reached by at most three hosts. Update services, Microsoft 365 and security-agent clouds are reached by most of the fleet, so they drop out with no list of process names to keep.

## Query
Run hourly with a 3-hour lookback.
```esql
FROM logs-crowdstrike.fdr-*
// Anchor: outbound connections to public addresses. DNS and NTP poll public servers on a fixed schedule by design.
| WHERE event.action IN ("NetworkConnectIP4", "NetworkConnectIP6") AND destination.ip IS NOT NULL
  AND destination.port NOT IN (53, 123)
  AND NOT CIDR_MATCH(destination.ip, "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "100.64.0.0/10",
                     "224.0.0.0/4", "::1/128", "fc00::/7", "fe80::/10")
| EVAL process.name = TO_LOWER(COALESCE(process.name, "unknown"))
// Browser traffic is judged at the proxy by B10, which sees the URL. This rule is for every other process.
| WHERE process.name NOT IN ("chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "msedgewebview2.exe")
// One row per host, process and destination: connections, the distinct minutes they fell in, and when.
| STATS conns = COUNT(*), active_minutes = COUNT_DISTINCT(DATE_TRUNC(1 minute, @timestamp)),
        first_seen = MIN(@timestamp), last_seen = MAX(@timestamp), host.name = VALUES(host.name)
    BY host.id, process.name, destination.ip, destination.port
// Rarity: every host that reached this address, counted before the beacon checks.
// Shared services reached by most of the fleet drop out here.
| INLINE STATS dst_hosts = COUNT_DISTINCT(host.id) BY destination.ip
// A beacon fills one minute per connection when it sleeps a minute or more, and every minute when it's faster,
// so dividing by the smaller of the two scores both near 1. A burst packed into a few minutes scores low.
| EVAL span_minutes = (last_seen::long - first_seen::long) / 60000,
       beacon_regularity = ROUND(active_minutes::double / LEAST(conns, span_minutes + 1), 2),
       avg_interval_minutes = ROUND(span_minutes::double / conns, 1)
// Beacon: 30+ connections over an hour or more, regular, to an address at most 3 hosts reach.
| WHERE conns >= 30 AND active_minutes >= 20 AND span_minutes >= 60 AND beacon_regularity >= 0.6 AND dst_hosts <= 3
| KEEP host.id, host.name, process.name, destination.ip, destination.port, dst_hosts, conns, active_minutes,
       span_minutes, beacon_regularity, avg_interval_minutes, first_seen, last_seen
```

**CrowdStrike (Falcon LogScale / Advanced Event Search)**, run over the last 3 hours:
```logscale
#event_simpleName=/^(NetworkConnectIP4|NetworkConnectIP6)$/
// Anchor: outbound connections to public addresses. DNS and NTP poll public servers on a fixed schedule by design.
| dst := coalesce([RemoteAddressIP4, RemoteAddressIP6])
| dst=*
| !in(field="RemotePort", values=["53", "123"])
| !cidr(dst, subnet=["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "100.64.0.0/10",
                     "224.0.0.0/4", "::1/128", "fc00::/7", "fe80::/10"])
| pname := lower(ContextBaseFileName)
| default(field=pname, value="unknown", replaceEmpty=true)
// Browser traffic is judged at the proxy by B10, which sees the URL. This rule is for every other process.
| !in(field="pname", values=["chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "msedgewebview2.exe"])
// One row per host, process and destination.
| minute := @timestamp - (@timestamp % 60000)
| groupBy([aid, pname, dst, RemotePort], function=[count(as=conns), count(minute, distinct=true, as=active_minutes),
                                                  min(@timestamp, as=first_seen), max(@timestamp, as=last_seen),
                                                  collect([ComputerName])], limit=max)
// Regularity, as in the ES|QL: minutes used, divided by the smaller of connections and minutes available.
| span_minutes := (last_seen - first_seen) / 60000
| span_minutes := math:floor(span_minutes)
| possible := span_minutes + 1
| case { test(conns < possible) | possible := conns; * ; }
| beacon_regularity := active_minutes / possible
// Mark the beacon-shaped rows. Every row still counts towards rarity below.
| case {
    test(conns >= 30 AND active_minutes >= 20 AND span_minutes >= 60 AND beacon_regularity >= 0.6)
      | beacon := format("%s %s port %s: %s connections, regularity %.2f", field=[aid, pname, RemotePort, conns, beacon_regularity]);
    * ;
  }
// Rarity: one row per address, counting every host that reached it. Keep addresses with a beacon and at most 3 hosts.
| groupBy([dst], function=[count(aid, distinct=true, as=dst_hosts), collect([beacon, ComputerName])], limit=max)
| test(dst_hosts <= 3)
| beacon=*
```
LogScale has no `INLINE STATS`, so this version rolls up to one row per destination address, listing each beacon on it (host, process, port, connections, regularity) and the names of the at most three hosts that reached it.

This is an approximation, not a true jitter analysis; a long-interval or high-jitter beacon can still slip under it. FDR connection events name the process only on sensors that send `ContextBaseFileName`. Otherwise `process.name` reads `unknown`, and every process on the host is counted together for that destination.

## Suppression
Suppress by `host.id`, `process.name`, `destination.ip` for 24h. Alerts missing a key field are not suppressed. Aggregating rule. A beacon runs for days; a new destination still alerts. `host.id` is the Falcon agent ID and is always present; `host.name` is filled only when the integration's host metadata enrichment is on.

## Known false positives / exclusions
- A scheduled agent or script on one to three hosts that polls its own vendor (a licence check, a niche monitoring agent). Rarity can't remove it. Exclude it by exact process name and destination once confirmed.
- A busy service whose addresses rotate across a CDN can show few hosts per address. If one keeps alerting, exclude it the same way.

## Triage
- Look at the process, the destination and `avg_interval_minutes` (the approximate sleep time). An unsigned binary or a script interpreter beaconing to a hosting provider or a newly registered domain is C2. Pivot to Zscaler (B10, N07) for the domain and its reputation, then isolate the host.

## Test
Run a benign agent that connects to a lab server every 30 seconds for an hour, then one every 2 minutes for three hours, and confirm both fire.
