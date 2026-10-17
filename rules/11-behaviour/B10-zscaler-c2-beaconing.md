---
id: B10
name: Steady beaconing to an uncategorised or newly registered domain, by at most three users (Zscaler)
category: behaviour
status: todo
severity: high
language: esql
index: logs-zscaler_zia.web-*
mitre: [T1071.001]
data_source: Zscaler ZIA web logs
suppression:
  fields: [who, domain]
  duration: 24h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
An implant checks in with its controller like a clock: small, regular requests hour after hour. A person browses in bursts and gaps. The rule looks for a user whose traffic to one domain is present in nearly every five-minute slot for hours, on a domain few others use that way.

It has one anchor, one corroborating property and one exclusion, with no domain allowlist:
- **Anchor:** allowed requests to domains Zscaler has no reputation for ("Miscellaneous or Unknown" or "Newly Registered Domains"). Fresh C2 domains sit here, and the filter cuts the volume to a small fraction of web traffic.
- **Corroborating property:** steady presence. The user must be active in 72 of the 96 five-minute slots in the 8-hour window, averaging two or more requests per active slot.
- **Exclusion by rarity:** a domain that more than three users beacon to is a shared app polling, not an implant, so it drops out with no list to maintain.

B06 is the endpoint view of the same behaviour: the process and destination IP, seen by Falcon. This rule sees the user and the domain at the proxy.

## Query
Run hourly with an 8-hour lookback. The lookback is part of the logic: `active_slots >= 72` out of the 96 slots in 8 hours is what makes this a regularity test. Over a longer lookback it only means "busy for 6 hours at some point".
```esql
FROM logs-zscaler_zia.web-*
| WHERE event.action == "allowed" AND url.domain IS NOT NULL
  AND zscaler_zia.web.url.category.sub IN ("Miscellaneous or Unknown", "Newly Registered Domains")
| EVAL who = TO_LOWER(user.name), domain = TO_LOWER(url.domain), slot = DATE_TRUNC(5 minutes, @timestamp)
| STATS requests = COUNT(*), active_slots = COUNT_DISTINCT(slot), path = VALUES(url.path),
        first_seen = MIN(@timestamp), last_seen = MAX(@timestamp),
        user_agents = VALUES(user_agent.original), dest_ips = VALUES(destination.ip),
        dest_geo = VALUES(destination.geo.country_name),
        urlcat = VALUES(zscaler_zia.web.url.category.sub), urlclass = VALUES(zscaler_zia.web.url.class)
    BY who, domain
| EVAL span_hours = ROUND(DATE_DIFF("minute", first_seen, last_seen) / 60.0, 1),
       avg_per_slot = ROUND(TO_DOUBLE(requests) / active_slots, 1)
| WHERE active_slots >= 72 AND avg_per_slot >= 2
// prevalence: how many users pass the beacon checks for the same domain
| INLINE STATS beaconing_users = COUNT_DISTINCT(who) BY domain
| WHERE beaconing_users <= 3
| KEEP who, domain, path, requests, active_slots, span_hours, avg_per_slot, beaconing_users,
       first_seen, last_seen, user_agents, dest_ips, dest_geo, urlcat, urlclass
```
`beaconing_users` is counted after the beacon checks, not in the same `STATS`. Counted per user, it's always 1 and the rarity filter does nothing. There's no `SORT` / `LIMIT`: sorting by request count would cut the quietest, most beacon-like rows first.

## Suppression
Suppress by `who`, `domain` for 24h. Alerts missing a key field are not suppressed. Aggregating rule: each hourly run overlaps the last seven hours, and a live beacon is found on every run, so the repeats fold into the open alert.

## Known false positives / exclusions
- A niche app used by one to three people that polls an uncategorised domain all day, such as a vendor portal with a keep-alive. Rarity can't remove an app with so few users. Exclude that domain by exact name in the first `WHERE`, after confirming it.
- Early in the day, an app most staff use can show only the one to three users who've been active for six hours. It drops out once more users qualify. If it alerts every morning, exclude it the same way.
- `avg_per_slot >= 2` drops beacons that sleep between about 2.5 and 5 minutes, which check in once per slot. Lower it to 1 if the noise allows.
- Out of scope: C2 on a categorised domain (a compromised site, a cloud front). B06 sees those on the endpoint.

## Triage
- Read `path` and `user_agents`. One path repeated, or random-looking paths, at a fixed cadence is a beacon. A non-browser user agent, or a browser string that doesn't match the user's browser, is a program calling out, not the user.
- Find the process on the user's host in FDR: the `NetworkConnectIP4` events to `dest_ips`, or the `DnsRequest` events for `domain`. Check that process and its parent; if it isn't a known app, isolate the host and block the domain in Zscaler.

## Test
On a lab host routed through Zscaler, request an uncategorised test domain every 60 seconds for seven hours, for example `while true; do curl -s https://<test-domain>/c; sleep 60; done`. It should alert once the 72-slot mark is crossed, and not before.
