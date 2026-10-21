---
id: B10
name: Steady beaconing to an uncategorised or newly registered domain, by at most three users (Zscaler)
category: behaviour
status: todo
language: esql
index: logs-zscaler_zia.web-*
mitre: [T1071.001]
data_source: Zscaler ZIA web logs
suppression:
  fields: [user.name, url.domain]
  duration: 24h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
An implant checks in with its controller like a clock, hour after hour, for as long as the host is on. A person browses in bursts and gaps. The rule looks for a user whose traffic to one domain keeps coming back across many hours, on a domain hardly anyone else reaches.

It has one anchor, one corroborating property and one exclusion, with no domain allowlist:
- **Anchor:** allowed, decrypted requests to domains Zscaler has no reputation for ("Miscellaneous or Unknown" or "Newly Registered Domains"). Fresh C2 domains sit here, and the filter cuts the volume to a small fraction of web traffic.
- **Corroborating property:** sustained presence. At least 72 active five-minute slots, spread over at least 12 different hours, averaging two or more requests per active slot.
- **Exclusion by rarity:** a domain that more than three users reach at all is a shared site or app, not an implant. Every user who reached the domain counts, not only those who pass the beacon checks.

The 12-hour test is what separates a beacon from a browser tab. A news tab left open polls its ad and analytics domains as steadily as an implant, often more steadily, but only while it's open: an afternoon is six or seven active hours. Request rate doesn't separate the two, so beyond the floor of two per slot the rule doesn't use it, and a quiet beacon is caught as readily as a noisy one.

B06 is the endpoint view of the same behaviour: the process and destination IP, seen by Falcon. It also covers what this rule leaves out: traffic Zscaler doesn't decrypt.

## Query
Run hourly with a 48-hour lookback.
```esql
FROM logs-zscaler_zia.web-*
// Anchor: allowed traffic to domains Zscaler has no reputation for, where fresh C2 domains sit.
// Filtering here cuts the volume before any counting.
| WHERE event.action == "allowed" AND url.domain IS NOT NULL
  AND zscaler_zia.web.url.category.sub IN ("Miscellaneous or Unknown", "Newly Registered Domains")
  // No path means a CONNECT that Zscaler didn't decrypt: nothing to investigate at the proxy.
  AND url.path IS NOT NULL
  // BYOD users have no access to the corporate network (placeholder prefix).
  AND NOT TO_LOWER(COALESCE(user.name, "")) LIKE "<byod_user_prefix>*"
  // Windows Update peer-to-peer delivery polls steadily. IS NULL keeps requests with no user agent.
  AND (user_agent.original IS NULL OR NOT user_agent.original LIKE "Microsoft-Delivery-Optimization*")
// Method, response code and path as one value (GET-200 /api/x), so the alert shows the beacon's pattern.
| EVAL user.name = TO_LOWER(user.name), url.domain = TO_LOWER(url.domain),
       uriPath = CONCAT(COALESCE(http.request.method, "?"), "-", COALESCE(TO_STRING(zscaler_zia.web.response.code), "?"), " ", url.path)
// One row per user and domain. Slots are 5-minute windows with traffic; hours are clock hours with traffic.
| STATS requests = COUNT(), active_slots = COUNT_DISTINCT(DATE_TRUNC(5 minutes, @timestamp)),
        active_hours = COUNT_DISTINCT(DATE_TRUNC(1 hour, @timestamp)), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp),
        uri.path = VALUES(uriPath), uripaths = COUNT_DISTINCT(uriPath), http.request.referrer = VALUES(http.request.referrer),
        user_agent.original = VALUES(user_agent.original), uaCount = COUNT_DISTINCT(user_agent.original),
        destination.ip = VALUES(destination.ip), destination.geo.country_name = VALUES(destination.geo.country_name),
        urlcat = VALUES(zscaler_zia.web.url.category.sub), urlclass = VALUES(zscaler_zia.web.url.class)
    BY user.name, url.domain
// Rarity: every user who reached the domain, counted before the beacon checks,
// so a site many people visit drops out even if only one of them left it open.
| INLINE STATS domain_users = COUNT_DISTINCT(user.name) BY url.domain
// Average requests per active slot. ::double stops whole-number division (445 / 82 gives 5.4, not 5).
| EVAL avg_per_slot = ROUND(requests / active_slots::double, 1)
// Beacon: 72+ active slots spread over 12+ hours (a tab left open for an afternoon is about 7),
// 2+ requests per slot, on a domain at most 3 users reach.
| WHERE active_slots >= 72 AND active_hours >= 12 AND avg_per_slot >= 2 AND domain_users <= 3
// Key columns first, then everything else.
| KEEP user.name, url.domain, domain_users, requests, active_slots, active_hours, avg_per_slot, *
```
- In `uri.path`, steady GETs to poll and POSTs to send results back is a beacon. `uripaths` near 1 is a fixed profile (Cobalt Strike style); hundreds is a profile that randomises its paths (Sliver), or browsing.
- The Elastic Zscaler integration keeps the response code in `zscaler_zia.web.response.code`. If your pipeline maps it to `http.response.status_code`, use that.

## Suppression
Suppress by `user.name`, `url.domain` for 24h. Alerts missing a key field are not suppressed. Aggregating rule: each hourly run overlaps the previous 47 hours, and a live beacon is found on every run, so the repeats fold into the open alert.

## Known false positives / exclusions
- A web app tab left open for more than a working day, polling an analytics or keep-alive domain of a SaaS app that one to three people use. Rarity can't remove it. Once confirmed, exclude that domain by exact name in the first `WHERE`.
- A browser tab left open for an afternoon (a news site's ad and analytics domains) is removed by the 12-hour test. One left open across two working days can pass; exclude it the same way.
- `avg_per_slot >= 2` drops beacons that sleep between about 2.5 and 5 minutes, which check in once per slot. Lower it to 1 if the noise allows.
- Out of scope: C2 on a categorised domain, or in traffic Zscaler doesn't decrypt. B06 sees both on the endpoint.

## Triage
- Read `uri.path`, `uripaths`, `uaCount` and `http.request.referrer`. A beacon usually sends no referrer and uses one user agent. A browser tab sends the page it's on as the referrer.
- Find the process on the user's host in FDR: the `NetworkConnectIP4` events to `destination.ip`, or the `DnsRequest` events for `url.domain`. Check that process and its parent; if it isn't a known app, isolate the host and block the domain in Zscaler.

## Test
On a lab host routed through Zscaler, request an uncategorised test domain every 60 seconds for 13 hours, for example `while true; do curl -s https://<test-domain>/c; sleep 60; done`. It should alert once it has been active in 12 different hours. A news site left open for an afternoon should not.
