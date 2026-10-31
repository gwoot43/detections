# Zscaler beaconing — new and uncategorised domains (rework of B10)

An implant checks in like a clock for as long as the host is on, to a domain nobody has a reason to visit. The anchor is the domain population: **allowed, decrypted traffic to a domain Zscaler has no reputation for**, reached by at most three users, holding a machine-shaped session for days. That is B10's idea, kept; what changed is that the *shape* of the session now does the work and the request rate no longer gates it.

Three things were wrong in the B10 version and are fixed here:

- **`avg_per_slot >= 2` excluded the slow beacon.** A 5-minute-interval beacon produces exactly one request per occupied slot, so `avg/slot = 1` failed - and a 5-minute beacon is the most common commodity profile. Rate is now output, not a condition; persistence is measured in slots *and* hours.
- **The shape fields were collected and never used.** `uris`, `UA_variants` and `referrer_hits` are what separate a beacon from a browser, a dashboard and a document viewer. They are conditions now.
- **A slow beacon had nowhere to land.** `hours >= 36` over the 72-hour window is the second shape: it recovers the 30-minute and 2-hour beacons without lowering the bar for the fast ones.

```esql
FROM logs-zscaler_zia.web-*
// 72-hour window: the persistence tests below need it, so the schedule must not be shortened.
| WHERE @timestamp >= NOW() - 72 hours
  AND event.action == "allowed" AND url.domain IS NOT NULL AND url.path IS NOT NULL
// Anchor: domains Zscaler has no reputation for, where fresh C2 domains sit.
  AND zscaler_zia.web.url.category.sub IN ("Miscellaneous or Unknown", "Newly Registered Domains")
// BYOD users have no access to the corporate network (placeholder prefix).
  AND (user.name IS NULL OR NOT user.name LIKE "<byod_user_prefix>*")
// Windows Update peer-to-peer delivery polls steadily. IS NULL keeps requests with no user agent.
  AND (user_agent.original IS NULL OR NOT user_agent.original LIKE "Microsoft-Delivery-Optimization*")
| EVAL user.name = TO_LOWER(user.name), url.domain = TO_LOWER(url.domain),
       uri = CONCAT(COALESCE(http.request.method, "?"), "-",
                    COALESCE(TO_STRING(zscaler_zia.web.response.code), "?"), " ", url.path),
       has_referrer = http.request.referrer IS NOT NULL AND http.request.referrer != "-"
| STATS requests = COUNT(),
        slots = COUNT_DISTINCT(DATE_TRUNC(5 minutes, @timestamp)),
        hours = COUNT_DISTINCT(DATE_TRUNC(1 hour, @timestamp)),
        uris = COUNT_DISTINCT(uri),
        ua_variants = COUNT_DISTINCT(user_agent.original),
        referrer_hits = COUNT(*) WHERE has_referrer,
        sample_uris = MV_SLICE(VALUES(uri), 0, 10),
        user_agent.original = MV_SLICE(VALUES(user_agent.original), 0, 3),
        destination.ip = MV_SLICE(VALUES(destination.ip), 0, 5),
        destination.geo.country_name = MV_SLICE(VALUES(destination.geo.country_name), 0, 3),
        first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
    BY user.name, url.domain
// Rate is context, not a condition: references per occupied 5-minute slot. It has to be an EVAL after the
// STATS - an alias cannot be read inside the aggregation that creates it.
| EVAL avg_per_slot = ROUND(requests::double / slots, 2)
// Rarity window-wide, before the beacon checks: every user who reached the domain counts, so a site
// many people visit drops out even if only one of them left it open.
| INLINE STATS domain_users = COUNT_DISTINCT(user.name) BY url.domain
// A machine-shaped session: one or two fixed URIs, one user agent, no referrer chain. A browser breaks
// all three, a dashboard breaks the referrer, a document viewer breaks the URI count.
| WHERE uris <= 2 AND ua_variants = 1 AND referrer_hits = 0
  AND domain_users <= 3
// Persistence, in two shapes: a heartbeat of an hour or less (72 slots over 12+ hours), or a slower one
// that keeps coming back for 36+ distinct hours. Both are unreachable for an open tab. These four numbers
// are starting values - measure the p99 per user off the B10 baseline query before tuning.
  AND ((slots >= 72 AND hours >= 12) OR hours >= 36)
| SORT hours DESC, requests DESC
| LIMIT 100
```

Run every hour with a 72-hour lookback, or daily over 72 hours. Suppress by `user.name` + `url.domain` for 24h.

## Verify in the tenant before enabling
- **The category strings.** `"Miscellaneous or Unknown"` is tenant-configured, and `Newly Registered Domains` may live in `url.class` rather than `url.category.sub`. A wrong value returns zero rows silently - probe it:
```esql
FROM logs-zscaler_zia.web-*
| WHERE event.action == "allowed" AND @timestamp >= NOW() - 24 hours
| STATS n = COUNT(*) BY zscaler_zia.web.url.category.sub, zscaler_zia.web.url.class
| SORT n DESC
| LIMIT 25
```
- **The nearest benign twin.** A vendor update checker is one URI, one user agent, no referrer, 72 hours of slots: it passes every condition here. If you cannot name how your estate excludes it, this rule will be switched off in its first week. The fix is first-seen - a 30-day transform recording the first time each domain was seen in the estate, so only *new* domains qualify and every long-standing heartbeat falls out. Until that exists, expect to add a few `host + domain` exclusion pairs from the baseline.

## What it misses
- **Domains that carry a reputation** - a compromised legitimate site, domain fronting through a CDN, a pre-aged domain classified as business. That is the companion rule, `zscaler-c2-beacon-known-domain.md`.
- **Beacons that imitate a browser**: fetching assets, rotating paths and user agents, sending a referrer. Every condition above is defeated by ten lines of code.
- **Anything Zscaler does not decrypt.** CONNECTs with no path are handled by the other zproxy in this estate and never reach this index, so pinned-TLS C2 - a common choice - is invisible here. B06 is the endpoint view of the same behaviour.
- **A beacon on a domain 4+ users reach**, whether or not it is malicious.

## References
- B10 in `rules/11-behaviour/` - the rule this reworks, and its anchor/corroborator/exclusion reasoning
- N07, B06 - the Imperva and Falcon views of the same callback behaviour
- `docs/DETECTION-STRUCTURE-ESQL.md` - the funnel shape and the baseline rule this query follows
