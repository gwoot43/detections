---
id: B11
name: Zscaler beaconing — domains that already have a reputation (compromised site, fronting, repurposed SaaS)
category: behaviour
status: todo
language: esql
index: logs-zscaler_zia.web-*
mitre: []
data_source: CrowdStrike FDR / Windows Security events
suppression:
  fields: [host.id]
  duration: 24h
  missing_fields: do_not_suppress
---
The other half of the beacon problem, and the one the category filter cannot see. When C2 rides a **compromised legitimate site**, a **CDN used for fronting**, or a **repurposed SaaS endpoint**, the domain carries its real reputation - business, news, technology - so nothing about the destination is unusual. What is unusual is the **shape of one user's session compared with everyone else's on the same domain**: the fleet opens it like a browser, one account polls it like a machine.

That contrast is the whole rule, and it is the reason this belongs in its own file rather than in a wider category list:

- **Anchor:** allowed, decrypted traffic to a domain that *does* have a reputation, and that at least five users in the estate reach - so browser traffic is normal traffic.
- **Corroborating property:** this user's session is machine-shaped (one or two fixed URIs, one user agent, no referrer chain) and fetches a third of what a normal session on that domain fetches, sustained across many hours.
- **Exclusion by construction:** the domain-level counts come before the shape test, so the domain itself is never the thing being judged.

```esql
FROM logs-zscaler_zia.web-*
// 72-hour window: the persistence tests need it.
| WHERE @timestamp >= NOW() - 72 hours
  AND event.action == "allowed" AND url.domain IS NOT NULL AND url.path IS NOT NULL
// The opposite population to the unknown-domain rule: domains that DO carry a reputation.
  AND zscaler_zia.web.url.category.sub NOT IN ("Miscellaneous or Unknown", "Newly Registered Domains")
// BYOD users have no access to the corporate network (placeholder prefix).
  AND (user.name IS NULL OR NOT user.name LIKE "<byod_user_prefix>*")
// Windows Update peer-to-peer delivery polls steadily.
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
// The fleet's own shape on that domain, window-wide: how many people reach it, and how varied a normal
// session there is. This is what makes the domain's reputation irrelevant.
| INLINE STATS domain_users = COUNT_DISTINCT(user.name), domain_avg_uris = AVG(uris) BY url.domain
// Shared site, but this account barely touches it and never like a browser: a third of the usual breadth,
// one user agent, no referrer, across a dozen or more hours. 5 users and 12 hours are starting values -
// measure the fleet baseline per domain (p50/p99 of uris) before tuning.
| WHERE domain_users >= 5
  AND uris::double * 3 < domain_avg_uris
  AND ua_variants = 1 AND referrer_hits = 0
  AND hours >= 12 AND slots >= 24
| SORT hours DESC, requests DESC
| LIMIT 100
```

Run every hour with a 72-hour lookback, or daily over 72 hours. Suppress by `user.name` + `url.domain` for 24h.

## What the nearest benign twin is
A **legitimate machine client of a real service**: an agent polling a vendor API, a licence heartbeat, a backup tool talking to its cloud, an EDR check-in. One URI, one user agent, no referrer, hours of slots - exactly this shape, on a domain with a reputation. Three ways to separate them, best first:

1. **First-seen on the URI, per domain** - a 30-day transform recording which URIs the estate has already requested on that domain. A vendor API path is familiar; `/wp-content/plugins/<random>/gate.php` on a news site is not. This is the strongest version and the one to build towards.
2. **Exclude by entity pair** - `host.name` + `url.domain` for each agent the baseline turns up, never a domain on its own.
3. **Narrow the categories** to the ones a compromised site actually sits in (news, business, technology, uncategorised-but-trusted), which removes most vendor API domains before the shape test runs.

## What it misses
- **A beacon on a domain fewer than five users reach** - that is the unknown-domain rule's population, and deliberately not this one's.
- **C2 that imitates a browser** on the compromised site: fetching assets, several paths, a referrer. The shape test is defeated by design, and only the URI-level first-seen test above survives that.
- **Anything Zscaler does not decrypt** - uninspected CONNECTs never reach this index, so a pinned-TLS callback to a legitimate domain is invisible here and in the unknown-domain rule.
- **Low-and-slow below 12 distinct hours** across the window.

## References
- B10 in `rules/11-behaviour/` - the unknown-domain rule this complements; the two are disjoint on population, not on threshold
- `zscaler-c2-beacon-unknown-domain.md` - the same shape test on domains with no reputation
- `docs/DETECTION-STRUCTURE-ESQL.md` - funnel shape, rarity-before-threshold, baseline discipline
