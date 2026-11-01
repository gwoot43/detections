# Shared-cloud staging and C2 — reads from attacker-controlled subdomains of trusted parents

The download direction of the same problem. `teamsupd.azurewebsites.net`, `msupdate.azurefd.net` and `o365updater.azureedge.net` are all real examples from public reporting: an attacker registers a **subdomain of a provider whose parent domain is trusted**, names it to look like a corporate update path, and serves a payload or a beacon endpoint from it. The certificate is genuine, the parent is Microsoft's, and the URL category is whatever the provider's category is - so nothing about the destination looks wrong.

This rule matches the **LOTS parent list** and then discriminates on what a legitimate site under those parents cannot do: hold a **one- or two-URI session with no referrer chain for days** (a beacon), or serve **a single multi-megabyte pull to a machine that never browsed the site** (a staged payload). Both conditions describe the client's behaviour, not the domain's name.

```esql
FROM logs-zscaler_zia.web-*
// 72-hour window: the persistence branch needs it, so the schedule must not be shortened.
| WHERE @timestamp >= NOW() - 72 hours
  AND event.action == "allowed" AND url.domain IS NOT NULL AND url.path IS NOT NULL
// Parents anyone can register under, taken from the LOTS list. Regex in the gate on purpose: no cheaper
// filter selects "any subdomain of these".
  AND url.domain RLIKE ".*\\.(azurewebsites\\.net|azureedge\\.net|azurefd\\.net|azurestaticapps\\.net|cloudapp\\.azure\\.com|blob\\.core\\.windows\\.net|cloudfront\\.net|amazonaws\\.com|appspot\\.com|web\\.app|firebaseapp\\.com|github\\.io|githubusercontent\\.com|pages\\.dev|netlify\\.app|vercel\\.app|workers\\.dev|run\\.app|supabase\\.co|fastly\\.net)$"
| EVAL user.name = TO_LOWER(COALESCE(user.name, "unknown-user")), url.domain = TO_LOWER(url.domain),
       uri = CONCAT(COALESCE(http.request.method, "?"), "-",
                    COALESCE(TO_STRING(zscaler_zia.web.response.code), "?"), " ", url.path),
       has_referrer = http.request.referrer IS NOT NULL AND http.request.referrer != "-"
| STATS requests = COUNT(),
        slots = COUNT_DISTINCT(DATE_TRUNC(5 minutes, @timestamp)),
        hours = COUNT_DISTINCT(DATE_TRUNC(1 hour, @timestamp)),
        uris = COUNT_DISTINCT(uri),
        ua_variants = COUNT_DISTINCT(user_agent.original),
        referrer_hits = COUNT(*) WHERE has_referrer,
        bytes_in = SUM(zscaler_zia.web.response.size),
        max_response = MAX(zscaler_zia.web.response.size),
        sample_uris = MV_SLICE(VALUES(uri), 0, 10),
        user_agent.original = MV_SLICE(VALUES(user_agent.original), 0, 2),
        destination.ip = MV_SLICE(VALUES(destination.ip), 0, 5),
        first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
    BY user.name, url.domain
// Rarity: a subdomain one to three people reach is either a niche tool or somebody's infrastructure.
| INLINE STATS domain_users = COUNT_DISTINCT(user.name) BY url.domain
// The payload branch is limited to parents that serve static content. S3 and CloudFront are not: a toolchain
// download to one admin, one user agent, no referrer, tens of megabytes is the AWS CLI doing its job - the
// worst false positive this rule would otherwise have, and the reason the parent list splits at this point.
| EVAL static_host = url.domain RLIKE ".*\\.(azurewebsites\\.net|azureedge\\.net|azurefd\\.net|azurestaticapps\\.net|cloudapp\\.azure\\.com|pages\\.dev|web\\.app|firebaseapp\\.com|github\\.io|netlify\\.app|vercel\\.app|workers\\.dev)$"
// Two shapes, because staging and C2 look different from the client side:
//   1. a heartbeat - one or two fixed URIs, one user agent, no referrer, for days;
//   2. a single payload pull - a few requests, megabytes back, by something that never browsed the site
//      (a browser download carries a referrer, a script or an implant does not).
// Every number here is a starting value: measure the p99 of uris/ua_variants per user off the baseline
// below before tuning, and treat the persistence thresholds as the shape they describe, not as tuning knobs.
| WHERE ((uris <= 2 AND ua_variants = 1 AND referrer_hits = 0 AND domain_users <= 3)
        AND ((slots >= 72 AND hours >= 12) OR hours >= 36))
   OR (static_host AND requests <= 5 AND max_response >= 5000000 AND ua_variants = 1
        AND referrer_hits = 0 AND domain_users <= 1)
| SORT hours DESC, bytes_in DESC
| LIMIT 100
```

Run every hour with a 72-hour lookback, or daily over 72 hours. Suppress by `user.name` + `url.domain` for 24h.

## Verify before enabling
- **Size field.** `zscaler_zia.web.response.size` must be populated for inspected HTTPS; if only CONNECT sizes arrive, the payload-pull branch is meaningless. Probe it with the percentile query in `shared-cloud-exfil-upload.md`.
- **The parent list.** Same maintenance point as the upload rule: the LOTS project (`lots-project.com`, MISP warninglist `lots-project`) tracks 175 parents. Re-check quarterly.
- **The benign twins, both real:**
  - *Beacon branch:* a vendor update checker or a telemetry client on a provider's own subdomain. It holds one URI with no referrer for days, exactly like an implant.
  - *Payload branch:* a vendor that hosts its installer on `azurewebsites.net` or `blob.core.windows.net` and is downloaded by script - `pfx`/`msi` pulls at 50 MB with no referrer are ordinary in a Windows estate.
- **The fix for both twins is first-seen, not a threshold.** A 30-day transform recording the first time each **subdomain** (or better, each subdomain+URI) was seen in the estate turns this rule from shape-matching into rarity matching: a provider's update host has been seen for months, an attacker's host appeared yesterday. Until that transform exists, expect to add entity pairs from the baseline.

## Baseline
Over 30 days, no thresholds, to see which LOTS-parent subdomains the estate legitimately depends on - and how many users reach each:
```esql
FROM logs-zscaler_zia.web-*
| WHERE @timestamp >= NOW() - 30 days
  AND event.action == "allowed" AND url.domain IS NOT NULL
// same regex on purpose: this is the baseline for the parents above, not a second detection
  AND url.domain RLIKE ".*\\.(azurewebsites\\.net|azureedge\\.net|azurefd\\.net|cloudfront\\.net|blob\\.core\\.windows\\.net|amazonaws\\.com|github\\.io|pages\\.dev|workers\\.dev|netlify\\.app|web\\.app)$"
| EVAL user.name = TO_LOWER(COALESCE(user.name, "unknown-user")), url.domain = TO_LOWER(url.domain)
| STATS users = COUNT_DISTINCT(user.name), requests = COUNT(),
        bytes_in = SUM(zscaler_zia.web.response.size), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
    BY url.domain
| SORT users ASC, bytes_in DESC
| LIMIT 100
```
Sort ascending by `users`: the bottom of that list is the population this rule hunts, and the longest-lived entries in it are the ones to exclude as pairs.

## What it misses
- **A payload pulled from a storage parent** (S3, CloudFront, blob, Google Storage) - deliberately out of the
  payload branch, because a legitimate toolchain download looks identical to it: one user, one user agent, no
  referrer, tens of megabytes. Storage parents are the upload rule's population; the read side of them is not
  covered by either rule yet.
- **A payload hosted on a subdomain the estate already uses.** Shared CDNs and `github.io` are heavily used legitimately; an attacker's payload on a host your estate fetches every day is invisible to a rarity test.
- **TLS-pinned destinations.** Uninspected CONNECTs never reach this index, so a pinned-TLS download is invisible here - B06 is the endpoint view.
- **Fronting rather than subdomain abuse.** Microsoft prohibited domain fronting on Azure Front Door and Azure CDN from Microsoft (announced 2022, enforced 2024), so the classic SNI/Host mismatch through `azureedge`/`azurefd` is largely closed; what remains is the attacker-owned subdomain this rule targets. On other CDNs fronting still exists, and it is only visible where SNI and Host are both logged.
- **Anything the client fetches from a non-proxied path** (off-network, split tunnel, mobile).

## References
- LOTS (Living Off Trusted Sites) - `*.azurewebsites.net`, `*.cloudfront.net`, `*.workers.dev`, `*.pages.dev` and 170 more, tagged phishing/C2/exfiltration/download: `lots-project.com`; MISP warninglist `lots-project`
- Public examples of the naming pattern: `teamsupd.azurewebsites.net`, `o365updater.azureedge.net`, `msupdate.azurefd.net`, `softwareservicesupport.azurewebsites.net` (Peach Sandstorm "Tickler")
- Microsoft, domain fronting prohibited on Azure Front Door / Azure CDN from Microsoft: `learn.microsoft.com/en-us/answers/questions/1461527/`
- Elastic Zscaler ZIA integration fields - `zscaler_zia.web.response.size`: `elastic.co/docs/reference/integrations/zscaler_zia`
- MITRE T1102 Web Service and T1608.001 Stage Capabilities: Upload Malware - the technique pair this rule sits between
