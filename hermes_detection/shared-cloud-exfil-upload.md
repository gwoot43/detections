# Shared-cloud exfiltration — uploads to attacker-controlled subdomains of trusted parents

Anyone can take `[attacker-choice].azurewebsites.net`, `[account].blob.core.windows.net`, `[random].cloudfront.net` or `[user].workers.dev` for free, and the **parent** domain stays Microsoft's, Amazon's or Cloudflare's - so the destination carries the provider's reputation, the certificate is a real wildcard, and any filter that judges the domain sees a trusted site. That is why these parents are on the Living Off Trusted Sites (LOTS) list for **exfiltration**, not only for phishing and C2.

This rule is the upload direction: **a single account pushing megabytes to a storage or hosting subdomain that nobody else in the estate uses**. The volume gate and the parent match are separate on purpose - volume first (cheap, rare), parent second (a regex, because no cheaper filter says "any subdomain of these").

```esql
FROM logs-zscaler_zia.web-*
// 24-hour window. The size gate runs before the parent regex so the expensive match sees few rows.
| WHERE @timestamp >= NOW() - 24 hours
  AND event.action == "allowed"
  AND http.request.method IN ("POST", "PUT", "PATCH")
  AND zscaler_zia.web.request.size >= 1000000
// Parents that accept writes and are free to register under. Regex in the gate on purpose: there is no
// cheaper filter for "any subdomain of these", and the volume test above has already cut the set.
  AND url.domain RLIKE ".*\\.(blob\\.core\\.windows\\.net|dfs\\.core\\.windows\\.net|file\\.core\\.windows\\.net|storage\\.googleapis\\.com|firebasestorage\\.googleapis\\.com|amazonaws\\.com|cloudfront\\.net|azurewebsites\\.net|azurecontainerapps\\.io|workers\\.dev|run\\.app|supabase\\.co)$"
| EVAL user.name = TO_LOWER(COALESCE(user.name, "unknown-user")), url.domain = TO_LOWER(url.domain)
| STATS bytes_out = SUM(zscaler_zia.web.request.size),
        uploads = COUNT(),
        sample_uris = MV_SLICE(VALUES(CONCAT(http.request.method, " ", url.path, " -> ",
                          TO_STRING(zscaler_zia.web.response.code))), 0, 10),
        destination.ip = MV_SLICE(VALUES(destination.ip), 0, 5),
        destination.geo.country_name = MV_SLICE(VALUES(destination.geo.country_name), 0, 3),
        user_agent.original = MV_SLICE(VALUES(user_agent.original), 0, 3),
        first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
    BY user.name, url.domain
// Rarity: how many people in the estate reached this subdomain at all. A bucket or site one account uses
// is either a sanctioned integration or somebody's exfil point - and it is the account that tells them apart.
| INLINE STATS domain_users = COUNT_DISTINCT(user.name) BY url.domain
// 5 MB out to a one-or-two-user subdomain in a day is a starting value: SaaS backups and telemetry
// send far less, and a data lift sends far more. Measure the p99 of bytes out per domain before tuning.
| WHERE bytes_out >= 5000000 AND domain_users <= 2
| SORT bytes_out DESC
| LIMIT 100
```

## Verify before enabling
- **Size field.** Confirm it is populated for inspected HTTPS on your Zscaler path - `zscaler_zia.web.request.size` in the Elastic integration (equivalently `source.bytes`). If it only carries CONNECT sizes, the volume test is meaningless:
```esql
FROM logs-zscaler_zia.web-*
| WHERE event.action == "allowed" AND http.request.method IN ("POST", "PUT")
| STATS n = COUNT(*), p50 = PERCENTILE(zscaler_zia.web.request.size, 50),
        p99 = PERCENTILE(zscaler_zia.web.request.size, 99), max = MAX(zscaler_zia.web.request.size)
    BY url.domain
| SORT max DESC
| LIMIT 20
```
- **The parent list is a maintained list, not a constant.** The LOTS project tracks 175 parents abused for exfiltration, C2, phishing and tool downloads (`lots-project.com`), and the MISP warninglist is the machine-readable copy. Start from the cloud-hosting parents in this rule and re-check the list quarterly - new hosts appear and old ones stop accepting registrations.
- **The sanctioned integrations.** Every backup, DLP, CASB and log-archive product in the estate uploads to exactly this shape. Each one is an entity pair (`user.name` + `url.domain`), never the parent domain alone, and the baseline below finds them.

## Baseline
Over 30 days, no threshold, to see who legitimately uploads where:
```esql
FROM logs-zscaler_zia.web-*
| WHERE @timestamp >= NOW() - 30 days
  AND event.action == "allowed" AND http.request.method IN ("POST", "PUT", "PATCH")
  AND zscaler_zia.web.request.size >= 1000000
// same regex on purpose: this is the baseline for the parents above, not a second detection
  AND url.domain RLIKE ".*\\.(blob\\.core\\.windows\\.net|storage\\.googleapis\\.com|amazonaws\\.com|cloudfront\\.net|azurewebsites\\.net|workers\\.dev)$"
| EVAL user.name = TO_LOWER(COALESCE(user.name, "unknown-user")), url.domain = TO_LOWER(url.domain)
| STATS bytes_out = SUM(zscaler_zia.web.request.size), uploads = COUNT(),
        first_seen = MIN(@timestamp), last_seen = MAX(@timestamp) BY user.name, url.domain
| INLINE STATS domain_users = COUNT_DISTINCT(user.name) BY url.domain
| SORT bytes_out DESC
| LIMIT 50
```
A subdomain with one user and steady daily volume is a product. A subdomain with one user and one burst is the case this rule exists for; `first_seen` is what separates them, and it is the reason to build the first-seen transform (see below).

## What it misses
- **Exfiltration in small pieces.** Chunked uploads below the size gate, or base64 in headers and URLs, never reach it.
- **Exfiltration over an approved SaaS** - SharePoint, Teams, OneDrive, Slack, an approved storage app - because the parent is your own tenant, not a shared one. The IN-series covers that direction.
- **TLS-pinned destinations.** Uninspected CONNECTs never reach this index in this estate, so an upload over pinned TLS is invisible here.
- **A sanctioned account turned malicious.** `domain_users <= 2` plus the entity-pair exclusions mean an attacker using a backup service account to its usual bucket is not caught by this rule. That is what per-account baselining (`bytes_out` against its own history) is for; it is not in this version.

## References
- LOTS (Living Off Trusted Sites) project - 175 parents abused for phishing, C2, exfiltration and tool downloads: `lots-project.com`; machine-readable copy at `github.com/MISP/misp-warninglists` (list `lots-project`)
- Microsoft, domain fronting prohibited on Azure Front Door and Azure CDN from Microsoft (announced 2022, enforced 2024) - fronting via those parents is largely dead, **attacker-owned subdomains are not**: `learn.microsoft.com/en-us/answers/questions/1461527/`
- Elastic Zscaler ZIA integration field reference - `zscaler_zia.web.request.size` / `.response.size`: `elastic.co/docs/reference/integrations/zscaler_zia`
- MITRE T1567.002 Exfiltration Over Web Service: Exfiltration to Cloud Storage - and the Sigma coverage around `rclone` / cloud upload tooling, which catches the tool, not the destination
