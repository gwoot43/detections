---
id: N08
name: Zscaler large upload to a new or risky destination (possible exfiltration)
category: network
status: todo
severity: medium
language: esql
index: logs-zscaler_zia.web-*
mitre: [T1567, T1048, T1041]
data_source: Zscaler Internet Access web logs (Elastic zscaler_zia integration, web data stream)
suppression:
  fields: [user.name, destination.domain]
  duration: 24h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
Data theft over web shows up as an unusually large upload to a destination the user does not normally send to, especially personal file-sharing, paste sites and newly seen domains. Volume plus destination novelty keeps this from firing on normal SaaS use.

## Query
```esql
FROM logs-zscaler_zia.web-*
| EVAL up = TO_LONG(http.request.bytes),
       cat = TO_LOWER(TO_STRING(zscaler_zia.web.url.category.sub))
| WHERE up IS NOT NULL
| STATS bytes_up = SUM(up), hits = COUNT(*), cats = VALUES(cat)
    BY user.name, destination.domain, BUCKET(@timestamp, 1 hour)
| WHERE bytes_up >= 524288000            // 500 MB/hour to one destination; tune to your baseline
| EVAL catlist = MV_CONCAT(cats, ",")
// URL category names are best guesses: verify value in Discover
| WHERE (catlist LIKE "*file*shar*" OR catlist LIKE "*file host*" OR catlist LIKE "*personal*storage*"
        OR catlist LIKE "*paste*" OR catlist LIKE "*newly*registered*" OR catlist LIKE "*uncategor*"
        OR catlist LIKE "*miscellaneous*" OR catlist LIKE "*unknown*")
```
Field notes for the Elastic Zscaler ZIA integration (`zscaler_zia.web`):
- `http.request.bytes` is Zscaler's request size (`reqsize`). The raw copy `zscaler_zia.web.request.size` is removed at ingest unless you enable duplicate custom fields.
- `cat` is the URL category (`zscaler_zia.web.url.category.sub`). The integration's test samples include "Cloud Storage" and "Collaboration".
- `user.name` is the part of the Zscaler login before the @. The full login is in `user.email`.

## Suppression
Suppress by `user.name`, `destination.domain` for 24h. Alerts missing a key field are not suppressed. Aggregating rule. Uploads continue across buckets.

## Known false positives / exclusions
- Sanctioned cloud storage and backup (your corporate OneDrive, approved SaaS). Exclude those domains. That is why the category filter targets personal storage, paste and uncategorized.
- Developers pushing large artifacts to approved registries. Exclude those domains.

## Triage
- Confirm the destination and whether the user should be sending that volume there. Correlate to any DLP alert and to endpoint activity (recent archive creation).

## Test
Upload a large file to a personal file-sharing site from a managed device (with permission).
