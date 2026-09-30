---
id: N08
name: Zscaler large upload to a new or risky destination (possible exfiltration)
category: network
status: todo
severity: medium
language: esql
index: logs-zscaler.zia_web-*
mitre: [T1567, T1048, T1041]
data_source: Zscaler Internet Access web logs
---
## Why this is high fidelity
Data theft over web shows up as an unusually large upload to a destination the user does not normally send to, especially personal file-sharing, paste sites and newly seen domains. Volume plus destination novelty keeps this from firing on normal SaaS use.

## Query
```esql
FROM logs-zscaler.zia_web-*
| EVAL up = TO_LONG(COALESCE(zscaler.zia.request_size, http.request.bytes, source.bytes)),
       cat = TO_LOWER(TO_STRING(COALESCE(zscaler.zia.url_category, rule.category)))
| WHERE up IS NOT NULL
| STATS bytes_up = SUM(up), hits = COUNT(*), cats = VALUES(cat)
    BY user.name, destination.domain, BUCKET(@timestamp, 1 hour)
| WHERE bytes_up >= 524288000            // 500 MB/hour to one destination; tune to your baseline
| WHERE (MV_CONCAT(cats, ",") LIKE "*file*share*" OR MV_CONCAT(cats, ",") LIKE "*personal storage*"
        OR MV_CONCAT(cats, ",") LIKE "*paste*" OR MV_CONCAT(cats, ",") LIKE "*newly*registered*"
        OR MV_CONCAT(cats, ",") LIKE "*uncategor*")
```

## Known false positives / exclusions
- Sanctioned cloud storage and backup (your corporate OneDrive, approved SaaS). Exclude those domains. That is why the category filter targets personal storage, paste and uncategorized.
- Developers pushing large artifacts to approved registries. Exclude those domains.

## Triage
- Confirm the destination and whether the user should be sending that volume there. Correlate to any DLP alert and to endpoint activity (recent archive creation).

## Test
Upload a large file to a personal file-sharing site from a managed device (with permission).
