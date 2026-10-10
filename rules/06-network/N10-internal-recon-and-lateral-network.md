---
id: N10
name: External reconnaissance scan against the Imperva-protected web edge (one source, many URIs)
category: network
status: todo
severity: medium
language: esql
index: logs-imperva_cloud_waf.event-*
mitre: [T1595.001, T1595.003]
data_source: Imperva Cloud WAF events
suppression:
  fields: [src]
  duration: 1h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
A single source touching many distinct URIs or hostnames on the edge in a short window is reconnaissance ahead of exploitation: directory and file brute forcing, or a vulnerability scanner walking the site. Normal visitors and crawlers request far fewer distinct paths in five minutes.

Internal fan-out (one internal host connecting to many internal hosts) is not covered here. B01 (horizontal scan) and B04 (lateral sweep over admin protocols) see it from the Falcon sensor on every host, including traffic that never passes through Zscaler.

## Query
```esql
FROM logs-imperva_cloud_waf.event-*
| EVAL src = source.ip
| STATS uris = COUNT_DISTINCT(url.path), hosts = COUNT_DISTINCT(url.domain), hits = COUNT(*)
    BY src, BUCKET(@timestamp, 5 minutes)
| WHERE hits >= 200 AND uris >= 100
```

## Suppression
Suppress by `src` for 1h. Alerts missing a key field are not suppressed. Aggregating rule. A scan spans many buckets.

## Known false positives / exclusions
- Your own external vulnerability scanners and attack-surface monitoring (Tenable, Qualys) and uptime probes. Exclude their source IPs.
- Search-engine crawlers and partner integrations that walk many URIs. Exclude by source after confirming.

## Triage
- Identify the source (ASN, country, reputation) and what it reached. Check the same source for unblocked attacks (N05) and for a block followed by success (N06): a scan that turns into exploitation is the case to act on.

## Test
Run a controlled directory brute force (for example `ffuf` with a small wordlist) from a lab host against a lab site behind Imperva.
