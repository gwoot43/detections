---
id: N10
name: External reconnaissance scan against the Imperva-protected web edge (one source, many URIs)
category: network
status: todo
severity: medium
language: esql
index: logs-imperva_cloud_waf.event-*
mitre: [T1595.002, T1595.003]
data_source: Imperva Cloud WAF events
suppression:
  fields: [src]
  duration: 1h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
A single source touching many distinct URIs or hostnames on the edge in a short window is reconnaissance ahead of exploitation: directory and file brute forcing, or a vulnerability scanner walking the site. Normal visitors and crawlers request far fewer distinct paths in five minutes.

Internal scanning is not covered here; that is B01 and B04.

## Query
Run every 5 minutes with a 10-minute lookback.
```esql
FROM logs-imperva_cloud_waf.event-*
// your own external scanners and attack-surface monitoring (placeholder range: replace with yours)
| WHERE NOT CIDR_MATCH(source.ip, "198.51.100.0/24")
| EVAL src = source.ip
| STATS uris = COUNT_DISTINCT(url.path), hosts = COUNT_DISTINCT(url.domain), hits = COUNT(*),
        first_seen = MIN(@timestamp)
    BY src
| WHERE hits >= 200 AND uris >= 100
```
Counts run over the whole lookback, not fixed buckets, so a scan that crosses a bucket edge isn't split in two.

## Suppression
Suppress by `src` for 1h. Alerts missing a key field are not suppressed. Aggregating rule: each run overlaps the last, and a long scan folds into the open alert.

## Known false positives / exclusions
- Your own external vulnerability scanners and attack-surface monitoring (Tenable, Qualys) and uptime probes. Exclude their source ranges in the query.
- Search-engine crawlers and partner integrations that walk many URIs. Exclude by source after confirming.

## Triage
- Identify the source (ASN, country, reputation) and what it reached. Check the same source for unblocked attacks (N05) and for a block followed by success (N06): a scan that turns into exploitation is the case to act on.

## Test
Run a controlled directory brute force (for example `ffuf` with a small wordlist) from a lab host against a lab site behind Imperva.
