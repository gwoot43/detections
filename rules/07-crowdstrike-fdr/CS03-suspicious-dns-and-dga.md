---
id: CS03
name: Suspicious DNS: C2 domains, DGA patterns or DNS tunneling
category: crowdstrike-fdr
status: todo
severity: medium
language: esql
index: logs-crowdstrike.fdr-*
mitre: [T1071.004, T1568.002, T1572]
data_source: CrowdStrike FDR DnsRequest / SuspiciousDnsRequest events
suppression:
  fields: [host.id, parent]
  duration: 24h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
A host making very many distinct lookups under one parent domain in a short window, with long query names, is DNS tunnelling or data exfiltration over DNS, which endpoint process rules miss. This complements Zscaler (N07) with the endpoint view. Falcon's own `SuspiciousDnsRequest` events are included in the count.

The parent is the registrable domain the integration computes from the public suffix list (`dns.question.registered_domain`), so `co.uk`-style suffixes do not merge unrelated sites. Reverse lookups (`.arpa`), the cluster-internal domain and the CDN, cloud and security-vendor domains that legitimately generate thousands of subdomains are excluded inline. Tunnelling tools encode data in the labels, so at least one name must be 50 characters or longer.

## Query
```esql
FROM logs-crowdstrike.fdr-*
| WHERE event.action IN ("DnsRequest", "SuspiciousDnsRequest")
| EVAL domain = TO_LOWER(TO_STRING(dns.question.name))
| WHERE domain IS NOT NULL AND NOT domain LIKE "*.arpa"
| EVAL parts = SPLIT(domain, "."), n = MV_COUNT(parts)
| WHERE n >= 2
// registrable domain from the public suffix list; fall back to the last two labels
| EVAL parent = TO_LOWER(COALESCE(dns.question.registered_domain, MV_CONCAT(MV_SLICE(parts, -2, -1), ".")))
// high-volume benign parents; add your own AD and internal DNS domains
| WHERE parent NOT IN ("akamaiedge.net", "akamai.net", "akamaihd.net", "cloudfront.net", "amazonaws.com", "azureedge.net", "trafficmanager.net",
                       "windows.net", "microsoft.com", "office.com", "office365.com", "office.net", "live.com", "msftncsi.com",
                       "googleapis.com", "gvt1.com", "gstatic.com", "1e100.net", "cluster.local",
                       "sophosxl.net", "mcafee.com", "spamhaus.org", "crowdstrike.com")
| STATS distinct_sub = COUNT_DISTINCT(domain), total = COUNT(*), max_len = MAX(LENGTH(domain)),
        sample = VALUES(domain), pids = VALUES(process.entity_id), host.name = VALUES(host.name)
    BY host.id, parent, BUCKET(@timestamp, 10 minutes)
| WHERE distinct_sub >= 50 AND max_len >= 50
```
`SuspiciousDnsRequest` on its own is already curated by CrowdStrike and reaches Elastic as a Falcon detection through CS04 when it is alertable.

## Suppression
Suppress by `host.id`, `parent` for 24h. Alerts missing a key field are not suppressed. Aggregating rule. Tunnelling runs continuously.

## Known false positives / exclusions
- CDNs, telemetry and antivirus cloud lookups generate many subdomains under one parent. The common ones are excluded inline; extend the list from a week of baseline. Your own AD domain belongs on it if servers resolve many internal hosts.

## Triage
- DNS events carry no process name. Find the process through `pids`: its ProcessRollup2 has the same `process.entity_id`. A browser is probably benign CDN traffic; `powershell.exe`, `rundll32.exe` or an unsigned binary doing 50+ long subdomain lookups is tunnelling. Block the parent domain and investigate the host.

## Test
Use a DNS-tunnel test tool (iodine/dnscat2) against a lab domain from a lab host.
