---
id: CS03
name: DNS tunnelling - many long, distinct names under one parent domain from one host
category: crowdstrike-fdr
status: todo
severity: medium
language: esql
index: logs-crowdstrike.fdr-*
mitre: [T1071.004, T1572, T1048.003]
data_source: CrowdStrike FDR DnsRequest / SuspiciousDnsRequest events
suppression:
  fields: [host.id, parent]
  duration: 24h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
A host making very many distinct lookups under one parent domain, a steady share of them with a long encoded first label, is DNS tunnelling or data exfiltration over DNS, which endpoint process rules miss. It does not look for DGA or known C2 domains; those are reputation problems for Zscaler (N07). Falcon's own `SuspiciousDnsRequest` events are included in the count.

The parent is the registrable domain the integration computes from the public suffix list (`dns.question.registered_domain`), so `co.uk`-style suffixes do not merge unrelated sites. Reverse lookups (`.arpa`), the cluster-internal domain and the CDN, cloud and security-vendor domains that legitimately generate thousands of subdomains are excluded inline. Tunnelling tools encode data in the first label (`4f2a9c….t.evil.com`), so the gate is 20 or more names whose first label is 30 characters or longer. One long name is not enough: CDNs and telemetry produce the odd long name every day, a tunnel produces them continuously.

## Query
Run every 15 minutes with a 1-hour lookback.
```esql
FROM logs-crowdstrike.fdr-*
| WHERE event.action IN ("DnsRequest", "SuspiciousDnsRequest")
| EVAL domain = TO_LOWER(TO_STRING(dns.question.name))
| WHERE domain IS NOT NULL AND NOT domain LIKE "*.arpa"
| EVAL parts = SPLIT(domain, "."), n = MV_COUNT(parts)
| WHERE n >= 2
// registrable domain from the public suffix list; fall back to the last two labels
| EVAL parent = TO_LOWER(COALESCE(dns.question.registered_domain, MV_CONCAT(MV_SLICE(parts, -2, -1), "."))),
       label_len = LENGTH(MV_FIRST(parts))
// high-volume benign parents; add your own AD and internal DNS domains
| WHERE parent NOT IN ("akamaiedge.net", "akamai.net", "akamaihd.net", "cloudfront.net", "amazonaws.com", "azureedge.net", "trafficmanager.net",
                       "windows.net", "microsoft.com", "office.com", "office365.com", "office.net", "live.com", "msftncsi.com",
                       "googleapis.com", "gvt1.com", "gstatic.com", "1e100.net", "cluster.local",
                       "sophosxl.net", "mcafee.com", "spamhaus.org", "crowdstrike.com")
| STATS distinct_sub = COUNT_DISTINCT(domain), total = COUNT(*),
        long_names = COUNT_DISTINCT(CASE(label_len >= 30, domain, NULL)), max_label = MAX(label_len),
        sample = VALUES(domain), pids = VALUES(process.entity_id), host.name = VALUES(host.name),
        first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
    BY host.id, parent
| WHERE distinct_sub >= 100 AND long_names >= 20
| EVAL sample = MV_SLICE(sample, 0, 9)
```

**CrowdStrike (Falcon LogScale / Advanced Event Search)**
```logscale
#event_simpleName=/^(DnsRequest|SuspiciousDnsRequest)$/
| domain := lower(DomainName)
| domain!=/\.arpa$/
| domain=/(?<parent>[^.]*\.[^.]*)$/
| !in(field="parent", ignoreCase=true, values=["akamaiedge.net", "akamai.net", "akamaihd.net", "cloudfront.net", "amazonaws.com", "azureedge.net", "trafficmanager.net",
                                               "windows.net", "microsoft.com", "office.com", "office365.com", "office.net", "live.com", "msftncsi.com",
                                               "googleapis.com", "gvt1.com", "gstatic.com", "1e100.net", "cluster.local",
                                               "sophosxl.net", "mcafee.com", "spamhaus.org", "crowdstrike.com"])
| domain=/^(?<label1>[^.]*)/
| label_len := length(label1)
| case { test(label_len >= 30) | long_name := domain; * ; }
| groupBy([aid, parent], function=[count(domain, distinct=true, as=distinct_sub), count(as=total),
                                   count(long_name, distinct=true, as=long_names), max(label_len, as=max_label),
                                   collect([ContextProcessId, ComputerName])], limit=max)
| test(distinct_sub >= 100 AND long_names >= 20)
```
Falcon has no registered-domain field, so `parent` here is the last two labels of the name, a simplification that groups unrelated sites under suffixes like `co.uk`.

`SuspiciousDnsRequest` on its own is already curated by CrowdStrike and reaches Elastic as a Falcon detection through CS04 when it is alertable.

## Suppression
Suppress by `host.id`, `parent` for 24h. Alerts missing a key field are not suppressed. Aggregating rule: each run overlaps the last and tunnelling runs continuously, so the repeats fold into the open alert. Counts run over the whole lookback, not fixed buckets.

## Known false positives / exclusions
- CDNs, telemetry and antivirus cloud lookups generate many subdomains under one parent. The common ones are excluded inline; extend the list from a week of baseline. Your own AD domain belongs on it if servers resolve many internal hosts.

## Triage
- DNS events carry no process name. Find the process through `pids`: its ProcessRollup2 has the same `process.entity_id`. A browser is probably benign CDN traffic; `powershell.exe`, `rundll32.exe` or an unsigned binary doing dozens of long, distinct subdomain lookups is tunnelling. `max_label` near 63 (the DNS label limit) is a tunnel filling every label. Block the parent domain and investigate the host.

## Test
Use a DNS-tunnel test tool (iodine/dnscat2) against a lab domain from a lab host, or run 150 lookups of random 40-character labels under a domain you control.
