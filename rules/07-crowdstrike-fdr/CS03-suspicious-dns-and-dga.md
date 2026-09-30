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
  fields: [host.name, parent]
  duration: 24h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
Falcon's `SuspiciousDnsRequest` is already scored by CrowdStrike. On top of that, a host making very many distinct subdomain lookups under one parent domain in a short window is DNS tunneling or DGA beaconing, which endpoint process rules miss. This complements Zscaler (N07) with the process context Zscaler lacks.

## Query
```esql
FROM logs-crowdstrike.fdr-*
| WHERE event.action IN ("DnsRequest", "SuspiciousDnsRequest")
| EVAL domain = TO_LOWER(TO_STRING(dns.question.name))
// registrable-ish parent: last two labels (approximate; refine with a public-suffix lookup if available)
| EVAL parts = SPLIT(domain, "."), n = MV_COUNT(parts)
| WHERE n >= 2
| EVAL parent = MV_CONCAT(MV_SLICE(parts, -2, -1), ".")
| STATS distinct_sub = COUNT_DISTINCT(domain), total = COUNT(*), procs = VALUES(process.name), sample = VALUES(domain)
    BY host.name, parent, BUCKET(@timestamp, 10 minutes)
| WHERE distinct_sub >= 50
```
Add a second, simpler rule that just surfaces every `SuspiciousDnsRequest` with its process, since that field is already curated.

## Suppression
Suppress by `host.name`, `parent` for 24h. Alerts missing a key field are not suppressed. Aggregating rule. Tunnelling runs continuously.

## Known false positives / exclusions
- CDNs, telemetry and antivirus cloud lookups generate many subdomains under one parent (e.g. `*.akamai`, `*.cloudfront`, vendor telemetry). Build an allowlist of high-volume benign parents from a week of baseline and exclude them.

## Triage
- Identify the process making the lookups. A browser is probably benign CDN traffic; `powershell.exe`, `rundll32.exe` or an unsigned binary doing 50+ subdomain lookups is tunneling. Block the parent domain and investigate the host.

## Test
Use a DNS-tunnel test tool (iodine/dnscat2) against a lab domain from a lab host.
