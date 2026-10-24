---
id: CS03
name: DNS tunnelling - many long, distinct names under one parent domain from one host (activity), or a DNS tunnel tool runs (filename fallback)
category: crowdstrike-fdr
status: todo
language: esql
index: logs-yourorg-crowdstrike-data-default*
mitre: [T1071.004, T1572, T1048.003]
data_source: CrowdStrike FDR DnsRequest / SuspiciousDnsRequest events
suppression:
  fields: [host.id, parent]
  duration: 24h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
A host making very many distinct lookups under one parent domain, a steady share of them with a long encoded first label, is DNS tunnelling or data exfiltration over DNS, which endpoint process rules miss. It does not look for DGA or known C2 domains; those are reputation problems for Zscaler (N07). Falcon's own `SuspiciousDnsRequest` events are included in the count.

- **Anchor:** DNS lookups, minus reverse lookups (`.arpa`).
- **Corroborating property:** the tunnel's shape. 100 or more distinct names under one parent, 20 or more of them with a first label of 30 characters or more. Tunnelling tools encode data in the first label (`4f2a9c….t.evil.com`). One long name isn't enough: CDNs and telemetry produce the odd one every day, a tunnel produces them continuously.
- **Exclusion by rarity:** the parent must be looked up by at most three hosts. CDN, cloud and security-vendor domains that generate thousands of subdomains are looked up across the fleet, so they drop out with no list to keep. The one exclusion left is mail servers' DNS blocklist lookups: they're tunnel-shaped by design and run on only a few hosts.

The parent is the registrable domain the integration computes from the public suffix list (`dns.question.registered_domain`), so `co.uk`-style suffixes do not merge unrelated sites.

## Query
Run every 15 minutes with a 1-hour lookback.
```esql
FROM logs-yourorg-crowdstrike-data-default*
// Activity: DNS lookups, minus reverse lookups. Filename fallback: a DNS tunnel tool starting (iodine, dnscat2, dns2tcp),
// which alerts even when the tunnel is still quiet.
| WHERE event.action IN ("dnsrequest", "suspiciousdnsrequest")
     OR (event.action IN ("processrollup2", "syntheticprocessrollup2")
         AND (TO_LOWER(process.name) IN ("iodine", "iodine.exe", "dnscat", "dnscat.exe", "dnscat2", "dnscat2.exe", "dns2tcpc", "dns2tcpc.exe")
              OR TO_LOWER(process.command_line) LIKE "*start-dnscat2*"))
| EVAL named = event.action LIKE "*processrollup2", domain = TO_LOWER(TO_STRING(dns.question.name))
| WHERE named OR (domain IS NOT NULL AND NOT domain LIKE "*.arpa")
// The parent is the registrable domain (public suffix list), falling back to the last two labels; for a tool's start, the tool's name.
// Tunnels encode data in the first label, so its length is the tell.
| EVAL parts = SPLIT(domain, "."),
       parent = CASE(named, CONCAT("tool:", TO_LOWER(process.name)),
                     TO_LOWER(COALESCE(dns.question.registered_domain, MV_CONCAT(MV_SLICE(parts, -2, -1), ".")))),
       label_len = LENGTH(MV_FIRST(parts))
// Mail servers' DNS blocklist lookups are tunnel-shaped by design and run on only a few hosts, so rarity can't remove them.
| WHERE NOT parent IN ("spamhaus.org", "spamcop.net", "surbl.org", "uribl.com", "barracudacentral.org")
// One row per host and parent: distinct names, and how many of them have a long first label.
| STATS distinct_sub = COUNT_DISTINCT(domain), total = COUNT(*),
        long_names = COUNT_DISTINCT(CASE(label_len >= 30, domain, NULL)), max_label = MAX(label_len),
        sample = VALUES(domain), pids = VALUES(process.entity_id), host.name = VALUES(host.name),
        named = MAX(CASE(named, 1, 0)), process.command_line = VALUES(process.command_line),
        first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
    BY host.id, parent
// Rarity: every host that looked up names under this parent, counted before the tunnel checks.
// CDN, cloud and security-vendor domains are looked up across the fleet and drop out here.
| INLINE STATS hosts = COUNT_DISTINCT(host.id) BY parent
// Activity first: 100+ distinct names, 20+ with a first label of 30+ characters, under a parent at most 3 hosts look up.
// Then the filename fallback.
| WHERE (distinct_sub >= 100 AND long_names >= 20 AND hosts <= 3) OR named == 1
| EVAL finding = CASE(named == 1, "DNS tunnel tool started (by name)", "DNS tunnel by behaviour")
| EVAL sample = MV_SLICE(sample, 0, 9)
```

**CrowdStrike (Falcon LogScale / Advanced Event Search)**
```logscale
#event_simpleName=/^(DnsRequest|SuspiciousDnsRequest|ProcessRollup2|SyntheticProcessRollup2)$/
// Activity: DNS lookups, minus reverse lookups. Falcon has no registered-domain field, so the parent is the last two labels.
// Filename fallback: a DNS tunnel tool starting; its name stands in for the parent.
| case {
    #event_simpleName=/DnsRequest$/
      | domain := lower(DomainName)
      | domain!=/\.arpa$/
      | domain=/(?<parent>[^.]*\.[^.]*)$/
      | domain=/^(?<label1>[^.]*)/
      | label_len := length(label1);
    #event_simpleName=/ProcessRollup2$/ (FileName=/^(iodine|dnscat2?|dns2tcpc)(\.exe)?$/i or CommandLine=/start-dnscat2/i)
      | parent := format("tool:%s", field=[FileName]) | named_host := aid;
  }
// Mail servers' DNS blocklist lookups are tunnel-shaped by design and run on only a few hosts, so rarity can't remove them.
| !in(field="parent", ignoreCase=true, values=["spamhaus.org", "spamcop.net", "surbl.org", "uribl.com", "barracudacentral.org"])
// Tunnels encode data in the first label, so its length is the tell.
| case { test(label_len >= 30) | long_name := domain; * ; }
// One row per host and parent.
| groupBy([aid, parent], function=[count(domain, distinct=true, as=distinct_sub), count(long_name, distinct=true, as=long_names),
                                   max(label_len, as=max_label), collect([ComputerName, ContextProcessId, named_host, CommandLine])], limit=max)
// Mark the tunnel-shaped rows. Every host still counts towards rarity below.
| case { test(distinct_sub >= 100) | test(long_names >= 20) | tunnel_host := aid; * ; }
// Rarity: one row per parent, counting every host that looked it up. Keep parents with a tunnel and at most 3 hosts.
| groupBy([parent], function=[count(aid, distinct=true, as=hosts), max(distinct_sub, as=distinct_sub), max(long_names, as=long_names),
                              max(max_label, as=max_label), collect([tunnel_host, named_host, ComputerName, ContextProcessId, CommandLine])],
          limit=max)
// Activity first: a tunnel-shaped host under a parent at most 3 hosts look up. Then the filename fallback.
// Deliberately no * branch: an event passes if any branch matches.
| case { test(hosts <= 3) | tunnel_host=*; named_host=*; }
| case {
    named_host=* | finding := "DNS tunnel tool started (by name)";
    * | finding := "DNS tunnel by behaviour";
  }
```
Falcon has no registered-domain field, so `parent` here is the last two labels of the name, a simplification that groups unrelated sites under suffixes like `co.uk`. LogScale has no `INLINE STATS`, so this version rolls up to one row per parent, listing the tunnel host and the at most three hosts that looked it up.

`SuspiciousDnsRequest` on its own is already curated by CrowdStrike and reaches Elastic as a Falcon detection through CS04 when it is alertable.

## Suppression
Suppress by `host.id`, `parent` for 24h. Alerts missing a key field are not suppressed. Aggregating rule: each run overlaps the last and tunnelling runs continuously, so the repeats fold into the open alert. Counts run over the whole lookback, not fixed buckets.

## Known false positives / exclusions
- A security or monitoring tool on one to three hosts that looks up hashes or encoded values under its vendor's domain. Rarity can't remove it. Exclude that parent by exact name once confirmed.
- A mail gateway other than the ones covered by the blocklist exclusion. Add its blocklist provider to the same line.

## Triage
- DNS events carry no process name. Find the process through `pids`: its ProcessRollup2 has the same `process.entity_id`. A browser is probably benign CDN traffic; `powershell.exe`, `rundll32.exe` or an unsigned binary doing dozens of long, distinct subdomain lookups is tunnelling. `max_label` near 63 (the DNS label limit) is a tunnel filling every label. Block the parent domain and investigate the host.

## Test
Use a DNS-tunnel test tool (iodine/dnscat2) against a lab domain from a lab host, or run 150 lookups of random 40-character labels under a domain you control.
