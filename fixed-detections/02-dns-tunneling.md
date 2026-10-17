# 02 · DNS tunneling (Falcon DNS requests)

**Verdict before:** cannot fire, and measures the wrong thing even once the syntax is fixed.
**After:** counts *distinct* names under one parent domain per host, and requires long labels or TXT/NULL record types. That is the shape of DNS tunneling, not of chatty software.

## Before
```text
from logs-yourorg-crowdstrike* metadata _id, _index, _version
| where event.action=="dnsrequest" and data.DomainName like "."
  and not (ends_with(data.DomainName, ".amazonaws.com") or ... 40+ provider suffixes ...)
  and not (data.DomainName like "._domainkey." or data.DomainName like ".dkim." or data.DomainName like ".spf.")
  and not (ends_with(data.DomainName, ".corp-internal.example") or ends_with(data.DomainName, ".prod.corp-internal.example")
           or ends_with(data.DomainName, ".corp-legacy.example") or ... trailing-dot variants ...)
  and not (data.ContextBaseFileName in ("MsSense.exe", "Sysmon.exe", "svchost.exe", "ldap_child", ... "MSExchangeTransport.exe"))
  and not (ends_with(data.DomainName, ".github.io") or ... more SaaS suffixes ...)
| eval timebucket=date_trunc(15 minutes, @timestamp)
| stats event_count=count() by timebucket, data.DomainName, data.ContextBaseFileName, host.name, data.ContextProcessId
| where event_count >= 50
```
(The full exclusion lists are shortened here; they don't change the analysis.)

## What's wrong

| # | Problem | Effect |
|---|---|---|
| 1 | `data.DomainName like "."`. In ES|QL, `LIKE` only treats `*` and `?` as wildcards, so this means "equals `.`". | **No row ever passes. The rule cannot fire.** |
| 2 | `like "._domainkey."`, `like ".dkim."`, `like ".spf."` have the same problem. | The DKIM/SPF exclusions do nothing. |
| 3 | Counts 50 repeats of the **same** name. Tunneling encodes data in the subdomain, so every query is a *different* name (`4f2a9c….t.evil.com`). | Even fixed, it finds noisy software, not tunnels. Real tunnels spread across thousands of unique names and stay under 50 per name. |
| 4 | Grouped by process ID and a 15-minute bucket. | A tunnel that restarts, or straddles a bucket edge, is split up. |
| 5 | Every exclusion is listed with and without the trailing dot. | Twice the list to maintain. Strip the dot once. |
| 6 | ~50 suffix exclusions, all maintained by hand. | Mostly unnecessary. Nobody can tunnel DNS through a domain whose name servers they don't control, and the distinct-name logic below doesn't fire on CDNs anyway. |
| 7 | Excluding `svchost.exe` outright. | Injected malware in svchost is exempt. With the new logic the exclusion isn't needed. |
| 8 | Title says Windows, but it includes Linux processes (`ldap_child`, `bpcd`). | Cosmetic. The new rule is explicitly cross-platform. |

## After
```esql
FROM logs-yourorg-crowdstrike-data-default*
// Anchor: DNS lookups that carry a name.
| WHERE event.action == "dnsrequest" AND data.DomainName IS NOT NULL
// Lower-case, drop a trailing dot, and keep names with three or more labels.
| EVAL q = TO_LOWER(data.DomainName)
| EVAL q = CASE(ENDS_WITH(q, "."), SUBSTRING(q, 1, LENGTH(q) - 1), q)
| EVAL parts = SPLIT(q, ".")
| WHERE MV_COUNT(parts) >= 3
// Registrable parent: last three labels for com.au-style suffixes, otherwise last two.
| EVAL sld = MV_SLICE(parts, -2, -2)
| EVAL parent = CASE(sld IN ("com", "net", "org", "gov", "edu", "asn", "id", "co", "ac"),
                     MV_CONCAT(MV_SLICE(parts, -3, -1), "."), MV_CONCAT(MV_SLICE(parts, -2, -1), "."))
// Exchange's DNS blocklist and SPF lookups are tunnel-shaped by design and run on only a few servers, so rarity can't remove them.
| WHERE NOT COALESCE(data.ContextBaseFileName, "") IN ("MSExchangeTransport.exe", "MSExchangeFrontendTransport.exe",
                                                       "MSExchangeSubmission.exe", "MSExchangeDelivery.exe")
// Tunnels encode data in a long first label, or use TXT (16) and NULL (10) records.
| EVAL label_len = LENGTH(MV_FIRST(parts)),
       long_label = CASE(label_len >= 30, 1, 0),
       odd_type = CASE(TO_STRING(data.RequestType) IN ("16", "10"), 1, 0)
// One row per host and parent.
| STATS names = COUNT_DISTINCT(q), queries = COUNT(*), long_names = SUM(long_label), odd_types = SUM(odd_type),
        max_label = MAX(label_len), hostnames = VALUES(host.name), procs = VALUES(data.ContextBaseFileName),
        sample = VALUES(q), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
    BY host.id, parent
// Rarity: every host that looked up names under this parent, counted before the tunnel checks.
// Your internal domains, CDNs and security-vendor lookups run across the fleet and drop out here.
| INLINE STATS hosts = COUNT_DISTINCT(host.id) BY parent
// Tunnel: 100+ distinct names with 20+ long labels or 20+ TXT/NULL queries, under a parent at most 3 hosts look up.
| WHERE names >= 100 AND (long_names >= 20 OR odd_types >= 20) AND hosts <= 3
| EVAL sample = MV_SLICE(sample, 0, 9)
```

**CrowdStrike (Falcon LogScale / Advanced Event Search), run over the last 1 hour**
```logscale
#event_simpleName=DnsRequest DomainName=*
// Lower-case, drop a trailing dot, and keep names with three or more labels.
| DomainName=/^(?<q>.+?)\.?$/
| q := lower(q)
| q=/\..*\./
// Registrable parent: last three labels for com.au-style suffixes, otherwise last two.
| q=/(?<sld>[^.]*)\.[^.]*$/
| case {
    in(field="sld", values=["com", "net", "org", "gov", "edu", "asn", "id", "co", "ac"]) | q=/(?<parent>[^.]*\.[^.]*\.[^.]*)$/;
    * | q=/(?<parent>[^.]*\.[^.]*)$/;
  }
// Exchange's DNS blocklist and SPF lookups are tunnel-shaped by design and run on only a few servers.
| !in(field="ContextBaseFileName", values=["MSExchangeTransport.exe", "MSExchangeFrontendTransport.exe",
                                          "MSExchangeSubmission.exe", "MSExchangeDelivery.exe"])
// Tunnels encode data in a long first label, or use TXT (16) and NULL (10) records.
| q=/^(?<label1>[^.]*)/
| label_len := length(label1)
| case { test(label_len >= 30) | long_label := 1; * | long_label := 0; }
| case { in(field="RequestType", values=["16", "10"]) | odd_type := 1; * | odd_type := 0; }
// One row per host and parent.
| groupBy([aid, parent], function=[count(q, distinct=true, as=names), sum(long_label, as=long_names), sum(odd_type, as=odd_types),
                                   max(label_len, as=max_label), collect([ComputerName, ContextBaseFileName]),
                                   collect([q], limit=10)], limit=max)
// Mark the tunnel-shaped rows. Every host still counts towards rarity below.
| case { test(names >= 100 AND (long_names >= 20 OR odd_types >= 20)) | tunnel_host := aid; * ; }
// Rarity: one row per parent, counting every host that looked it up. Keep parents with a tunnel and at most 3 hosts.
| groupBy([parent], function=[count(aid, distinct=true, as=hosts), max(names, as=names), max(long_names, as=long_names),
                              max(odd_types, as=odd_types), collect([tunnel_host, ComputerName, ContextBaseFileName, q])], limit=max)
| test(hosts <= 3)
| tunnel_host=*
```
Run every 15 minutes with a 1-hour lookback, and no time bucket. Suppress by `host.id`, `parent` for 24h. LogScale has no `INLINE STATS`, so its version rolls up to one row per parent, listing the tunnel host and the at most three hosts that looked it up.

- **Rarity replaces the exclusion list.** A parent that more than three hosts look up in the hour (your internal domains, CDNs, antivirus cloud lookups) is shared infrastructure, not a tunnel. The only exclusion left is Exchange, whose blocklist lookups run on just a few servers. If another mail gateway does blocklist lookups, exclude it by host.
- **Why the parent logic matters for you:** with a plain "last two labels", every `.com.au` domain would group under `com.au` and the rule would fire on Australian web browsing.
- **`data.RequestType`:** check it exists in your feed and holds numbers. If it doesn't, delete the `odd_type` lines and keep the long-label condition.

## Before vs after

| | Before | After |
|---|---|---|
| Can fire | No (`like "."`) | Yes |
| Signal | 50 repeats of one name | 100+ distinct names under one parent, with long labels or TXT/NULL queries |
| Catches iodine / dnscat2 / Cobalt Strike DNS beacons | No | Yes |
| Exclusions to maintain | ~60 suffixes, duplicated with trailing dots, plus 14 processes | 4 Exchange processes; rarity (3 hosts or fewer) replaces the suffix list |
| Bucket-edge splits | Yes (15-minute buckets) | No |
| `.com.au` handling | n/a | Explicit |

## Test
On a lab host, run 150 lookups of random 40-character labels under a domain you control, e.g. `Resolve-DnsName ("{0}.test.yourlabdomain.com" -f (-join (1..40 | % {[char](97 + (Get-Random 26))})))` in a loop. One alert should arrive for that parent.
