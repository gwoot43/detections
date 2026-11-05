---
id: CS28
name: DNS tunnelling seen from the resolver - unique-name ratio on the host every client's queries pass through
category: crowdstrike-fdr
status: todo
language: esql
index: logs-yourorg-crowdstrike-data-default*
mitre: [T1071.004, T1048.003]
data_source: CrowdStrike FDR DnsRequest events on the estate's DNS servers
suppression:
  fields: [host.id, dns.question.registered_domain]
  duration: 24h
  missing_fields: do_not_suppress
---

## Why this is high fidelity

`CS03` runs on the client, which means it only sees hosts that run the sensor. A tunnel from an unmanaged machine,
a BYOD laptop or a device with a broken agent is invisible to it. But every query still has to be **recursed by
your resolver**, so the same logic run on the resolver's host covers the whole estate, including the machines you
cannot see.

The property is the same one `CS03` uses, and it is the property a tunnel cannot avoid: a tunnel asks for a name
that has never been asked before, every time. A resolver handling normal traffic sees the same names over and over,
so its **uniqueness ratio** is low even when its volume is enormous.

## Query

```esql
FROM logs-yourorg-crowdstrike-data-default*
| WHERE @timestamp >= NOW() - 15 minutes
  AND event.action == "dnsrequest"
// the resolver's own host: replace with your DNS servers, or keep it wide and rely on the ratio below
  AND host.name IN ("<dns-server-1>", "<dns-server-2>")
| EVAL name = TO_LOWER(TO_STRING(dns.question.name)),
       parent = TO_LOWER(TO_STRING(dns.question.registered_domain)),
       label_len = LENGTH(MV_FIRST(SPLIT(TO_LOWER(TO_STRING(dns.question.name)), "."))),
       qtype = TO_UPPER(TO_STRING(dns.question.type))
| WHERE name IS NOT NULL AND parent IS NOT NULL AND parent != "" AND NOT name LIKE "*.arpa"
| STATS queries = COUNT(*), names = COUNT_DISTINCT(name, 40000),
        long_names = COUNT(*) WHERE label_len >= 30,
        odd_types = COUNT(*) WHERE qtype IN ("TXT", "NULL"),
        max_label = MAX(label_len),
        sample = MV_SLICE(VALUES(name), 0, 5),
        clients = MV_SLICE(VALUES(source.ip), 0, 5)
    BY host.name, parent
| EVAL unique_ratio = ROUND(names::double / queries, 2)
// A resolver's normal traffic repeats: ratio stays well under 0.5 even at high volume. A tunnel is >= 0.9 with
// long labels. Baseline: measure the ratio per parent over a week; the estate's real maximum is your floor.
| WHERE queries >= 20 AND long_names >= 3 AND unique_ratio >= 0.9 AND max_label >= 30
| SORT queries DESC
| LIMIT 50
```

## Reading the alert

- **`clients` is the payoff.** The resolver sees which internal address asked, so an alert here gives you the
  tunnelling host even when that host has no agent - which is the whole reason this rule exists.
- **`odd_types`** non-zero strengthens it: `TXT` and `NULL` carry the most data per query and almost no legitimate
  client asks for `NULL`.
- **`parent`** is the tunnel's domain. Check registration age and whether anyone in the estate has a business
  relationship with it.

## Nearest benign twins

- **A content delivery or telemetry domain** with per-request unique subdomains (some CDN and ad-tech names do
  this). Those are high-volume but they come from many clients; the `clients` sample shows a spread rather than one.
- **A vulnerability scanner or mail gateway** doing DNSBL lookups - reversed names, so they carry `.arpa` or a
  fixed suffix and are excluded above.
- **DNSSEC or zone-transfer traffic** from a secondary server. Allowlist the secondary's address.

## What it misses

- **DoH.** If clients resolve over HTTPS, the resolver never sees the query. `CS27` covers a client that skips the
  resolver; `N09` covers DoH through the proxy.
- **A tunnel that reuses names** (a fixed set with data encoded in the answer, not the question). Ratio stays low.
- **A resolver that is not a Falcon host.** If DNS is forwarded by a firewall or a cloud resolver, this rule has no
  data - confirm with the test below before relying on it.

## Test

```esql
FROM logs-yourorg-crowdstrike-data-default*
| WHERE @timestamp >= NOW() - 24 hours AND event.action == "dnsrequest"
| STATS queries = COUNT(*), hosts = COUNT_DISTINCT(host.id) BY host.name
| SORT queries DESC
| LIMIT 20
```

The DNS servers must appear near the top. If they do not, the sensor is not logging the resolver's own queries and
this rule cannot fire - fall back to `CS03` on the clients.
