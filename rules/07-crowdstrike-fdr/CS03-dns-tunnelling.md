---
id: CS03
name: DNS tunnelling — uniqueness, not volume
category: crowdstrike-fdr
status: todo
language: esql
index: logs-yourorg-crowdstrike-data-default*
mitre: [T1071.004, T1572, T1048.003]
data_source: CrowdStrike FDR DnsRequest / SuspiciousDnsRequest events
suppression:
  fields: [host.id]
  duration: 24h
  missing_fields: do_not_suppress
---
Tunnels (iodine, dnscat2, dns2tcp, Cobalt Strike's DNS beacon, and most exfil frameworks) move data by encoding it into the **leftmost label** of a query name. That produces a property no legitimate name resolution shares: **every query is a name that has never been asked before**, because each one carries new payload. A CDN, a telemetry endpoint, a resolver retry and a browser all repeat names constantly.

That is the lever the older rule missed. It counted distinct names (100+) and long labels (20+), which is a *volume* test: a fast tunnel trips it, a slow one - 30 queries a minute, the realistic rate - does not, and a noisy vendor domain trips it anyway. Uniqueness and fleet rarity do the work with numbers that fit a slow tunnel.

```esql
FROM logs-yourorg-crowdstrike-data-default*
// One hour, stated in the query. Tunnelling is continuous, so a longer lookback adds noise rather than signal.
| WHERE @timestamp >= NOW() - 1 hour
  AND event.action == "dnsrequest"
| EVAL name = TO_LOWER(TO_STRING(dns.question.name)),
       parent = TO_LOWER(TO_STRING(dns.question.registered_domain)),
       qtype = TO_UPPER(TO_STRING(dns.question.type))
// Blind spot, stated in the query: DoH/DoT never reach this event. An encrypted-DNS request is a TCP/443
// (or :853) connection to the resolver, so it is a network-rule problem, not a dnsrequest. This rule only
// sees cleartext DNS the sensor resolves on the host - a tunnel over DoH is invisible here by construction.
// Reverse lookups are the resolver talking to itself and carry no payload.
| WHERE name IS NOT NULL AND parent IS NOT NULL AND parent != "" AND NOT name LIKE "*.arpa"
// DNS blocklists / RBLs reverse IP octets into the leftmost label, so they are tunnel-shaped by design and
// fleet rarity will NOT drop them (they run on one or two mail gateways). Excluded by target domain here -
// a list of targets ages slowly, unlike a list of tools. Folded into the gate rather than left as prose.
  AND NOT parent IN ("spamhaus.org", "spamcop.net", "surbl.org", "uribl.com", "barracudacentral.org",
                     "spamhaus.net", "sophosxl.net", "senderbase.org", "spamrl.com")
| EVAL label1 = MV_FIRST(SPLIT(name, ".")),
       label_len = LENGTH(label1),
// TXT and NULL are the data channels; a tunnel on A/AAAA is just the same thing with smaller payloads.
       odd_type = qtype IN ("TXT", "NULL", "CNAME", "SRV", "MX")
| STATS queries = COUNT(*),
        names = COUNT_DISTINCT(name, 40000),
        long_names = COUNT(*) WHERE label_len >= 30,
        avg_label = ROUND(AVG(label_len), 1),
        odd_queries = COUNT(*) WHERE odd_type,
        max_label = MAX(label_len),
        sample = MV_SLICE(VALUES(name), 0, 6),
        pids = MV_SLICE(VALUES(process.entity_id), 0, 5)
    BY host.id, host.name, parent
// Every name distinct is the tunnel: new data in every label. 0.9 rather than 1.0 because a retried query
// and a keepalive repeat occasionally. long_ratio is the fidelity lever - the fraction of queries carrying a
// long label, not an absolute count, so most of the traffic has to be encoder output, not five names in a flood.
| EVAL unique_ratio = ROUND(names::double / queries, 2),
       long_ratio = ROUND(long_names::double / queries, 2)
// Fleet rarity: a domain only this host resolves. Vendor, CDN and AV-cloud domains are resolved estate-wide,
// which removes them without a list to maintain.
| INLINE STATS parent_hosts = COUNT_DISTINCT(host.id) BY parent
// 20 queries over an hour is a slow tunnel - the old 100 was a fast-tunnel test. The tighteners that raise
// fidelity: long_ratio >= 0.5 means most lookups are long-labelled (a sustained encoder, not a benign domain
// with five long names among hundreds), and avg_label >= 20 backs it with the central tendency, not one spike.
// Every number is a starting value; the baseline below tunes them.
| WHERE queries >= 20 AND unique_ratio >= 0.9 AND long_ratio >= 0.5
  AND avg_label >= 20 AND max_label >= 30 AND parent_hosts <= 3
| SORT queries DESC
| LIMIT 100
```

## Reading the alert
- **`unique_ratio`** at or near 1.0 is the tunnel. Between 0.9 and 1.0 with a handful of long labels is a slow encoder; 1.0 with short labels is usually a hash-lookup service.
- **`long_ratio` and `avg_label`** are the fidelity pair. `long_ratio` near 1.0 with `avg_label` in the 30s-60s is a sustained encoder - every lookup carries payload. A low `long_ratio` with a high `max_label` is a service that emitted one long name and should not fire; that is the case the old absolute `long_names >= 5` count let through.
- **`odd_queries`** shows whether the channel uses TXT/NULL (bulk data) or plain A/AAAA (beacon and small exfil).
- **`max_label`** at 50-63 is a tunnel filling the label limit (63 bytes). Anything consistently at 63 is deliberate.
- **`sample`** should look like base32/base64 - case-insensitive alphanumerics, no words, no hyphens forming a hostname prefix.
- **`pids`** is the only attribution available: DNS events carry no process name. Resolve the `process.entity_id` against `processrollup2`; browser = probably a CDN, `powershell.exe`/`rundll32.exe`/unsigned binary = tunnelling.

## Nearest benign twins
- **DNS blocklist lookups** (spamhaus, surbl, barracudacentral) reverse the octets into the label and are tunnel-shaped by design. They run on mail gateways, so `parent_hosts <= 3` does not remove them - the exact-name exclusion **now folded into the gate** (`NOT parent IN (...)`) is what does. It is a list of *targets*, not of tools, which is the one kind of list that ages slowly; add to that clause in the query as you find more RBL/reputation domains in your estate.
- **Security products resolving hashes or encoded identifiers under their own cloud domain** from one or two hosts. Confirm once and exclude that parent by name.
- **Printer, IoT and patch-management lookups** with long serial-number labels. One host, repeated names - the uniqueness ratio drops them.
- **A newly deployed SaaS client** in its first hours, which resolves one vendor domain from a handful of hosts. `queries >= 20` and the uniqueness test usually hold it off; if it persists, it is an entity pair.

## What it misses
- **Encrypted or tunnelled-over-HTTPS DNS** (DoH), which never reaches this event at all. Falcon sees the connection to the resolver, not the names.
- **A tunnel that reuses names** - a very slow beacon with a fixed label (`id123.beacon.evil.com`) is a beacon, not a tunnel, and belongs to the C2-beacon family instead.
- **A tunnel through an internal recursive resolver** that the sensor never sees (sensorless segments, appliances).
- **A domain the whole estate resolves** legitimately: `parent_hosts <= 3` is what keeps CDNs out, and it also hides a tunnel whose domain is shared - rare, but real for commodity C2 infrastructure.
- **Payload in the response**, which has no volume field here. Response-size analysis would separate a tunnelled download from a chatty resolver; it is not in this feed.

## Baseline
```esql
FROM logs-yourorg-crowdstrike-data-default*
| WHERE @timestamp >= NOW() - 7 days
  AND event.action == "dnsrequest"
| EVAL name = TO_LOWER(TO_STRING(dns.question.name)),
       parent = TO_LOWER(TO_STRING(dns.question.registered_domain)),
       label_len = LENGTH(MV_FIRST(SPLIT(name, ".")))
| WHERE parent != "" AND NOT name LIKE "*.arpa"
| STATS queries = COUNT(*), names = COUNT_DISTINCT(name, 40000), long_names = COUNT(*) WHERE label_len >= 30,
        avg_label = ROUND(AVG(label_len), 1)
    BY host.id, parent
| EVAL unique_ratio = ROUND(names::double / queries, 2),
       long_ratio = ROUND(long_names::double / queries, 2)
// Second STATS on purpose: the first one is per host and parent, this one rolls up per host so the estate's
// noisiest resolvers sort to the top. This is the baseline - the source for every threshold in the rule,
// long_ratio and avg_label included.
| STATS pairs = COUNT(*), p99_queries = PERCENTILE(queries, 99), max_queries = MAX(queries),
        p99_unique = PERCENTILE(unique_ratio, 99), p99_long_ratio = PERCENTILE(long_ratio, 99),
        p99_avg_label = PERCENTILE(avg_label, 99)
    BY host.id
| SORT max_queries DESC
| LIMIT 30
```
Read the top rows for `unique_ratio` before tuning: the estate's noisiest resolvers are the number `parent_hosts <= 3` and `queries >= 20` have to survive.

## Probe before enabling
The rule needs the parsed ECS DNS fields, not the raw FDR ones:
```esql
FROM logs-yourorg-crowdstrike-data-default*
| WHERE @timestamp >= NOW() - 1 hour
  AND event.action == "dnsrequest"
| STATS n = COUNT(*), named = COUNT(*) WHERE dns.question.name IS NOT NULL,
        parented = COUNT(*) WHERE dns.question.registered_domain IS NOT NULL
```
`parented` at zero means the pipeline does not compute the registrable domain, and the rule silently dies - fall back to the last two labels (`MV_CONCAT(MV_SLICE(SPLIT(name, "."), -2, -1), ".")`), knowing that `co.uk`-style suffixes will merge unrelated sites.

## References
- MITRE T1071.004 (DNS application-layer protocol), T1048.003 (exfil over non-C2 protocol), T1572 (protocol tunnelling)
- Born & Gustafson, *Detecting DNS Tunnels Using Character Frequency Analysis* (2010) - the entropy/label-analysis approach this rule approximates without an entropy function
- Tool families whose shapes this catches: iodine, dnscat2, dns2tcp, Heyoka, Cobalt Strike DNS beacon
- `archive/07-crowdstrike-fdr/CS03-dns-tunnelling.md` - the volume-based version this replaces, and why it missed slow tunnels
