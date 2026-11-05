---
id: CS27
name: Endpoint sends DNS straight to an external resolver, skipping the estate resolver
category: crowdstrike-fdr
status: todo
language: esql
index: logs-yourorg-crowdstrike-data-default*
mitre: [T1071.004, T1572, T1562.006]
data_source: CrowdStrike FDR NetworkConnectIP4/IP6
suppression:
  fields: [host.id, process.name]
  duration: 24h
  missing_fields: do_not_suppress
---

## Why this is high fidelity

`CS03` detects a DNS tunnel by the shape of the queries, but its own blind-spot note says the limit out loud:
DoH never reaches the DNS event at all. This rule closes the cheaper half of that gap. A client that sends port 53
traffic to an address outside the estate has bypassed the resolver your logging depends on - and on a normal
Windows or Linux estate the baseline is **zero**, because the resolver is handed out by DHCP or set by policy.

It catches three things at once: a tunnel aimed at a public resolver, a test of whether DNS logging can be evaded,
and a misconfiguration that has been quietly blinding you for months. TCP/53 is included on purpose - a client that
switches to TCP for DNS is either doing a zone transfer or moving more data than a query.

## Query

```esql
FROM logs-yourorg-crowdstrike-data-default*
| WHERE @timestamp >= NOW() - 1 hour
  AND event.action IN ("networkconnectip4", "networkconnectip6")
  AND destination.port == 53
| EVAL dst = TO_STRING(destination.ip),
       proc = TO_LOWER(COALESCE(process.name, ""))
// anything inside the estate or link-local is your resolver, a forwarder or a peer - not the case here
| WHERE NOT CIDR_MATCH(dst, "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8",
                      "169.254.0.0/16", "fc00::/7", "fe80::/10")
| STATS connections = COUNT(*), resolvers = COUNT_DISTINCT(dst),
        resolver_sample = MV_SLICE(VALUES(dst), 0, 5),
        first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
    BY host.id, host.name, proc
// Baseline is zero: on this estate every client uses the estate resolver, so a single connection is the alert.
// If your policy is a public resolver (Zscaler DNS, a cloud forwarder), allowlist it by address here rather than
// raising the threshold - the rule is about *which* resolver, not how often.
| WHERE connections >= 1
| SORT connections DESC
| LIMIT 50
```

## Reading the alert

- **The process matters more than the host.** `chrome.exe` reaching a public resolver is a browser with DoH or a
  hard-coded fallback; `svchost.exe`, `nslookup`, `dig` or a Python binary is someone testing the path.
- **One resolver, many hosts** is a policy or a proxy. **One host, several resolvers** is evasion - a tunnel that
  rotates to stay under per-destination volume limits.
- If the destination is a known DoH provider's address on port 53, treat it as deliberate: no legitimate client
  sends plain DNS to `1.1.1.1` when it has an internal resolver.

## Nearest benign twins

- **A VPN or Zscaler client** that installs its own resolver for the duration of a session. Allowlist the client
  process, not the host.
- **A container or dev sandbox** with `/etc/resolv.conf` set to `8.8.8.8` by an image default. Fix the image; the
  rule is telling you the truth.
- **A guest or BYOD network** where the resolver is not yours. Those hosts should not be in this index at all.

## What it misses

- **DoH and DoT.** A tunnel over HTTPS never sends a packet to port 53. `CS03` states the same limit; `N09` catches
  DoH through the proxy, which covers managed traffic but not a direct connection.
- **DNS tunnelled over another protocol** (ICMP, or inside an existing HTTPS session) - no port 53 anywhere.
- **A resolver that forwards to a public one.** If your own resolver recurses to `8.8.8.8`, that connection is on
  the resolver's host, and this rule will flag the resolver itself. Exclude the resolver's host, and cover it with
  `CS28` instead.

## Test

```esql
FROM logs-yourorg-crowdstrike-data-default*
| WHERE @timestamp >= NOW() - 24 hours
  AND event.action IN ("networkconnectip4", "networkconnectip6")
  AND destination.port == 53
| STATS connections = COUNT(*), internal = COUNT(*) WHERE CIDR_MATCH(TO_STRING(destination.ip), "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
    BY host.name
| SORT connections DESC
| LIMIT 20
```

If `connections` equals `internal` everywhere, no client is bypassing the resolver and this rule will be silent
until one does - which is exactly what you want it for.
