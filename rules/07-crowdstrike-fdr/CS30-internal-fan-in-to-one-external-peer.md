---
id: CS30
name: Internal fan-in bridged to exactly one external peer - the reverse tunnel's shape
category: crowdstrike-fdr
status: todo
language: esql
index: logs-yourorg-crowdstrike-data-default*
mitre: [T1090.001, T1572, T1021]
data_source: CrowdStrike FDR NetworkReceiveAcceptIP4 and NetworkConnectIP4/IP6
suppression:
  fields: [host.id]
  duration: 24h
  missing_fields: do_not_suppress
---

## Why this is high fidelity

Every reverse tunnel does the same thing, whatever binary carries it: many internal peers connect **in** to one
host and port, and that host carries all of it **out** over a single external connection. chisel with `R:socks`,
ligolo, `socat`, a self-hosted ngrok edge, an SSH `-R` into a VPS - the topology is identical because the topology
*is* the technique.

`CS11` asks whether the accepting program is rare and new; that misses a pivot running under a common or signed
binary name. This rule asks a different question: **does this host have exactly one external peer while several
internal peers are connecting in?** A normal server has many external peers (updates, telemetry, APIs) or none. A
pivot has precisely one, because it is a single channel.

## Query

```esql
FROM logs-yourorg-crowdstrike-data-default*
| WHERE @timestamp >= NOW() - 30 minutes
  AND event.action IN ("networkreceiveacceptip4", "networkreceiveacceptip6", "networkconnectip4", "networkconnectip6")
| EVAL is_inbound = event.action IN ("networkreceiveacceptip4", "networkreceiveacceptip6"),
       peer = TO_STRING(source.ip),
       dst = TO_STRING(destination.ip),
       internal_peer = CIDR_MATCH(peer, "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"),
       external_dst = NOT CIDR_MATCH(dst, "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
                                     "127.0.0.0/8", "169.254.0.0/16", "fc00::/7", "fe80::/10")
| STATS inbound_peers = COUNT_DISTINCT(peer) WHERE is_inbound AND internal_peer,
        inbound_conns = COUNT(*) WHERE is_inbound AND internal_peer,
        external_peers = COUNT_DISTINCT(dst) WHERE NOT is_inbound AND external_dst,
        external_conns = COUNT(*) WHERE NOT is_inbound AND external_dst,
        ports = MV_SLICE(VALUES(destination.port), 0, 5),
        sample_peers = MV_SLICE(VALUES(peer), 0, 10),
        first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
    BY host.id, host.name
// 3+ internal peers arriving while the host holds exactly one external peer: a bridge. Baseline: a normal server
// either has no external peer in the window or several (CDN, update and API endpoints are different addresses),
// so `external_peers == 1` is the discriminating part, not the count of internal peers.
| WHERE inbound_peers >= 3 AND external_peers == 1 AND external_conns >= 3
| SORT inbound_peers DESC
| LIMIT 50
```

## Reading the alert

- **`sample_peers`** is the blast radius: the hosts that reached the pivot are the ones the attacker can now reach.
- **`ports`** on the inbound side tells you what was being tunnelled - one port used by many peers is a proxy;
  many ports from few peers is a scan.
- **`external_peers == 1` with high `external_conns`** is a persistent channel rather than a lookup.

## Nearest benign twins

- **A jump host or VDI gateway.** It has many internal peers in and usually **several** external peers; and it
  listens on a documented port. Allowlist by host.
- **A build or package proxy** (an internal mirror fetching from one upstream). The external peer count of one fits,
  but the inbound peers are all build agents and the port is the mirror's.
- **A monitoring collector** shipping to one SaaS endpoint. Outbound only - `inbound_peers` will be zero.

## What it misses

- **A tunnel that multiplexes over several external peers** (round-robin to defeat exactly this rule). Then
  `external_peers > 1` and the shape looks like a normal client.
- **Fan-in below the threshold.** A quiet pivot used by two peers stays under 3; tune to your own `CS11` baseline.
- **A tunnel over UDP.** FDR records UDP connections separately; if the transport is QUIC, confirm the sensor logs
  `networkconnectip4` rows for it (the same probe `CS14` documents).

## Test

```esql
FROM logs-yourorg-crowdstrike-data-default*
| WHERE @timestamp >= NOW() - 24 hours
  AND event.action IN ("networkreceiveacceptip4", "networkreceiveacceptip6")
| STATS peers = COUNT_DISTINCT(source.ip), conns = COUNT(*) BY host.id, host.name, destination.port
// baseline: this is the fan-in population of the estate itself - 3 is the rule's starting value, and whatever
// sits above it here is what the rule would have alerted on before you enabled it
| WHERE peers >= 3
| SORT peers DESC
| LIMIT 30
```

Run it before enabling: the hosts at the top are your real fan-in population (file servers, RDP gateways, mail).
Anything there that you did not expect is the rule finding something already.
