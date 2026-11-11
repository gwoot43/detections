---
id: CS31
name: ligolo-ng pivot - the agent dialling out, the proxy listening on 11601, or its tunnel flags
category: crowdstrike-fdr
status: todo
language: esql
index: logs-yourorg-crowdstrike-data-default*
mitre: [T1572, T1090.001, T1021]
data_source: CrowdStrike FDR NetworkListenIP4 / NetworkConnectIP4 and ProcessRollup2
suppression:
  fields: [host.id, process.name]
  duration: 24h
  missing_fields: do_not_suppress
---

## Why this is high fidelity

ligolo-ng is the pivot of the moment: a **proxy** on the attacker's host and an **agent** on the compromised one.
The agent dials out to the proxy - **default TCP 11601** - the proxy brings up a TUN interface, and the operator then
reaches the internal network as if directly attached. It can also expose SOCKS and forward ports, which is what makes
it a full replacement for chisel and for a signed binary used as a SOCKS proxy.

There is no certificate to key on: the proxy uses a self-signed certificate by default (`-selfcert`) and the agent
pins a fingerprint. So the anchors are the **port**, the **flags**, and the **topology** - and only the topology
survives a renamed binary on a non-default port.

`CS30` is the topology rule (internal fan-in bridged to one external peer). This rule is the cheap one that fires
first.

## Query

Run every 15 minutes with a 1-hour lookback.

```esql
FROM logs-yourorg-crowdstrike-data-default*
| WHERE @timestamp >= NOW() - 1 hour
  AND event.action IN ("networklistenip4", "networkconnectip4")
| EVAL proc = TO_LOWER(COALESCE(process.name, "")),
       cmd = TO_LOWER(COALESCE(process.command_line, "")),
       // a listen event carries its own port in source.port; a connect event carries the peer's in destination.port
       port = CASE(event.action == "networklistenip4", source.port, destination.port),
       peer = TO_STRING(destination.ip)
// the default port in either direction, the pinning flag, or the tool by name
| WHERE port == 11601
     OR cmd LIKE "*--accept-fingerprint*"
     OR cmd LIKE "*ligolo*"
     OR proc LIKE "ligolo*"
     OR (proc IN ("agent", "agent.exe", "proxy", "proxy.exe") AND cmd LIKE "*--connect*")
| STATS events = COUNT(*), ports = MV_SLICE(VALUES(port), 0, 5),
        peers = MV_SLICE(VALUES(peer), 0, 5),
        first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
    BY host.id, host.name, proc
// Baseline: zero. 11601 is ligolo's default and nothing else in a corporate estate listens or connects there. If a
// legitimate user ever appears, allowlist that host - do not raise the port test.
| WHERE events >= 1
| SORT first_seen DESC
| LIMIT 50
```

## Reading the alert

- **A listener on 11601 on an internal host** is the agent side in `-bind` mode, or a proxy run *inside* the estate -
  the second is worse, because it means the attacker has a foothold on both ends.
- **An outbound connection to 11601** is the agent dialling the operator's proxy. The `peer` is the attacker's
  address and is the thing to block.
- **The flag `--accept-fingerprint`** appears on the agent command line and nowhere else in a normal estate - it is
  the strongest single string in the rule.

## Nearest benign twins

- **A security team testing the tool** - allowlist by host and by the engagement window.
- **A port collision with a developer service.** Rare on 11601; confirm with `CS11` (the program accepting internal
  connections) rather than assuming.

## What it misses

- **A renamed agent on a non-default port.** Then only `CS30` (bridge topology) or `CS11` (rare acceptor) sees it.
- **The proxy outside the estate.** Only the agent's outbound connection is visible, which is why the port test
  matters - the operator's address is never in your data.
- **Tunnelling over the agent's SOCKS into internal services.** That traffic is `CS21`-shaped (fan-out) rather than
  ligolo-shaped.

## Test

```esql
FROM logs-yourorg-crowdstrike-data-default*
| WHERE @timestamp >= NOW() - 30 days
  AND event.action IN ("networklistenip4", "networkconnectip4")
| EVAL port = CASE(event.action == "networklistenip4", source.port, destination.port)
| WHERE port == 11601
| STATS events = COUNT(*) BY host.name, event.action
| SORT events DESC
| LIMIT 20
```

If this is empty - which is the expected answer - the rule has a zero baseline and can be enabled without tuning.
