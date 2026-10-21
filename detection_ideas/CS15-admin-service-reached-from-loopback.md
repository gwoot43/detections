---
id: CS15
name: RDP or SSH reached from the host itself (traffic relayed in by a tunnel, whatever it's called)
category: crowdstrike-fdr
status: todo
language: esql
index: logs-yourorg-crowdstrike-data-default*
mitre: [T1572, T1021.001, T1021.004]
data_source: CrowdStrike FDR NetworkReceiveAcceptIP4/IP6 (and Windows Security 4624 as a second source)
suppression:
  fields: [host.id, destination.port]
  duration: 24h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
CS14 recognises tunnel services it knows. This rule catches any tunnel by what it does when it exposes the host's own RDP or SSH. The tunnel program receives the attacker's traffic over its outbound connection and hands it to the local service, so RDP or SSH accepts a connection from the host itself (`127.0.0.1` or `::1`). Real RDP and SSH come from other machines. This happens whatever the tunnel is: cloudflared, ngrok, `ssh -R`, `plink -R`, frp, chisel, a custom implant or a relay on the attacker's own server.

- **Anchor:** RDP (3389) or SSH (22) on this host accepting a connection from a loopback address.
- **Corroborating property:** none needed: the loopback source is the tunnel.
- **Exclusion by newness:** the host must not have done this in the previous 7 days. A host where it's routine (a local SSH health check, an RD Gateway that forwards to RDP on the same server) has it in its history and stays quiet, with no list of hosts to keep.

This covers a tunnel exposing the host it runs on. A tunnel used to pivot to other internal hosts (a SOCKS proxy through chisel or ligolo) looks like ordinary RDP from that host on the target; that's B04 (fan-out), CS10 (from a web server) and CS11 (a new listener). Beaconing (B06) rarely sees tunnels: an agent holds one long-lived connection, so there's no cadence to measure.

## Query
Run hourly with a 7-day lookback.
```esql
FROM logs-yourorg-crowdstrike-data-default*
// Anchor: RDP or SSH on this host accepting a connection from the host itself.
// Real RDP and SSH come from other machines, so a loopback source means something here is relaying traffic in.
| WHERE event.action IN ("networkreceiveacceptip4", "networkreceiveacceptip6") AND destination.port IN (3389, 22)
  AND CIDR_MATCH(source.ip, "127.0.0.0/8", "::1/128")
// One row per host and service: when this first happened in the 7 days, and how often.
| STATS first_seen = MIN(@timestamp), last_seen = MAX(@timestamp), connections = COUNT(*),
        process.name = VALUES(process.name), host.name = VALUES(host.name)
    BY host.id, destination.port
// New in the last 2 hours (two hourly runs). Hosts where it's routine have it in their history and stay quiet.
| WHERE first_seen >= NOW() - 2 hours
```

**CrowdStrike (Falcon LogScale / Advanced Event Search)**, run over the last 7 days:
```logscale
#event_simpleName=/^(NetworkReceiveAcceptIP4|NetworkReceiveAcceptIP6)$/
// Anchor: RDP or SSH on this host accepting a connection from the host itself.
| in(field="LocalPort", values=["3389", "22"])
| RemoteAddress := coalesce([RemoteAddressIP4, RemoteAddressIP6])
| cidr(RemoteAddress, subnet=["127.0.0.0/8", "::1/128"])
// One row per host and service: when this first happened in the 7 days, and how often.
| groupBy([aid, LocalPort], function=[min(@timestamp, as=first_seen), max(@timestamp, as=last_seen), count(as=connections),
                                      collect([ComputerName, ContextBaseFileName])], limit=max)
// New in the last 2 hours (two hourly runs). Hosts where it's routine have it in their history and stay quiet.
| _now := now()
| test(first_seen > _now - 7200000)
```

**Check that Falcon records loopback connections.** Run `FROM logs-yourorg-crowdstrike-data-default* | WHERE event.action == "networkreceiveacceptip4" AND CIDR_MATCH(source.ip, "127.0.0.0/8") | STATS COUNT(*) BY destination.port` over a day. Any rows at all (local services talk to each other constantly) mean it does. If there are none, use the Windows Security version below for RDP.

**Same detection in the Windows Security log (RDP only)**, run hourly with a 7-day lookback:
```esql
FROM logs-system.security*, logs-windows.forwarded*
// An RDP logon (type 10) whose source is the host itself: the session came in through a tunnel on that host.
| WHERE event.code == "4624" AND TO_STRING(winlog.event_data.LogonType) == "10"
  AND CIDR_MATCH(source.ip, "127.0.0.0/8", "::1/128")
// One row per host (with event forwarding, host.name is the collector, so use the computer name).
| STATS first_seen = MIN(@timestamp), last_seen = MAX(@timestamp), logons = COUNT(*), user.name = VALUES(user.name)
    BY winlog.computer_name
// New in the last 2 hours, as above.
| WHERE first_seen >= NOW() - 2 hours
```
`user.name` here is the account the attacker logged in with through the tunnel.

## Suppression
Suppress by `host.id`, `destination.port` for 24h (`winlog.computer_name` for the Windows version). Alerts missing a key field are not suppressed. Aggregating rule: the 7-day lookback overlaps every run, and a host alerts once, when it starts.

## Known false positives / exclusions
- A new RD Gateway, Guacamole or similar remote-access gateway installed on the same server as the RDP or SSH it serves. It alerts once, then has a history.
- A monitoring check or script newly set up to connect to the host's own SSH. Same: once, then history.

## Triage
- Find the tunnel: the program on this host that made outbound connections around `first_seen`, especially to a public address it doesn't usually reach (FDR network events, CS14, W10). On Windows, `netstat -ano` shows the program holding the loopback connection to 3389.
- Look at who logged in: 4624 logon type 10 from `127.0.0.1` gives the account. Assume it's compromised.
- Contain the host and kill the tunnel program. Check the other hosts that account logged on to.

## Test
On a lab Windows host with RDP on, run `ssh -R 13389:localhost:3389 <lab server>`, then RDP to port 13389 on the lab server. The lab host's RDP should accept a connection from `127.0.0.1` and alert once.
