---
id: CS14
name: Tunnel service agent running on an endpoint (Cloudflare, ngrok, Tailscale, ZeroTier, SSH tunnel services, bore and others)
category: crowdstrike-fdr
status: todo
severity: high
language: esql
index: logs-crowdstrike.fdr-*
mitre: [T1572, T1090.002]
data_source: CrowdStrike FDR NetworkConnectIP4/IP6 and DnsRequest
suppression:
  fields: [host.id, service]
  duration: 24h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
A tunnel service makes a host reachable from the internet through the vendor's relay, so whoever holds the tunnel can reach that host, and anything it can reach, without an inbound firewall rule. Each service's agent has to reach that relay, and the relay is fixed by the vendor: its port, or the host the agent connects to. That's what the rule matches, so renaming the binary or moving its options into a config file changes nothing.

- **Anchor:** a connection to a public address on a tunnel relay's fixed port, or a DNS lookup of a tunnel agent's server.
- **Corroborating property:** none needed. These ports and hosts are used only by tunnel agents. Cloudflare's edge, for example, listens only on 7844: when UDP is blocked the agent falls back from QUIC to HTTP/2 over TCP, still on 7844, never 443.
- **Exclusion:** hosts approved to run a tunnel connector, by Falcon agent ID. There's no rarity check, on purpose: if you run one of these services on a few servers, an intruder using the same service on a workstation must still alert.

People visiting a site hosted on one of these services resolve other names (`*.trycloudflare.com`, `*.ngrok-free.app`, `*.lhr.life`), so this rule is about running a tunnel, not visiting one. Visits are fixed-detections 01 After A, at the proxy. VS Code and Microsoft dev tunnels are CS13, by command line, because the dev tunnels relay also serves the VS Code desktop app.

## Query
Run every 15 minutes with a 1-hour lookback.
```esql
FROM logs-crowdstrike.fdr-*
// Anchor: a connection to a public address on a tunnel relay's fixed port, or a DNS lookup under a tunnel service's domain.
| WHERE ((event.action IN ("NetworkConnectIP4", "NetworkConnectIP6") AND destination.port IN (7844, 7835, 9993, 41641)
          AND NOT CIDR_MATCH(destination.ip, "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16",
                             "100.64.0.0/10", "fc00::/7", "fe80::/10"))
         OR (event.action == "DnsRequest"
             AND dns.question.registered_domain IN ("argotunnel.com", "cftunnel.com", "trycloudflare.com", "ngrok-agent.com", "ngrok.com",
                                                    "tailscale.com", "localhost.run", "serveo.net", "pinggy.io", "bore.pub",
                                                    "localtonet.com", "playit.gg", "tunnelmole.com")))
  // hosts approved to run a tunnel connector (placeholders: Falcon agent IDs)
  AND NOT host.id IN ("<approved_tunnel_host_aid>")
| EVAL d = TO_LOWER(dns.question.name), port = destination.port
// Name the service from what its agent can't avoid: the relay's port, or the host the agent connects to.
// Website visits (www.ngrok.com, the Tailscale admin console) don't match: only the agents' own hosts do.
| EVAL service = CASE(
    // Cloudflare: the edge only listens on 7844 (QUIC, falling back to HTTP/2 over TCP); quick tunnels start at api.trycloudflare.com
    port == 7844 OR d LIKE "*argotunnel.com" OR d LIKE "*cftunnel.com" OR d == "api.trycloudflare.com", "cloudflare tunnel",
    // ngrok: every name under ngrok-agent.com is agent infrastructure; tunnel.<region>.ngrok.com is the older agent's
    d LIKE "*ngrok-agent.com" OR d LIKE "tunnel.*ngrok.com", "ngrok",
    // Tailscale: the client's control server, and direct peer-to-peer traffic on UDP 41641
    d == "controlplane.tailscale.com" OR port == 41641, "tailscale",
    // ZeroTier: the client reaches its root servers on UDP 9993 by address, with no DNS lookup
    port == 9993, "zerotier",
    // plain ssh -R to a public tunnel service: nothing to install, so this is the only trace on the network
    d IN ("localhost.run", "serveo.net") OR d LIKE "*pinggy.io", "ssh tunnel service",
    // bore: the public server bore.pub takes control connections on 7835
    d == "bore.pub" OR port == 7835, "bore",
    d IN ("localtonet.com", "api.playit.gg", "service.tunnelmole.com"), "other tunnel service",
    NULL)
| WHERE service IS NOT NULL
// One row per host and service. DNS events often carry no process name: find it through pids (process.entity_id).
| STATS events = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp), domains = VALUES(d), ports = VALUES(port),
        procs = VALUES(process.name), pids = VALUES(process.entity_id), host.name = VALUES(host.name)
    BY host.id, service
```

**CrowdStrike (Falcon LogScale / Advanced Event Search)**, run over the last 1 hour:
```logscale
#event_simpleName=/^(NetworkConnectIP4|NetworkConnectIP6|DnsRequest)$/
// hosts approved to run a tunnel connector (placeholders: Falcon agent IDs)
| !in(field="aid", values=["<approved_tunnel_host_aid>"])
| d := lower(DomainName)
| dst := coalesce([RemoteAddressIP4, RemoteAddressIP6])
// Name the service from what its agent can't avoid: the relay's port, or the host the agent connects to.
| case {
    // connections to a public address on a tunnel relay's fixed port
    #event_simpleName=/^NetworkConnect/
      !cidr(dst, subnet=["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "100.64.0.0/10",
                         "fc00::/7", "fe80::/10"])
      | case {
          // Cloudflare: the edge only listens on 7844 (QUIC, falling back to HTTP/2 over TCP)
          RemotePort=7844 | service := "cloudflare tunnel";
          // Tailscale peers on UDP 41641, ZeroTier root servers on UDP 9993, bore's server on 7835
          RemotePort=41641 | service := "tailscale";
          RemotePort=9993 | service := "zerotier";
          RemotePort=7835 | service := "bore";
        };
    // DNS lookups of a tunnel agent's server; website visits don't match
    #event_simpleName=DnsRequest
      | case {
          d=/(argotunnel|cftunnel)\.com$/ | service := "cloudflare tunnel";
          d="api.trycloudflare.com" | service := "cloudflare tunnel";
          d=/ngrok-agent\.com$|^tunnel\.([a-z]+\.)?ngrok\.com$/ | service := "ngrok";
          d="controlplane.tailscale.com" | service := "tailscale";
          in(field="d", values=["localhost.run", "serveo.net"]) | service := "ssh tunnel service";
          d=/pinggy\.io$/ | service := "ssh tunnel service";
          d="bore.pub" | service := "bore";
          in(field="d", values=["localtonet.com", "api.playit.gg", "service.tunnelmole.com"]) | service := "other tunnel service";
        };
  }
// One row per host and service.
| groupBy([aid, service], function=[count(as=events), min(@timestamp, as=first_seen), max(@timestamp, as=last_seen),
                                    collect([ComputerName, d, RemotePort, ContextBaseFileName, ContextProcessId])], limit=max)
```

**Check that Falcon sees UDP.** Cloudflare's QUIC, Tailscale and ZeroTier run over UDP. Run `FROM logs-crowdstrike.fdr-* | WHERE event.action == "NetworkConnectIP4" AND destination.port IN (7844, 9993, 41641) | STATS COUNT(*) BY network.transport` over a week. If only `tcp` appears while one of these is in use, the sensor isn't recording those UDP connections; the DNS branches still fire, and your firewall logs see the ports.

## Suppression
Suppress by `host.id`, `service` for 24h. Alerts missing a key field are not suppressed. Aggregating rule: an agent stays connected, so each run's repeats fold into the open alert. A second service on the same host still alerts.

## Known false positives / exclusions
- A service you run yourselves (Cloudflare Tunnel connectors, a sanctioned Tailscale rollout). Exclude the connector hosts by `host.id`. If the service is deployed fleet-wide, remove its branch from the `CASE` instead.
- Developers running ngrok or a similar service to share a local build. It's still a host reachable from the internet; confirm and decide whether it's allowed.

## Triage
- `procs` and `pids` name the program. A renamed binary, or one in `Downloads`, `Temp` or `ProgramData`, is the intrusion pattern. Its ProcessRollup2 event (same `process.entity_id`) gives the command line and parent.
- Ask what the tunnel exposes: look for connections arriving on the host from the tunnel agent (it relays to a local port), and for RDP, SSH or SMB being reached through it.
- If you don't use these services, block them at the firewall: outbound 7844, UDP 9993 and 41641, and the agent domains. A Cloudflare tunnel can't start at all with 7844 blocked.

## Test
On a lab host, run `cloudflared tunnel --url http://localhost:8080`, then `ssh -R 80:localhost:8080 nokey@localhost.run`. Each should raise one alert with the right `service`.
