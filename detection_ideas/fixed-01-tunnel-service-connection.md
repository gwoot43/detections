# 01 · Tunnel service connection (Zscaler) → tunnel agent detection (Zscaler + Falcon)

**Verdict before:** keep the idea, fix the query. One of the two deployed copies can never match, the domain list covers three services, and the most common transport (cloudflared over QUIC) never reaches the web proxy.
**After:** two rules. A Zscaler rule covering a wider, tiered service list, and a Falcon rule that sees the tunnel agent on the endpoint whatever the port or binary name. The Falcon rule also takes over the plink branch from rule 03.

## Before

Copy 1, as deployed:
```kql
event.action:allowed AND (http.request.method:CONNECT OR network.protocol:tls) AND ((url.domain:(opentunnel.xyz OR opentunnel.xyz. OR service.tunnelmole.com OR service.tunnelmole.com. OR api.trycloudflare.com OR api.trycloudflare.com. OR cftunnel.com OR cftunnel.com. OR h2.cftunnel.com OR h2.cftunnel.com. OR quic.cftunnel.com OR quic.cftunnel.com.)) OR (url.domain:(.v2.argotunnel.com OR .v2.argotunnel.com.)))
```
Copy 2 is identical except for `url.domain:(*.v2.argotunnel.com OR *.v2.argotunnel.com.)`.

## What's wrong

| # | Problem | Effect |
|---|---|---|
| 1 | Copy 1 has `.v2.argotunnel.com` with no `*`. On a keyword field that is an exact match for the literal string ".v2.argotunnel.com". | The argotunnel branch of copy 1 never matches. Delete copy 1. |
| 2 | `http.request.method:CONNECT OR network.protocol:tls`. With TLS inspection Zscaler logs GET/POST, not CONNECT, and the protocol value depends on your parser. | Inspected tunnel traffic can drop out. The domain alone is the signal. |
| 3 | cloudflared's default transport is QUIC on UDP 7844 to `region1/2.v2.argotunnel.com`. That isn't web traffic, so it never appears in Zscaler web logs. | The most common Cloudflare Tunnel setup is invisible to this rule. |
| 4 | Three services covered. ngrok, Microsoft dev tunnels (`code tunnel`), localhost.run, serveo, pinggy, localtunnel, bore, localtonet, playit and Tailscale are missing. | Easy to step around. |
| 5 | No split between *running* a tunnel agent and *visiting* a tunnel-hosted site (`*.trycloudflare.com`), which is common in malware and ClickFix delivery. | Two different stories in one alert, or one of them missed. |
| 6 | Zscaler sees the user and device, never the process. | Triage always needs a second lookup in Falcon. |
| 7 | Trailing-dot duplicates of every domain. | Harmless, but doubles the list. Normalise once instead. |

## After A · Zscaler (ES|QL)

```esql
FROM logs-yourorg-zscaler*                       // the index your current KQL rule runs on
// Anchor: allowed requests with a domain. The trailing dot is stripped once instead of listing every domain twice.
| WHERE event.action == "allowed" AND url.domain IS NOT NULL
| EVAL d = TO_LOWER(url.domain)
| EVAL d = CASE(ENDS_WITH(d, "."), SUBSTRING(d, 1, LENGTH(d) - 1), d)
// Name the service from its agent or relay domains. The services are the signal, so the list stays.
// A *.trycloudflare.com-style address is a visit to a site hosted on a tunnel, not an agent.
| EVAL service = CASE(
    d IN ("api.trycloudflare.com", "update.argotunnel.com", "cftunnel.com")
      OR ENDS_WITH(d, ".argotunnel.com") OR ENDS_WITH(d, ".cftunnel.com"), "cloudflare tunnel agent",
    d IN ("connect.ngrok-agent.com", "tunnel.ngrok.com")
      OR ENDS_WITH(d, ".connect.ngrok-agent.com") OR ENDS_WITH(d, ".tunnel.ngrok.com"), "ngrok agent",
    d == "global.rel.tunnels.api.visualstudio.com"
      OR ENDS_WITH(d, ".rel.tunnels.api.visualstudio.com"), "microsoft dev tunnel host (code tunnel)",
    d IN ("opentunnel.xyz", "service.tunnelmole.com", "localhost.run", "admin.localhost.run", "serveo.net",
          "bore.pub", "localtonet.com", "api.playit.gg", "localtunnel.me", "loca.lt")
      OR ENDS_WITH(d, ".pinggy.io"), "other tunnel agent",
    d IN ("controlplane.tailscale.com", "login.tailscale.com"), "tailscale",
    ENDS_WITH(d, ".trycloudflare.com") OR ENDS_WITH(d, ".ngrok-free.app") OR ENDS_WITH(d, ".ngrok.app")
      OR ENDS_WITH(d, ".ngrok.io") OR ENDS_WITH(d, ".loca.lt") OR ENDS_WITH(d, ".devtunnels.ms")
      OR ENDS_WITH(d, ".lhr.life") OR ENDS_WITH(d, ".serveo.net"), "visited a tunnel-hosted site",
    NULL)
| WHERE service IS NOT NULL
// Running an agent is high; visiting a tunnel-hosted site (common in malware and ClickFix delivery) is medium.
| EVAL severity = CASE(service == "visited a tunnel-hosted site", "medium", "high")
// One row per user, service and severity.
| STATS first_seen = MIN(@timestamp), last_seen = MAX(@timestamp), requests = COUNT(*),
        domains = VALUES(d), source_ips = VALUES(source.ip)
    BY user.name, service, severity
```
Run every 15 minutes with a 1-hour lookback. Suppress by `user.name`, `service` for 24h.

If you'd rather keep a KQL rule, the minimal fix to copy 2 is: delete copy 1, remove the `(http.request.method:CONNECT OR network.protocol:tls)` clause, and add the agent domains above.

## After B · Falcon endpoint (ES|QL)

```esql
FROM logs-yourorg-crowdstrike-data-default* METADATA _id, _index, _version
// Anchor: process starts and outbound connections on the endpoint.
| WHERE event.action IN ("processrollup2", "networkconnectip4")
| EVAL raw = COALESCE(process.command_line, ""),
       cmd = TO_LOWER(raw),
       pname = MV_LAST(SPLIT(MV_LAST(SPLIT(TO_LOWER(COALESCE(process.executable, "")), "\\")), "/"))
// Each branch is the shape of one tunnel tool, matched whatever the binary is called. The label says which.
| EVAL finding = CASE(
    // cloudflared's default QUIC transport, which never reaches the web proxy
    event.action == "networkconnectip4" AND destination.port == 7844
      AND NOT CIDR_MATCH(destination.ip, "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"),
      "cloudflare tunnel edge connection (port 7844)",
    event.action == "processrollup2" AND cmd LIKE "* tunnel*"
      AND (cmd LIKE "*--url*" OR cmd LIKE "* run*" OR cmd LIKE "*--token*"),
      "cloudflared-style tunnel started",
    // "<anything> tcp 3389" or "<anything> http localhost:8080": the ngrok argument shape
    event.action == "processrollup2" AND cmd RLIKE ".* (http|tcp|tls) ([a-z0-9.-]+:)?[0-9]{2,5}( .*)?",
      "ngrok-style tunnel started (any binary name)",
    event.action == "processrollup2"
      AND ((cmd LIKE "* client *" AND cmd LIKE "* r:*") OR (cmd LIKE "* server *" AND cmd LIKE "*--reverse*")),
      "chisel-style reverse tunnel",
    // ssh flags on the original case: -R (reverse) and -D (SOCKS) are tunnels; -L and -l are everyday use
    event.action == "processrollup2" AND pname IN ("plink.exe", "plink", "ssh.exe", "ssh")
      AND (raw LIKE "* -R*" OR raw LIKE "* -D*"),
      "ssh or plink reverse / socks tunnel",
    NULL)
| WHERE finding IS NOT NULL
| KEEP @timestamp, host.id, host.name, user.name, finding, process.executable, process.command_line,
       destination.ip, destination.port, data.ContextBaseFileName, data.ParentBaseFileName, _id, _version, _index
```

**CrowdStrike (Falcon LogScale / Advanced Event Search)**
```logscale
#event_simpleName=/^(ProcessRollup2|SyntheticProcessRollup2|NetworkConnectIP4)$/
| cmd := lower(CommandLine)
| regex("(?<pname>[^\\\\/]*)$", field=ImageFileName, strict=false)
| pname := lower(pname)
// Each branch is the shape of one tunnel tool, matched whatever the binary is called. The label says which.
| case {
    // cloudflared's default QUIC transport, which never reaches the web proxy
    #event_simpleName=NetworkConnectIP4 RemotePort=7844
      !cidr(RemoteAddressIP4, subnet=["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"])
      | finding := "cloudflare tunnel edge connection (port 7844)";
    #event_simpleName=/ProcessRollup2$/
      | case {
          cmd=/ tunnel/ cmd=/--url| run|--token/
            | finding := "cloudflared-style tunnel started";
          // "<anything> tcp 3389" or "<anything> http localhost:8080": the ngrok argument shape
          cmd=/ (http|tcp|tls) ([a-z0-9.-]+:)?[0-9]{2,5}( |$)/
            | finding := "ngrok-style tunnel started (any binary name)";
          cmd=/ client / cmd=/ r:/
            | finding := "chisel-style reverse tunnel";
          cmd=/ server / cmd=/--reverse/
            | finding := "chisel-style reverse tunnel";
          // original case: -R (reverse) and -D (socks), not -L or -l
          in(field="pname", values=["plink.exe", "plink", "ssh.exe", "ssh"]) CommandLine=/ -R| -D/
            | finding := "ssh or plink reverse / socks tunnel";
        };
  }
| table([@timestamp, aid, ComputerName, UserName, finding, ImageFileName, CommandLine,
         RemoteAddressIP4, RemotePort, ContextBaseFileName, ParentBaseFileName])
```
Suppress by `host.id`, `finding` for 24h.

- **No `NOT user.name:*$` filter.** Falcon generally records SYSTEM processes under the machine account, so that filter hides tunnels started from a service or scheduled task.
- **ssh flags are matched on the original-case command line.** `-R` (reverse) and `-D` (SOCKS) are what tunnels use. Lower-case `-l` (login name) and `-L` (local forward, common for developers reaching databases) are deliberately not matched.
- **VS Code tunnels are library rule CS13** and `devtunnel.exe` is W10. CS13 anchors on the `tunnel` argument and needs the licence flag, a `code*` name or a staging folder with it. The earlier branch here matched `code-tunnel.exe` with any `tunnel` argument, which fires on the `code-tunnel.exe tunnel status` check the VS Code desktop app runs routinely.
- **The ngrok-style pattern** catches a renamed binary run as `<anything> tcp 3389`, `<anything> http localhost:8080` or `<anything> tcp 10.0.0.5:3389`. If one of your internal tools uses that argument shape, exclude it by `pname`.

## Before vs after

| | Before | After |
|---|---|---|
| Can fire | Copy 2 only | Yes |
| Tunnel services | 3 | 12, plus "visited a tunnel-hosted site" |
| cloudflared over QUIC | Missed | Caught on the endpoint (port 7844) |
| Renamed agent binary | Missed | Caught by command-line shape |
| `code tunnel` / dev tunnels | Missed | Caught (Zscaler here; Falcon in library rules CS13 and W10) |
| Process in the alert | No | Yes (After B) |
| Duplicate rules | Two near-identical copies | One per data source |

## Exclusions to add
- If your organisation runs Cloudflare Tunnel or Tailscale itself, exclude the connector hosts in After B (`host.id`) and the service in After A.

## Test
On a lab host: run `cloudflared tunnel --url http://localhost:8080` and browse to any `*.trycloudflare.com` URL. Each should alert once. Run `code tunnel` too: After A should alert on the relay domain, and CS13 on the endpoint.
