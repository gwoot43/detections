---
id: IWA-01
name: Isolated Web App installed or used for internal network access (Direct Sockets scanning / pivoting from the browser)
language: cql
index: logs-yourorg-crowdstrike-data-default*
mitre: [T1090.001, T1046, T1572]
data_source: CrowdStrike FDR ProcessRollup2 and NetworkConnectIP4/IP6
suppression:
  fields: [host.id, finding]
  duration: 12h
  missing_fields: do_not_suppress
---
**Catches:** an Isolated Web App (IWA) being installed or used as an attack tool. IWAs are Chromium apps packaged as Signed Web Bundles (`.swbn`) that get the **Direct Sockets API** - raw TCP/UDP from inside the browser. That capability turns the browser into a port scanner, a proxy, or a C2 client that runs under a signed, trusted process and reaches wherever the browser can. It's an emerging offensive technique, so treat this as a hunt and confirm the signals against the Chromium build in your estate.

Two signals, kept as separate findings:

**`iwa_install` - the app being set up.** Dev-mode IWA install needs an explicit switch or a bundle file:
- a browser command line with `--install-isolated-web-app-from-file`, `--install-isolated-web-app-from-url`, or the `IsolatedWebAppDevMode`/`IsolatedWebApps` feature flag;
- a `.swbn` bundle written to disk.

**`browser_direct_sockets` - the app in use.** A browser reaching several internal hosts on non-web ports is not browsing - it's the Direct Sockets API scanning or pivoting. (Detection 20 excludes browsers on purpose; this is the browser case it leaves out.)

Run every 15 minutes over the last 30.
```logscale
// iwa_install: the browser switch or feature flag that installs a dev-mode IWA
#event_simpleName=ProcessRollup2
| CommandLine=/(?<Match>--install-isolated-web-app-from-(file|url)|isolatedwebapp(devmode|s))/iF
| finding := "iwa_install"
| select([@timestamp, ComputerName, UserName, ImageFileName, ParentBaseFileName, finding, Match, CommandLine])
```
```logscale
// browser_direct_sockets: a browser reaching internal hosts on non-web ports (raw sockets, not browsing)
#event_simpleName=/^NetworkConnectIP[46]$/ ConnectionDirection=0
| ContextBaseFileName=/^(chrome|msedge|brave|chromium)(\.exe)?$/i
| RemoteAddress := coalesce([RemoteAddressIP4, RemoteAddressIP6])
| cidr(RemoteAddress, subnet=["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"])
//ordinary intranet browsing is 80/443 and the usual proxy ports; strip those, what's left is raw sockets
| !in(field="RemotePort", values=["80", "443", "8080", "8443", "3128"])
| groupBy([aid, ContextBaseFileName], function=[count(RemoteAddress, distinct=true, as=internal_hosts), count(RemotePort, distinct=true, as=ports),
    collect([ComputerName, RemoteAddress, RemotePort], limit=50), min(@timestamp, as=first_seen), max(@timestamp, as=last_seen)], limit=max)
//a browser touching 5+ internal hosts on non-web ports is scanning/pivoting (starting value - baseline below)
| internal_hosts >= 5
| finding := "browser_direct_sockets"
| match(file="aid_master_main.csv", field=aid, include=[ComputerName], strict=false)
| select([ComputerName, ContextBaseFileName, internal_hosts, ports, RemoteAddress, RemotePort, finding, first_seen, last_seen])
```

**Elastic (ES|QL)**
```esql
FROM logs-yourorg-crowdstrike-data-default* METADATA _id, _index, _version
// iwa_install: the browser switch or feature flag that installs a dev-mode IWA
| WHERE event.action == "processrollup2"
| EVAL cmd = TO_LOWER(COALESCE(process.command_line, ""))
| WHERE cmd LIKE "*--install-isolated-web-app-from-file*" OR cmd LIKE "*--install-isolated-web-app-from-url*"
     OR cmd LIKE "*isolatedwebappdevmode*" OR cmd LIKE "*isolatedwebapps*"
| EVAL finding = "iwa_install"
| KEEP @timestamp, host.id, host.name, user.name, process.name, process.parent.name, finding, process.command_line, _id, _index, _version
```
```esql
FROM logs-yourorg-crowdstrike-data-default*
// browser_direct_sockets: a browser reaching internal hosts on non-web ports (raw sockets, not browsing)
| WHERE event.action IN ("networkconnectip4", "networkconnectip6") AND data.ConnectionDirection == "0"
| EVAL proc = TO_LOWER(COALESCE(process.name, ""))
| WHERE proc IN ("chrome.exe", "msedge.exe", "brave.exe", "chromium", "chrome", "msedge")
  AND CIDR_MATCH(destination.ip, "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7")
  AND NOT destination.port IN (80, 443, 8080, 8443, 3128)
| STATS internal_hosts = COUNT_DISTINCT(destination.ip), ports = COUNT_DISTINCT(destination.port),
        host_sample = MV_SLICE(VALUES(destination.ip), 0, 49), port_sample = MV_SLICE(VALUES(destination.port), 0, 49),
        host.name = VALUES(host.name), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
    BY host.id, proc
// a browser touching 5+ internal hosts on non-web ports is scanning/pivoting (starting value - baseline below)
| WHERE internal_hosts >= 5
| EVAL finding = "browser_direct_sockets"
```
Suppress by host and finding for 12h.

## Before turning it on
- Confirm the switch names against the Chromium/Edge version your estate runs - IWA is still moving, and the flags have changed across releases. If dev-mode installs happen through the `chrome://web-app-internals` page rather than the command line, the `iwa_install` command-line signal won't see them; the `.swbn` write and the `browser_direct_sockets` behaviour still will.
- Baseline `browser_direct_sockets` over a week: some internal dev work legitimately opens non-web ports from the browser (local dev servers, WebSocket backends on odd ports). Exclude those hosts/ports; keep the fan-out threshold above what normal dev does.
- Loopback (`127.0.0.0/8`) is left out on purpose - Direct Sockets to localhost is common in development.

## What it misses
- A production IWA installed through enterprise policy (allow-listed), which is the sanctioned path - exclude it by its app id/host.
- A single-target use (connecting to one internal host) stays under the fan-out threshold; lower it if you want the quieter case.
- IWAs doing their socket work over 443 to blend with browsing - the install signal still catches the setup.

## When it fires
`iwa_install` with the command line shows who set it up and from where (`--install-isolated-web-app-from-url` names the source). `browser_direct_sockets` with `port_sample`/`host_sample` shows the scan or pivot - a spread of hosts on one port is a sweep, many ports on few hosts is a port scan. Find the browser's parent and the profile in use, check what `.swbn` bundles exist on the host, and whether the same host also shows a tunnel (20, 21). A browser speaking raw sockets across the internal network is not a user browsing - treat it as tooling.
