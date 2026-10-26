---
id: IWA-01
name: Isolated Web App installed or used for internal network access (Direct Sockets scanning / pivoting from the browser)
language: cql
index: logs-yourorg-crowdstrike-data-default*
mitre: [T1090.001, T1046, T1572]
data_source: CrowdStrike FDR ProcessRollup2 and NetworkConnectIP4/IP6; Zscaler ZIA web logs
suppression:
  fields: [host.id, finding]
  duration: 12h
  missing_fields: do_not_suppress
---
**Catches:** an Isolated Web App (IWA) being installed or used as an attack tool. IWAs are Chromium apps packaged as Signed Web Bundles (`.swbn`) that get the **Direct Sockets API** - raw TCP/UDP from inside the browser. That capability turns the browser into a port scanner, a proxy, or a C2 client that runs under a signed, trusted process and reaches wherever the browser can. It's an emerging offensive technique, so treat this as a hunt and confirm the signals against the Chromium build in your estate.

Three signals, kept as separate findings:

**`iwa_install` - the app being set up on the endpoint.** A Chromium browser (IWA is Chromium-only, so no Firefox) started with a switch that installs or enables a dev-mode IWA: `--install-isolated-web-app-from-file`, `--install-isolated-web-app-from-url`, or the `IsolatedWebAppDevMode`/`IsolatedWebApps` feature flag. `iwa_method` says which one.

**`iwa_bundle_download` - the package crossing the proxy.** A Signed Web Bundle (`.swbn`) fetched through Zscaler, the companion to detection 07's ClickOnce download. This is what the proxy can see when the install itself happens off the command line (through `chrome://flags` or `chrome://web-app-internals`).

**`browser_direct_sockets` - the app in use.** A browser reaching several internal hosts on non-web ports is not browsing - it's the Direct Sockets API scanning or pivoting. (Detection 20 excludes browsers on purpose; this is the browser case it leaves out.)

Run every 15 minutes over the last 30.
```logscale
// iwa_install: a Chromium browser started with a switch that installs or enables a dev-mode IWA (Chromium-only, no Firefox)
#event_simpleName=ProcessRollup2
| in(field="FileName", ignoreCase=true, values=["chrome.exe", "msedge.exe", "brave.exe", "chromium.exe", "opera.exe", "vivaldi.exe"])
| CommandLine=/(?<Match>--install-isolated-web-app-from-(file|url)|isolatedwebapp(devmode|s))/iF
// which switch was used
| case {
    CommandLine=/--install-isolated-web-app-from-file/i | iwa_method := "install_from_file" ;
    CommandLine=/--install-isolated-web-app-from-url/i | iwa_method := "install_from_url" ;
    CommandLine=/isolatedwebappdevmode/i | iwa_method := "devmode_enabled" ;
    * | iwa_method := "feature_flag" ;
  }
| finding := "iwa_install"
| select([@timestamp, ComputerName, UserName, FileName, ImageFileName, ParentBaseFileName, finding, iwa_method, Match, CommandLine])
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
// iwa_install: a Chromium browser started with a switch that installs or enables a dev-mode IWA (Chromium-only, no Firefox)
| WHERE event.action == "processrollup2"
| EVAL proc = TO_LOWER(COALESCE(process.name, "")), cmd = TO_LOWER(COALESCE(process.command_line, ""))
| WHERE proc IN ("chrome.exe", "msedge.exe", "brave.exe", "chromium.exe", "chromium", "opera.exe", "vivaldi.exe")
  AND (cmd LIKE "*--install-isolated-web-app-from-file*" OR cmd LIKE "*--install-isolated-web-app-from-url*"
       OR cmd LIKE "*isolatedwebappdevmode*" OR cmd LIKE "*isolatedwebapps*")
| EVAL iwa_method = CASE(cmd LIKE "*--install-isolated-web-app-from-file*", "install_from_file",
                        cmd LIKE "*--install-isolated-web-app-from-url*", "install_from_url",
                        cmd LIKE "*isolatedwebappdevmode*", "devmode_enabled", "feature_flag"),
       finding = "iwa_install"
| KEEP @timestamp, host.id, host.name, user.name, process.name, process.parent.name, finding, iwa_method, process.command_line, _id, _index, _version
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

**Zscaler (ES|QL)** - the `iwa_bundle_download` signal, a Signed Web Bundle crossing the proxy (companion to detection 07, same index and fields):
```esql
FROM logs-zscaler_zia.web-*
// a Signed Web Bundle (.swbn) downloaded - the IWA package, visible at the proxy even when the install is off the command line
| WHERE url.extension == "swbn"
// leave out the sites you deploy IWAs from, if any (placeholders)
| WHERE NOT url.domain IN ("<approved_iwa_host>")
| EVAL finding = "iwa_bundle_download"
| STATS first_seen = MIN(@timestamp), requests = COUNT(*), files = TOP(url.path, 10, "asc"),
        actions = VALUES(event.action), source_ip = MV_SLICE(VALUES(source.ip), 0, 19), status = VALUES(http.response.status_code)
    BY user.name, url.domain, finding
```
If `url.extension` isn't filled on your Zscaler events, use `url.path LIKE "*.swbn"` instead (slower - every request is read), as detection 07 notes.

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
`iwa_install` with the command line shows who set it up and how (`iwa_method`: a file bundle, a URL, or dev mode turned on); `iwa_bundle_download` names the site the `.swbn` came from, and pairs with an `iwa_install` on the same host/user when the install happened off the command line. `browser_direct_sockets` with `port_sample`/`host_sample` shows the scan or pivot - a spread of hosts on one port is a sweep, many ports on few hosts is a port scan. Find the browser's parent and the profile in use, check what `.swbn` bundles exist on the host, and whether the same host also shows a tunnel (20, 21). A browser speaking raw sockets across the internal network is not a user browsing - treat it as tooling.
