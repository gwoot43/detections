---
id: W16
name: 
category: endpoint-windows
status: todo
language: esql
index: logs-yourorg-crowdstrike-data-default*
mitre: [T1046, T1090.001, T1572]
data_source: CrowdStrike FDR / Windows Security events
suppression:
  fields: [host.id]
  duration: 24h
  missing_fields: do_not_suppress
---
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
// hyphenated spellings matter: --enable-isolated-web-apps-in-renderer is what the renderer child carries, and it
// survives an install done through chrome://web-app-internals. iwa-tools also disables the local network access
// check, and SilentChrome installs an unpacked extension.
| CommandLine=/(?<Match>--install-isolated-web-app-from-(file|url)|isolatedwebapp(devmode|s)|isolated-web-app|local-network-access-check|--load-extension)/iF
// which switch was used
| case {
    CommandLine=/--install-isolated-web-app-from-file/i | iwa_method := "install_from_file" ;
    CommandLine=/--install-isolated-web-app-from-url/i | iwa_method := "install_from_url" ;
    CommandLine=/isolatedwebappdevmode/i | iwa_method := "devmode_enabled" ;
    CommandLine=/isolated-web-app/i | iwa_method := "renderer_switch" ;
    CommandLine=/local-network-access-check/i | iwa_method := "network_check_disabled" ;
    CommandLine=/--load-extension/i | iwa_method := "unpacked_extension" ;
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
// the host count carries the finding; only the low-cardinality port field is collected as a sample, because a
// collect() of every destination address is a high-cardinality list (the ES|QL twin keeps MV_SLICE host samples)
| groupBy([aid, ContextBaseFileName], function=[count(RemoteAddress, distinct=true, as=internal_hosts), count(RemotePort, distinct=true, as=ports),
    collect([ComputerName, RemotePort], limit=20), min(@timestamp, as=first_seen), max(@timestamp, as=last_seen)], limit=max)
//a browser touching 5+ internal hosts on non-web ports is scanning/pivoting (starting value - baseline below)
| internal_hosts >= 5
| finding := "browser_direct_sockets"
| match(file="aid_master_main.csv", field=aid, include=[ComputerName], strict=false)
| select([ComputerName, ContextBaseFileName, internal_hosts, ports, finding, first_seen, last_seen])
```

**Elastic (ES|QL)**
```esql
FROM logs-yourorg-crowdstrike-data-default* METADATA _id, _index, _version
// iwa_install: a Chromium browser started with a switch that installs or enables a dev-mode IWA (Chromium-only, no Firefox)
| WHERE event.action == "processrollup2"
| EVAL proc = TO_LOWER(COALESCE(process.name, "")), cmd = TO_LOWER(COALESCE(process.command_line, ""))
| WHERE proc IN ("chrome.exe", "msedge.exe", "brave.exe", "chromium.exe", "chromium", "opera.exe", "vivaldi.exe")
  AND (cmd LIKE "*--install-isolated-web-app-from-file*" OR cmd LIKE "*--install-isolated-web-app-from-url*"
       OR cmd LIKE "*isolatedwebappdevmode*" OR cmd LIKE "*isolatedwebapps*"
// hyphenated spellings: --enable-isolated-web-apps-in-renderer is what appears on the renderer child when an
// IWA launches, and it is the one signal that survives an install done through chrome://web-app-internals
       OR cmd LIKE "*isolated-web-app*"
// iwa-tools disables the local network access check, otherwise Chromium blocks TCP to RFC1918
       OR cmd LIKE "*local-network-access-check*"
// the unpacked-extension half: SilentChrome installs an extension, which needs developer mode
       OR cmd LIKE "*--load-extension=*" OR cmd LIKE "*--load-extension *")
| EVAL iwa_method = CASE(cmd LIKE "*--install-isolated-web-app-from-file*", "install_from_file",
                        cmd LIKE "*--install-isolated-web-app-from-url*", "install_from_url",
                        cmd LIKE "*isolatedwebappdevmode*", "devmode_enabled",
                        cmd LIKE "*isolated-web-app*", "renderer_switch",
                        cmd LIKE "*local-network-access-check*", "network_check_disabled",
                        cmd LIKE "*--load-extension*", "unpacked_extension",
                        "feature_flag"),
       finding = "iwa_install"
| KEEP @timestamp, host.id, host.name, user.name, process.name, process.parent.name, finding, iwa_method, process.command_line, _id, _index, _version
```
```esql
FROM logs-yourorg-crowdstrike-data-default*
// browser_direct_sockets: a browser reaching internal hosts on non-web ports (raw sockets, not browsing)
// data.ConnectionDirection is a string compare: if the field ingests numeric this returns nothing and the
// branch looks quiet. Probe it before trusting the rule.
| WHERE event.action IN ("networkconnectip4", "networkconnectip6") AND data.ConnectionDirection == "0"
| EVAL proc = TO_LOWER(COALESCE(process.name, "")),
       internal = CIDR_MATCH(destination.ip, "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7")
| WHERE proc IN ("chrome.exe", "msedge.exe", "brave.exe", "chromium", "chrome", "msedge")
  AND internal
  AND NOT destination.port IN (80, 443, 8080, 8443, 3128)
| STATS internal_hosts = COUNT_DISTINCT(destination.ip), ports = COUNT_DISTINCT(destination.port),
        host_sample = MV_SLICE(VALUES(destination.ip), 0, 49), port_sample = MV_SLICE(VALUES(destination.port), 0, 49),
        host.name = VALUES(host.name), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
    BY host.id, proc
// a browser touching 5+ internal hosts on non-web ports is scanning/pivoting (starting value - baseline below)
| WHERE internal_hosts >= 5
| EVAL finding = "browser_direct_sockets"
```
```esql
FROM logs-yourorg-crowdstrike-data-default*
// browser_ad_protocol: the same Direct Sockets capability aimed at directory services, at a threshold of one.
// A browser has no reason to speak SMB, LDAP, Kerberos or RDP to anything, so a single connection is the finding -
// this is the quiet case that the 5-host fan-out above deliberately leaves out.
| WHERE @timestamp >= NOW() - 15 minutes
  AND event.action IN ("networkconnectip4", "networkconnectip6")
| EVAL proc = TO_LOWER(COALESCE(process.name, "")),
       internal = CIDR_MATCH(destination.ip, "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7")
| WHERE proc IN ("chrome.exe", "msedge.exe", "brave.exe", "chromium", "chrome", "msedge")
  AND internal
  AND destination.port IN (88, 135, 389, 445, 636, 3268, 3269, 3389, 5985, 1433, 1521)
| STATS connections = COUNT(*), targets = COUNT_DISTINCT(destination.ip),
        port_sample = MV_SLICE(VALUES(destination.port), 0, 5),
        host_sample = MV_SLICE(VALUES(destination.ip), 0, 9),
        first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
    BY host.id, host.name, user.name, proc
| EVAL finding = "browser_ad_protocol"
| SORT connections DESC
| LIMIT 100
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

## Triage

`iwa_install` names who set it up and how (`iwa_method`): `install_from_file` is a bundle on disk,
`install_from_url` and `feature_flag` are a download, `devmode_enabled` and `renderer_switch` mean the developer
mode flag is on, `network_check_disabled` means the browser was told it may reach RFC1918, and `unpacked_extension`
is the extension half rather than the IWA half. Work it in this order.

**1. Find the bundle at the proxy.** The `.swbn` is the package; the `manifest.json` inside it is what a dev-mode
install fetches when the bundle is served from a dev proxy rather than downloaded whole. Both are worth a look even
when the endpoint signal is thin:

```esql
FROM logs-zscaler_zia.web-*
| WHERE @timestamp >= NOW() - 7 days
// leading-wildcard patterns on purpose: a bundle or manifest name is the tail of the path, and there is no
// indexed field for "this file is an IWA package"
  AND (url.extension == "swbn" OR url.path LIKE "*.swbn" OR url.path LIKE "*manifest.json*")
| STATS requests = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp),
        paths = TOP(url.path, 10, "asc"), actions = VALUES(event.action),
        status = MV_SLICE(VALUES(http.response.status_code), 0, 5)
    BY user.name, url.domain
| SORT requests DESC
| LIMIT 50
```

Read `url.domain` first: a dev proxy or a paste/file host serving `manifest.json` next to a `.swbn` is the
signature. A CDN serving `manifest.json` for every web app it hosts is noise — compare against the domains your
own applications use.

**2. Ask the endpoint what the browser is holding.** On the host, the profile carries the evidence: the
`Local State` / `Preferences` JSON for the profile in use will contain the IWA dev-mode entries, and the IWA
storage sits under the profile's `Web Applications` directory. Check `chrome://web-app-internals` on the live
profile if you can, and look for `.swbn` files anywhere the user can write.

**3. Walk the process tree, not just the hit.** The browser's parent tells you whether a person opened it or
something launched it: `explorer.exe` is a user, an Office application, a script host or an agent process is not.
Then look for the extension half — `--load-extension=` with a path under `%APPDATA%`, `%TEMP%` or a downloads
folder — and for a second browser process started with an `--app-id=` that has no corresponding installed app.

**4. Check what the sockets reached.** `browser_ad_protocol` and `browser_direct_sockets` give `host_sample` and
`port_sample`: a spread of hosts on one port is a sweep, many ports on few hosts is a port scan, and a single host
on 445 or 389 is an AD tool talking to a domain controller. Pivot to the DC's own logs for what the browser
account did there — `4624` type 3 from that address, and `4769` for tickets it asked for.

**5. Confirm the profile, then remove the app.** IWA dev-mode apps live per profile: deleting the app in one
profile does not touch another. Remove the `.swbn` from storage, unset the dev-mode flag, and check whether the
same host shows a tunnel (20, 21) — a browser pivoting internally and an outbound tunnel on the same box is one
operation, not two.

**6. Fix the cause rather than the symptom.** The controls that remove this technique are policy, not queries:
`ExtensionDeveloperModeSettings` set to `Disallow (1)` as a mandatory Chrome/Edge policy forces developer mode off
(an unpacked extension then fails with `DISABLE_UNSUPPORTED_EXTENSION` and never starts its service worker), and a
policy that blocks the IWA feature flags stops the dev-mode bundle from loading at all.

## Prevention worth recommending alongside the rule
- `ExtensionDeveloperModeSettings = Disallow (1)`, mandatory, for both Chrome and Edge.
- Block the IWA flags (`IsolatedWebApps`, `IsolatedWebAppDevMode`) and `--load-extension` by policy.
- If IWAs are sanctioned for internal apps, allow-list the specific app ids and hosts rather than the feature.
