---
id: HUNT-01
name: Hunt - brotli installed across the estate, by upstream version (distro build kept alongside)
language: esql
index: logs-yourorg-crowdstrike-data-default*
mitre: [T1190]
data_source: CrowdStrike Falcon installed-application inventory
suppression:
  fields: [data.AppName]
  duration: 24h
  missing_fields: do_not_suppress
---
A hunt, not an alert: where brotli is installed, which version, and on which kind of host (internet-facing, its criticality and owner). Package versions come with the distro's build attached (`1.1.0-7.el10_1` on RHEL, `1.0.9-2+b2` on Debian, sometimes an epoch like `1:1.0.9-2`), so the query pulls out the upstream version (`1.1.0`, `1.0.9`) to group on, and keeps the exact builds next to it.

## Plain version (runs now, no lookup)
Built on the original search: free text `brotli`, which is known to return the inventory data.

**CrowdStrike (Falcon LogScale)**
```logscale
//Filter for brotli, as in the original search, keeping events that name an application
brotli AppName=*
//Upstream version: drop any epoch ("1:") and the distro build after it ("-7.el10_1", "-2+b2")
| case {
    AppVersion=/^(\d+:)?v?(?<UpstreamVersion>\d+(\.\d+)*)/ ;
    * | UpstreamVersion := "unparsed";
  }
//Group by package and upstream version, keeping the exact builds and where they are
| groupBy([AppName, UpstreamVersion], function=[count(ComputerName, distinct=true, as=hosts), min(@timestamp, as=FirstSeen), max(@timestamp, as=LastSeen), collect([AppVersion, Appsource]), collect([ComputerName], limit=100)], limit=max)
//First and last seen in the search window, in Sydney time
| FirstSeen := formatTime("%Y-%m-%d %H:%M:%S", field=FirstSeen, timezone="Australia/Sydney")
| LastSeen := formatTime("%Y-%m-%d %H:%M:%S", field=LastSeen, timezone="Australia/Sydney")
```
Free text reads every event for the word, so it's slow over long ranges. To speed it up, find which event the hits come from with `brotli | groupBy(#event_simpleName)` and put `#event_simpleName=<that event>` in front of the search.

**Elastic (ES|QL)**
```esql
FROM logs-yourorg-crowdstrike-data-default*
// Filter for installed applications with brotli in the name
| WHERE data.AppName IS NOT NULL AND TO_LOWER(data.AppName) LIKE "*brotli*"
// Upstream version: drop any epoch and the distro build after it
| GROK data.AppVersion """^(\d+:)?v?(?<upstream_version>\d+(\.\d+)*)"""
| EVAL upstream_version = COALESCE(upstream_version, "unparsed")
// Group by package and upstream version, keeping the exact builds and where they are
| STATS hosts = COUNT_DISTINCT(host.name), builds = VALUES(data.AppVersion), host_sample = TOP(host.name, 20, "asc"),
        first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
    BY data.AppName, upstream_version
```
`first_seen` and `last_seen` stay dates, so Discover shows them in Kibana's display time zone: set Advanced Settings > `dateFormat:tz` to `Australia/Sydney`. ES|QL has no time zone conversion of its own, and a fixed `+ 10 hours` would be wrong during daylight saving.

## With asset context (internet exposure, criticality, owner)
Needs the `asset_context` lookup described below.

**CrowdStrike (Falcon LogScale)**
```logscale
//Filter for brotli, as in the original search, keeping events that name an application
brotli AppName=*
//Upstream version: drop any epoch ("1:") and the distro build after it ("-7.el10_1", "-2+b2")
| case {
    AppVersion=/^(\d+:)?v?(?<UpstreamVersion>\d+(\.\d+)*)/ ;
    * | UpstreamVersion := "unparsed";
  }
//Add asset context from your Exposure Management export (see Asset context below)
| match(file="asset_context.csv", field=aid, include=[InternetExposure, Criticality, Owner], strict=false)
| default(field=[InternetExposure, Criticality, Owner], value="unknown")
//Mark internet-facing hosts so they're counted on their own, and label each host with its context
| case { InternetExposure="Yes" | internet_host := ComputerName; * ; }
| host_context := format("%s (%s, %s, %s)", field=[ComputerName, InternetExposure, Criticality, Owner])
//Group by package and upstream version, keeping the exact builds and the hosts with their context
| groupBy([AppName, UpstreamVersion], function=[count(ComputerName, distinct=true, as=hosts), count(internet_host, distinct=true, as=internet_facing_hosts), min(@timestamp, as=FirstSeen), max(@timestamp, as=LastSeen), collect([AppVersion, Appsource]), collect([host_context], limit=100)], limit=max)
//First and last seen in the search window, in Sydney time
| FirstSeen := formatTime("%Y-%m-%d %H:%M:%S", field=FirstSeen, timezone="Australia/Sydney")
| LastSeen := formatTime("%Y-%m-%d %H:%M:%S", field=LastSeen, timezone="Australia/Sydney")
```

**Elastic (ES|QL)**
```esql
FROM logs-yourorg-crowdstrike-data-default*
// Filter for installed applications with brotli in the name
| WHERE data.AppName IS NOT NULL AND TO_LOWER(data.AppName) LIKE "*brotli*"
// Upstream version: drop any epoch and the distro build after it
| GROK data.AppVersion """^(\d+:)?v?(?<upstream_version>\d+(\.\d+)*)"""
| EVAL upstream_version = COALESCE(upstream_version, "unparsed")
// Add asset context from a lookup index keyed on host.id (see Asset context below)
| LOOKUP JOIN asset_context ON host.id
| EVAL host_context = CONCAT(COALESCE(host.name, host.id), " (", COALESCE(internet_exposure, "unknown"), ", ",
                             COALESCE(criticality, "unknown"), ", ", COALESCE(owner, "unknown"), ")")
// Group by package and upstream version, keeping the exact builds and the hosts with their context
| STATS hosts = COUNT_DISTINCT(host.id), internet_facing_hosts = COUNT_DISTINCT(host.id) WHERE internet_exposure == "Yes",
        builds = VALUES(data.AppVersion), host_sample = TOP(host_context, 20, "asc"),
        first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
    BY data.AppName, upstream_version
```

To see only internet-facing hosts, add `| InternetExposure="Yes"` after the `match` (LogScale) or `| WHERE internet_exposure == "Yes"` after the `LOOKUP JOIN` (ES|QL).

## Asset context
Internet exposure, criticality and owner come from Falcon Exposure Management, not from the sensor's events, so the queries read them from a lookup you build from it:
1. **Check whether NG-SIEM already has them.** The built-in host lookups may carry some of it (OU, site, server or workstation). List their columns: `readFile("aid_master_main.csv") | head(1)`, and the same for `aid_master_details.csv`. If what you need is there, use that file in the `match` instead.
2. **Otherwise, export it.** In Exposure Management > Assets, filter to managed assets and export with the host ID, internet exposure, criticality and owner columns (whatever your console calls them, such as Managed by or Assigned to). Rename the columns to `aid`, `InternetExposure`, `Criticality`, `Owner`.
3. **Upload it** as `asset_context.csv` under Next-Gen SIEM > Lookup files (or with the NGSIEM lookup-file API). Refresh it on a schedule, say weekly, with a Falcon Fusion workflow or a script, or the context goes stale.
4. **In Elastic,** load the same CSV into an index created with `index.mode: lookup`, named `asset_context`, with the host ID in a field called `host.id` and the others as `internet_exposure`, `criticality`, `owner`. `LOOKUP JOIN` needs Elastic 8.18 or 9.x.

Until the lookup exists, use the plain version.

## Reading the result
- `internet_facing_hosts` is where to start: an internet-facing host running a vulnerable build is the one to patch first.
- `FirstSeen` / `LastSeen` are the first and last time the inventory reported that package in the search window, not its install date. Widen the time range to see how long it's been there.
- **Windows, or anything installed outside the distro's package manager:** the upstream version is the answer. Compare it with the advisory's fixed version.
- **RHEL, Debian, Ubuntu packages: don't judge on the upstream number.** Distros backport security fixes into the version they already ship and only bump the build (TuxCare's fix for CVE-2025-6176 shipped as `1.0.9-7.el9_5.tuxcare.els1`: still "1.0.9", but patched). Compare the full build in `AppVersion` / `builds` with the distro's advisory (RHSA/ALSA, DSA, USN), which names the exact fixed build.
- `unparsed` rows have a version that doesn't start with a number; read those by hand.

## Before running it
- Check the field names: `Appsource` (as in the original search), and in Elastic `data.AppName` and `data.AppVersion`. The asset-context version matches the lookup on `aid`: check the inventory events carry it, or match on `ComputerName` instead.
- To hunt another package, change the `brotli` in the name filter.

## What it misses
- Copies of brotli bundled inside Python wheels, Node modules or applications: they aren't in the installed-application inventory. Dependency scanning (Aikido) covers those.
- Hosts without Falcon, or where the inventory hasn't refreshed since the last update.
