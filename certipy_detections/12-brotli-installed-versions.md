---
id: HUNT-01
name: Hunt - brotli installed across the estate, by upstream version (distro build kept alongside)
language: esql
index: logs-yourorg-crowdstrike-data-default*
mitre: [T1190]
data_source: CrowdStrike Falcon installed-application inventory (InstalledApplication)
suppression:
  fields: [data.AppName]
  duration: 24h
  missing_fields: do_not_suppress
---
A hunt, not an alert: where brotli is installed and which version. Package versions come with the distro's build attached (`1.1.0-7.el10_1` on RHEL, `1.0.9-2+b2` on Debian, sometimes an epoch like `1:1.0.9-2`), so the query pulls out the upstream version (`1.1.0`, `1.0.9`) to group on, and keeps the exact builds next to it.

**CrowdStrike (Falcon LogScale)**
```logscale
//Filter for installed applications with brotli in the name (brotli, libbrotli, brotli-devel, python3-brotli...)
#event_simpleName=InstalledApplication AppName=/brotli/i
//Upstream version: drop any epoch ("1:") and the distro build after it ("-7.el10_1", "-2+b2")
| regex("^(\\d+:)?v?(?<UpstreamVersion>\\d+(\\.\\d+)*)", field=AppVersion, strict=false)
| default(field=UpstreamVersion, value="unparsed")
//Group by package and upstream version, keeping the exact builds and where they are
| groupBy([AppName, UpstreamVersion], function=[count(aid, distinct=true, as=hosts), collect([AppVersion, ComputerName, AppSource], limit=100)], limit=max)
```

**Elastic (ES|QL)**
```esql
FROM logs-yourorg-crowdstrike-data-default*
// Filter for installed applications with brotli in the name
| WHERE event.action == "installedapplication" AND data.AppName IS NOT NULL
| WHERE TO_LOWER(data.AppName) LIKE "*brotli*"
// Upstream version: drop any epoch and the distro build after it
| GROK data.AppVersion """^(\d+:)?v?(?<upstream_version>\d+(\.\d+)*)"""
| EVAL upstream_version = COALESCE(upstream_version, "unparsed")
// Group by package and upstream version, keeping the exact builds and where they are
| STATS hosts = COUNT_DISTINCT(host.id), builds = VALUES(data.AppVersion), host_sample = TOP(host.name, 20, "asc")
    BY data.AppName, upstream_version
```

## Reading the result
- **Windows, or anything installed outside the distro's package manager:** the upstream version is the answer. Compare it with the advisory's fixed version.
- **RHEL, Debian, Ubuntu packages: don't judge on the upstream number.** Distros backport security fixes into the version they already ship and only bump the build (TuxCare's fix for CVE-2025-6176 shipped as `1.0.9-7.el9_5.tuxcare.els1`: still "1.0.9", but patched). Compare the full build in `AppVersion` / `builds` with the distro's advisory (RHSA/ALSA, DSA, USN), which names the exact fixed build.
- `unparsed` rows have a version that doesn't start with a number; read those by hand.

## Before running it
- Check the field names: `AppSource` (it may be spelled `Appsource` in your tenant), and in Elastic `data.AppName`, `data.AppVersion` and the `event.action` value. If your hits come from a different event, find it with `brotli | groupBy(#event_simpleName)` in LogScale.
- To hunt another package, change the `brotli` in the name filter.

## What it misses
- Copies of brotli bundled inside Python wheels, Node modules or applications: they aren't in the installed-application inventory. Dependency scanning (Aikido) covers those.
- Hosts without Falcon, or where the inventory hasn't refreshed since the last update.
