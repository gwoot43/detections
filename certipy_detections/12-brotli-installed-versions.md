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
Built on the original search: free text `brotli`, which is known to return the inventory data. The inventory reports the same package again and again, so each host is first cut down to its most recent report of each package: a host that upgraded counts once, at its current version.

**CrowdStrike (Falcon LogScale)**
```logscale
//Filter for brotli, as in the original search, keeping events that name an application
brotli AppName=*
//Keep each host's most recent report of each package (an upgraded host counts once, at its current version)
| groupBy([ComputerName, AppName], function=[selectFromMax(field=@timestamp, include=[AppVersion, Appsource]), min(@timestamp, as=FirstSeen), max(@timestamp, as=LastSeen)], limit=max)
//Upstream version: drop any epoch ("1:") and the distro build after it ("-7.el10_1", "-2+b2")
| case {
    AppVersion=/^(\d+:)?v?(?<UpstreamVersion>\d+(\.\d+)*)/ ;
    * | UpstreamVersion := "unparsed";
  }
//Group by package and upstream version, keeping the exact builds and where they are
| groupBy([AppName, UpstreamVersion], function=[count(ComputerName, distinct=true, as=hosts), min(FirstSeen, as=FirstSeen), max(LastSeen, as=LastSeen), collect([AppVersion, Appsource]), collect([ComputerName], limit=100)], limit=max)
//First and last seen in the search window, in Sydney time
| FirstSeen := formatTime("%Y-%m-%d %H:%M:%S", field=FirstSeen, timezone="Australia/Sydney")
| LastSeen := formatTime("%Y-%m-%d %H:%M:%S", field=LastSeen, timezone="Australia/Sydney")
```
Free text reads every event for the word, so it's slow over long ranges. To speed it up, find which event the hits come from with `brotli | groupBy(#event_simpleName)` and put `#event_simpleName=<that event>` in front of the search.

For one row per host instead (its current version and when it last reported it), stop after the first `groupBy` and the `case`.

**Elastic (ES|QL)**
```esql
FROM logs-yourorg-crowdstrike-data-default*
// Filter for installed applications with brotli in the name
| WHERE data.AppName IS NOT NULL AND TO_LOWER(data.AppName) LIKE "*brotli*"
// Keep each host's most recent report of each package (an upgraded host counts once, at its current version)
| INLINE STATS latest = MAX(@timestamp), host_first_seen = MIN(@timestamp) BY host.name, data.AppName
| WHERE @timestamp == latest
// Upstream version: drop any epoch and the distro build after it
| GROK data.AppVersion """^(\d+:)?v?(?<upstream_version>\d+(\.\d+)*)"""
| EVAL upstream_version = COALESCE(upstream_version, "unparsed")
// Group by package and upstream version, keeping the exact builds and where they are
| STATS hosts = COUNT_DISTINCT(host.name), builds = VALUES(data.AppVersion), host_sample = TOP(host.name, 20, "asc"),
        first_seen = MIN(host_first_seen), last_seen = MAX(latest)
    BY data.AppName, upstream_version
```
`first_seen` and `last_seen` stay dates, so Discover shows them in Kibana's display time zone: set Advanced Settings > `dateFormat:tz` to `Australia/Sydney`. ES|QL has no time zone conversion of its own, and a fixed `+ 10 hours` would be wrong during daylight saving.

## With asset context (internet exposure, criticality, owner)
Needs the `asset_context` lookup described below. The lookup runs once per host, after the most-recent cut, so it's cheap.

**CrowdStrike (Falcon LogScale)**
```logscale
//Filter for brotli, as in the original search, keeping events that name an application
brotli AppName=*
//Keep each host's most recent report of each package (an upgraded host counts once, at its current version)
| groupBy([ComputerName, AppName], function=[selectFromMax(field=@timestamp, include=[AppVersion, Appsource, aid]), min(@timestamp, as=FirstSeen), max(@timestamp, as=LastSeen)], limit=max)
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
| groupBy([AppName, UpstreamVersion], function=[count(ComputerName, distinct=true, as=hosts), count(internet_host, distinct=true, as=internet_facing_hosts), min(FirstSeen, as=FirstSeen), max(LastSeen, as=LastSeen), collect([AppVersion, Appsource]), collect([host_context], limit=100)], limit=max)
//First and last seen in the search window, in Sydney time
| FirstSeen := formatTime("%Y-%m-%d %H:%M:%S", field=FirstSeen, timezone="Australia/Sydney")
| LastSeen := formatTime("%Y-%m-%d %H:%M:%S", field=LastSeen, timezone="Australia/Sydney")
```

**Elastic (ES|QL)**
```esql
FROM logs-yourorg-crowdstrike-data-default*
// Filter for installed applications with brotli in the name
| WHERE data.AppName IS NOT NULL AND TO_LOWER(data.AppName) LIKE "*brotli*"
// Keep each host's most recent report of each package (an upgraded host counts once, at its current version)
| INLINE STATS latest = MAX(@timestamp), host_first_seen = MIN(@timestamp) BY host.id, data.AppName
| WHERE @timestamp == latest
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
        first_seen = MIN(host_first_seen), last_seen = MAX(latest)
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

## Without the installed-application inventory
The inventory only lists what an OS package manager or installer put there. These find the rest. Each one covers a different way brotli gets onto a host; none of them sees a copy that arrived as a dependency and was never written, loaded or run while you were watching.

**1. Installs that name brotli on the command line.** pip, npm, yarn and pnpm installs (never in the inventory), plus the OS package managers (for when it was installed). PyPI calls the package `Brotli`, so the ES|QL matches `*rotli*` to catch both cases without lowercasing every command line. This only sees installs that name brotli: `npm install` from a lock file, or `pip install -r requirements.txt`, pulls it in without saying so.
```logscale
//Filter for package installs that name brotli: pip, npm, yarn, pnpm and the OS package managers
#event_simpleName=ProcessRollup2 CommandLine=/\b(pip[0-9.]*|python[0-9.]*\s+-m\s+pip|npm|yarn|pnpm|apt(-get)?|dnf|yum|rpm|dpkg|zypper|choco|winget)\b.*(install|add|-i|-U)\b.*brotli/i
//One row per host and command: its most recent run, and how many times it ran
| groupBy([ComputerName, CommandLine], function=[selectFromMax(field=@timestamp, include=[UserName, FileName]), max(@timestamp, as=LastRun), count(as=runs)], limit=max)
| LastRun := formatTime("%Y-%m-%d %H:%M:%S", field=LastRun, timezone="Australia/Sydney")
```
```esql
FROM logs-yourorg-crowdstrike-data-default*
// Filter for process starts whose command line mentions brotli or Brotli
| WHERE event.action == "processrollup2" AND process.command_line LIKE "*rotli*"
// Keep package installs: pip, npm, yarn, pnpm and the OS package managers
| WHERE TO_LOWER(process.command_line)
        RLIKE ".*(pip|npm|yarn|pnpm|apt|apt-get|dnf|yum|rpm|dpkg|zypper|choco|winget).*(install|add| -i| -u).*brotli.*"
// One row per host and command: its most recent run, and how many times it ran
| STATS last_run = MAX(@timestamp), runs = COUNT(*), users = VALUES(user.name) BY host.name, process.command_line
```

**2. The brotli command-line tool being run.** Shows where the tool is installed and used, including copies outside the package manager.
```logscale
//Filter for the brotli tool starting, and where it ran from
#event_simpleName=ProcessRollup2 FileName=/^brotli(\.exe)?$/i
| groupBy([ComputerName, ImageFileName], function=[count(as=runs), max(@timestamp, as=LastRun)], limit=max)
| LastRun := formatTime("%Y-%m-%d %H:%M:%S", field=LastRun, timezone="Australia/Sydney")
```
```esql
FROM logs-yourorg-crowdstrike-data-default*
// Filter for the brotli tool starting, and where it ran from
| WHERE event.action == "processrollup2" AND process.name IN ("brotli", "brotli.exe")
| STATS runs = COUNT(*), last_run = MAX(@timestamp) BY host.name, process.executable
```

**3. Applications that bundle their own copy (Windows).** brotli's DLLs (`brotlicommon.dll`, `brotlidec.dll`, `brotlienc.dll`) being loaded, with the folder of the application that ships them, which is who you'd chase for an update. Depends on your tenant recording DLL loads (`ImageHash`); there's no equivalent on Linux.
```logscale
//Filter for brotli DLLs being loaded, and which application folder they come from
#event_simpleName=ImageHash event_platform=Win FileName=/brotli/i
| groupBy([FileName, FilePath], function=[count(ComputerName, distinct=true, as=hosts), collect([ComputerName], limit=20)], limit=max)
```
```esql
FROM logs-yourorg-crowdstrike-data-default*
// Filter for brotli DLLs being loaded, and which application folder they come from
| WHERE event.action == "imagehash" AND data.FileName LIKE "*rotli*"
| STATS hosts = COUNT_DISTINCT(host.name), host_sample = TOP(host.name, 20, "asc") BY data.FileName, data.FilePath
```

**4. brotli library files being written.** Python wheels (`_brotli*.so`, `_brotli*.pyd`), Node packages and applications unpacking their own copy. Falcon records writes of executable files, which these are, but not every file, so treat it as a bonus.
```logscale
//Filter for written files whose name contains brotli, and which process wrote them
#event_simpleName=/Written$/ TargetFileName=/brotli/i
| groupBy([ComputerName, TargetFileName], function=[max(@timestamp, as=LastWritten), collect([ContextBaseFileName])], limit=max)
| LastWritten := formatTime("%Y-%m-%d %H:%M:%S", field=LastWritten, timezone="Australia/Sydney")
```
```esql
FROM logs-yourorg-crowdstrike-data-default*
// Filter for written files whose name contains brotli, and which process wrote them
| WHERE event.action LIKE "*written" AND data.TargetFileName LIKE "*rotli*"
| STATS last_written = MAX(@timestamp), writers = VALUES(data.ContextBaseFileName) BY host.name, data.TargetFileName
```

**5. Looking on the host (Falcon RTR).** For the servers that matter (anything running Python or Node apps), search the disk directly with `runscript`. This finds what's there now, however it got there.
- Linux: `find / -xdev \( -path '*site-packages/brotli*' -o -path '*site-packages/_brotli*' -o -path '*node_modules/brotli*' -o -name 'libbrotli*' \) 2>/dev/null`
- Windows: `Get-ChildItem -Path C:\ -Recurse -Filter '*brotli*' -ErrorAction SilentlyContinue | Select-Object FullName, LastWriteTime`

## Reading the result
- `internet_facing_hosts` is where to start: an internet-facing host running a vulnerable build is the one to patch first.
- `FirstSeen` / `LastSeen` are the first and last time the inventory reported that package in the search window, not its install date. Widen the time range to see how long it's been there. A host whose `LastSeen` is days old while it still reports other software has probably had the package removed.
- **Windows, or anything installed outside the distro's package manager:** the upstream version is the answer. Compare it with the advisory's fixed version.
- **RHEL, Debian, Ubuntu packages: don't judge on the upstream number.** Distros backport security fixes into the version they already ship and only bump the build (TuxCare's fix for CVE-2025-6176 shipped as `1.0.9-7.el9_5.tuxcare.els1`: still "1.0.9", but patched). Compare the full build in `AppVersion` / `builds` with the distro's advisory (RHSA/ALSA, DSA, USN), which names the exact fixed build.
- `unparsed` rows have a version that doesn't start with a number; read those by hand.

## Before running it
- Check the field names: `Appsource` (as in the original search), and in Elastic `data.AppName` and `data.AppVersion`. The asset-context version matches the lookup on `aid`: check the inventory events carry it, or match on `ComputerName` instead.
- To hunt another package, change the `brotli` in the name filter.

## What it misses
- Copies of brotli bundled inside Python wheels, Node modules or applications: they aren't in the installed-application inventory. The searches under "Without the installed-application inventory" catch some; dependency scanning (Aikido) covers your own code and builds.
- Hosts without Falcon, or where the inventory hasn't refreshed since the last update.
