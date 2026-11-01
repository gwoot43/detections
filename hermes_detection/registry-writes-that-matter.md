# Registry writes that matter — one rule on the native event, no `reg.exe` twin

Almost every registry modification is normal: installers, updaters, per-user app settings, Defender platform refreshes. A rule that alerts on "registry modified" is a change-log, and a second rule watching `reg.exe add` command lines alerts on the *same write* a second time - Falcon's native registry event already carries the process that made the write, so the CLI rule is a duplicate signal, not extra coverage.

This rule keeps the native event and adds the two things that make it precise:

**The key has to be somewhere worth writing.** A fixed set of families where a value *is* the persistence: `Run`/`RunOnce`, `Winlogon`, IFEO (`Debugger`, `GlobalFlag`) and its newer `SilentProcessExit` sibling (`MonitorProcess`, `ReportingMode`), `AppInit_DLLs`, COM `InprocServer32`/`LocalServer32`/`ScriptletURL`, `Services` keys, LSA packages, `WDigest`, shell open commands. This is a list of *targets*, not of tools - the kind of list that ages slowly.

**The writer has to be unusual.** Two ways to be unusual, and either one is enough: the value it wrote points at a user-writable path, a script host, an encoded blob or a URL (content); or this process has written this key family on at most two hosts in the estate (rarity). An app that legitimately writes a `Run` key does so on every host it is installed on; a loader does it once.

`reg.exe` is not excluded and not separately detected. It appears as `writer`, and because it is a generic administrative tool it must satisfy the *content* test - `reg.exe add ... /d C:\Temp\x.exe` trips it, `reg.exe add ... /d "C:\Program Files\Vendor\App.exe"` does not.

```esql
FROM logs-yourorg-crowdstrike-data-default*
// 15 minutes, stated in the query. Registry churn is continuous; the window keeps the fleet counts honest.
| WHERE @timestamp >= NOW() - 15 minutes
  AND event.action IN ("asepvalueupdate", "reggenericvalueupdate", "regsystemconfigvalueupdate", "registryoperationdetectinfo")
  AND host.os.type == "windows"
| EVAL k = TO_LOWER(TO_STRING(COALESCE(registry.path, registry.key))),
       v = TO_LOWER(TO_STRING(COALESCE(registry.data.strings, registry.value))),
       writer = TO_LOWER(COALESCE(process.name, "unknown")),
       cl = TO_LOWER(COALESCE(process.command_line, ""))
// The families where a value is the persistence. Everything else falls out here, which is why this is not a
// registry change-log.
| EVAL fam = CASE(
        k LIKE """*\\currentversion\\run*""" OR k LIKE """*\\currentversion\\runonce*""", "run",
        k LIKE """*\\winlogon*""", "winlogon",
// Both halves of T1546.012: the classic Debugger/GlobalFlag values under IFEO, and the newer
// SilentProcessExit MonitorProcess/ReportingMode pair that IFEO-only rules miss.
        k LIKE """*\\image file execution options*""" OR k LIKE """*\\silentprocessexit*""", "ifeo",
        k LIKE """*\\appinit_dlls*""", "appinit",
        k LIKE """*\\inprocserver32*""" OR k LIKE """*\\localserver32*""" OR k LIKE """*\\scriptleturl*""", "com",
        k LIKE """*\\services\\*""", "service",
        k LIKE """*\\control\\lsa*""", "lsa",
        k LIKE """*\\wdigest*""", "wdigest",
        k LIKE """*\\currentversion\\policies\\explorer*""", "policy",
        k LIKE """*\\shell\\open\\command*""", "shellexec",
        "")
| WHERE fam != ""
// Content test: the value points somewhere a signed vendor would not install to, or asks a script host to run it.
| EVAL payload_bad = v LIKE """*\\temp\\*""" OR v LIKE """*\\appdata\\*""" OR v LIKE """*\\users\\public\\*"""
                    OR v LIKE """*\\downloads\\*""" OR v LIKE """*\\programdata\\*"""
                    OR v LIKE "*powershell*" OR v LIKE "*pwsh*" OR v LIKE "*mshta*" OR v LIKE "*wscript*"
                    OR v LIKE "*rundll32*" OR v LIKE "*regsvr32*" OR v LIKE "*certutil*" OR v LIKE "*bitsadmin*"
                    OR v LIKE "* -enc*" OR v LIKE "*frombase64*" OR v LIKE "*http*",
// Generic administrative and scripting writers: they need the content test, because one host running reg.exe
// against a Run key is maintenance, and rarity would flag it every time.
       generic_writer = writer IN ("reg.exe", "regedt32.exe", "regedit.exe", "powershell.exe", "pwsh.exe", "cmd.exe", "wmic.exe")
| STATS writes = COUNT(*), keys = COUNT_DISTINCT(k), bad_writes = COUNT(*) WHERE payload_bad,
        value_sample = MV_SLICE(VALUES(v), 0, 5),
        key_sample = MV_SLICE(VALUES(k), 0, 3),
        lineage = MV_SLICE(VALUES(cl), 0, 3),
        first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
    BY host.id, host.name, writer, fam
// Rarity: how many hosts this writer has touched this key family on. A vendor writes fleet-wide; a loader
// writes once. Counted after the family filter, so only plausible targets count.
| INLINE STATS fam_hosts = COUNT_DISTINCT(host.id) BY writer, fam
// Either the content is wrong, or the writer is new to this family and is not a generic CLI tool.
// 2 hosts is the starting value for rarity: a vendor writes this family on every host it is installed on,
// and the baseline at the foot of this file is the source that sets it.
| WHERE bad_writes >= 1 OR (fam_hosts <= 2 AND NOT generic_writer)
| SORT writes DESC
| LIMIT 100
```

Deploy every 5 minutes over the last 15. Suppress by `host.id`, `fam` for 24h.

## Reading the alert
- **`fam`** says what was achieved: `run`/`winlogon`/`ifeo` are logon-time execution, `com` is hijacking something already run by a trusted process, `lsa`/`wdigest` are credential access, `service` is a persistent host process.
- **`value_sample`** is the payload. A path under `%TEMP%`, `%APPDATA%` or `%PROGRAMDATA%` with a `.dll`, `.exe`, `.ps1` or `.js` is persistence; an `http://` value is a downloader.
- **`lineage`** is where `reg.exe` earns its keep: not that it ran, but that its parent was an Office application, a browser, or `wscript.exe`.
- **`fam_hosts`** is the fleet view. `1` means one host in this window wrote this family with this writer - for a vendor process, that is either a fresh rollout or a foothold.

## Nearest benign twins
- **Software installers and per-user auto-start apps** (Zoom, Slack, Spotify, browsers) that write `Run` keys under `%APPDATA%`. They are content-flagged by design, and they are why the first week needs entity pairs: `writer` + `fam`, usually with the vendor's install path.
- **Defender platform updates**, which rewrite their own paths under `%PROGRAMDATA%\Microsoft\Windows Defender\Platform`. If they show up here, they do so through the content test - exclude the exact path, not the writer, so a renamed binary still trips.
- **OneDrive, Teams and other per-user updaters**, which rewrite their `Run` values on every update cycle.
- **A backup or management agent** that writes LSA or service values. Legitimate, and rare enough per family to hit the rarity branch; entity pair after the first alert.

## What it misses
- **Values written through a driver or the kernel** (some EDR tamper attempts) never appear as a process write.
- **`offline` registry writes** from WIM, hive files or `reg load` into a mounted image. The path exists; the process context does not.
- **A writer that is fleet-common because the attacker deployed it broadly** (a malicious updater). The content test still catches it if the value points at a user-writable path; rarity will not.
- **Deltas without a value** - key creation alone, a permission change, a value delete. `asepvalueupdate` and the `reggenericvalueupdate` events are the write-shaped half; deletions need their own branch if you care.
- **Linux.** This rule is Windows-only; the equivalents on the estate's Linux hosts are the persistence files themselves (`~/.config/autostart`, systemd units, crontab), which need file telemetry in this feed.

## Baseline
```esql
FROM logs-yourorg-crowdstrike-data-default*
| WHERE @timestamp >= NOW() - 7 days
  AND event.action IN ("asepvalueupdate", "reggenericvalueupdate", "regsystemconfigvalueupdate")
  AND host.os.type == "windows"
| EVAL k = TO_LOWER(TO_STRING(COALESCE(registry.path, registry.key))),
       writer = TO_LOWER(COALESCE(process.name, "unknown"))
| WHERE k LIKE """*\\currentversion\\run*""" OR k LIKE """*\\winlogon*""" OR k LIKE """*\\image file execution options*"""
     OR k LIKE """*\\inprocserver32*""" OR k LIKE """*\\control\\lsa*"""
| STATS writes = COUNT(*), hosts = COUNT_DISTINCT(host.id) BY writer
| SORT hosts DESC
| LIMIT 40
```
The top rows are the estate's legitimate writers - installers, updaters, agents. Everything below them is where `fam_hosts <= 2` starts to bite.

## Probe before enabling
```esql
FROM logs-yourorg-crowdstrike-data-default*
| WHERE @timestamp >= NOW() - 1 hour
| STATS n = COUNT(*), with_path = COUNT(*) WHERE registry.path IS NOT NULL,
        with_value = COUNT(*) WHERE registry.data.strings IS NOT NULL
    BY event.action
| SORT n DESC
| LIMIT 15
```
If `with_path` and `with_value` are zero on the registry actions, the pipeline is not parsing the registry block and the rule is silently dead - switch the field names to the raw FDR ones (`RegObjectName`, `RegValueName`, `RegStringValue`) before deploying.

## References
- `rules/07-crowdstrike-fdr/CS02` - the earlier ASEP rule; this one adds writer rarity and folds the `reg.exe` command-line rule into the same event
- MITRE T1547.001 (Run keys), T1546.012 (IFEO), T1546.015 (COM hijacking), T1547.005 (authentication packages)
- Microsoft, *Autoruns* categories - the definitive list of ASEPs, and the reason the family list above is short
- `rules/11-behaviour/B09`, `W11-com-hijack-and-office-addin.md` - the process-side view of the same behaviours, where a rule on the *writer* is the right anchor
