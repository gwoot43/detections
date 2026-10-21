---
id: CP06
name: Microsoft Defender protection weakened (real-time off, exclusion added, ASR or network protection off, tamper attempt)
category: controlplane
status: todo
language: esql
index: logs-windows.windows_defender-*
mitre: [T1685, T1112]
data_source: Defender Operational channel. 5007 configuration changed (old and new registry value), 5001 real-time protection disabled, 5013 tamper protection blocked a change.
suppression:
  fields: [setting, change]
  duration: 24h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
Event 5007 records **every** Defender setting change as an old and a new registry value, whichever way it was made: `Set-MpPreference`, the Windows Security app, a direct `reg add`, Group Policy, Intune, or a tool that registers a fake AV. This rule owns Defender settings changes: it catches the *result*, whatever command or tool made it. W05 no longer matches `Set-MpPreference`, `Add-MpPreference` or `DisableAntiSpyware` commands; it keeps the process-side signals 5007 cannot see (Defender services stopped, the engine wiped with `MpCmdRun`, safe boot set).

Only changes that make protection weaker are kept:
- Real-time, behaviour, script, download or on-access scanning switched off, or Defender AV turned off outright.
- Exclusions added (path, extension, process, IP), or an ASR-only exclusion.
- Cloud protection, sample submission or block at first sight turned off.
- Network protection or controlled folder access switched off or set to audit, or an app allowed through controlled folder access.
- An ASR rule set to off or audit.
- Tamper protection turned off.
- A known threat set to "allow".
- 5001: real-time protection reported disabled.
- 5013: tamper protection **blocked** a change. That is an attempt that failed, which is worth knowing about on its own.

**How policy changes are handled.** Changes written under `\Policies\` come from Group Policy or Intune and usually reach many hosts. They are held back until the change is four hours old, and then alert only if three or fewer hosts got it. A fleet rollout stays quiet. A policy key written by hand on one or two hosts (a common attacker shortcut) still alerts. Local changes alert on the next run.

GPO-driven changes at fleet scale belong to **WE06** (GPO modification). Intune-driven ones belong to **W13**.

## Prerequisite
- Turn on the **Windows Defender** stream in the Elastic Windows integration. It ships disabled.
- Rule interval 30 minutes, lookback 12 hours. The long lookback is what lets the policy branch wait four hours. Local changes still alert on the first run after they happen.
- The query reads `message` rather than `winlog.event_data.New_Value`. Those event data fields are only mapped once the first 5007 has been indexed, so this way the rule won't fail on a quiet fleet.

## Query
```esql
FROM logs-windows.windows_defender-*
| WHERE event.code IN ("5007", "5001", "5013")
| EVAL msg = TO_LOWER(COALESCE(message, ""))
| GROK msg """new value:[ \t]*%{GREEDYDATA:new_raw}"""
| GROK msg """old value:[ \t]*%{GREEDYDATA:old_raw}"""
| GROK msg """\n[ \t]*value:[ \t]*%{GREEDYDATA:tp_raw}"""
| EVAL value = TRIM(CASE(event.code == "5007", COALESCE(new_raw, ""), event.code == "5013", COALESCE(tp_raw, ""), "")),
       old_value = TRIM(COALESCE(old_raw, ""))
| EVAL weakened = CASE(
         value LIKE "*disablerealtimemonitoring = 0x1", "real-time protection off",
         value LIKE "*disablebehaviormonitoring = 0x1", "behaviour monitoring off",
         value LIKE "*disableioavprotection = 0x1", "download scanning off",
         value LIKE "*disableonaccessprotection = 0x1", "on-access protection off",
         value LIKE "*disablescriptscanning = 0x1", "script scanning off",
         value LIKE "*disableantispyware = 0x1" OR value LIKE "*disableantivirus = 0x1", "defender antivirus turned off",
         value LIKE "*disableblockatfirstseen = 0x1", "block at first sight off",
         value LIKE "*spynetreporting = 0x0", "cloud protection off",
         value LIKE "*submitsamplesconsent = 0x2", "sample submission off",
         value LIKE "*tamperprotection = 0x0" OR value LIKE "*tamperprotection = 0x4", "tamper protection off",
         value LIKE "*enablenetworkprotection = 0x0" OR value LIKE "*enablenetworkprotection = 0x2", "network protection off or audit",
         value LIKE "*enablecontrolledfolderaccess = 0x0" OR value LIKE "*enablecontrolledfolderaccess = 0x2", "controlled folder access off or audit",
         value LIKE """*\\controlled folder access\\allowedapplications\\*""", "app allowed through controlled folder access",
         value LIKE """*\\asr\\rules\\* = 0x0""" OR value LIKE """*\\asr\\rules\\* = 0x2""", "asr rule off or audit",
         value LIKE """*\\asronlyexclusions\\*""", "asr exclusion added",
         value LIKE """*\\exclusions\\paths\\*""" OR value LIKE "*excludedpaths = *", "path exclusion added",
         value LIKE """*\\exclusions\\extensions\\*""" OR value LIKE "*excludedextensions = *", "extension exclusion added",
         value LIKE """*\\exclusions\\processes\\*""" OR value LIKE "*excludedprocesses = *", "process exclusion added",
         value LIKE """*\\exclusions\\ipaddresses\\*""", "ip exclusion added",
         value LIKE """*\\threatiddefaultaction\\* = 0x6""", "known threat set to allow",
         NULL)
| EVAL setting = CASE(event.code == "5001", "real-time protection disabled (5001)",
                      event.code == "5013", CONCAT("tamper protection blocked: ", COALESCE(weakened, "protected setting")),
                      weakened),
       scope = CASE(event.code == "5001", "state", value LIKE """*\\policies\\*""", "policy", "local")
| WHERE setting IS NOT NULL
| EVAL change = CASE(event.code == "5007" OR scope == "policy", value, TO_LOWER(host.name))
| STATS hosts = COUNT_DISTINCT(host.name), host_list = VALUES(host.name), first_seen = MIN(@timestamp),
        last_seen = MAX(@timestamp), previous_values = VALUES(old_value), events = COUNT(*)
    BY setting, scope, change
| WHERE scope != "policy" OR (hosts <= 3 AND DATE_DIFF("minute", first_seen, NOW()) >= 240)
| KEEP setting, scope, change, hosts, host_list, first_seen, last_seen, previous_values, events
```

**How the parsing works.** 5007 renders as two lines, `Old value: <key>\<name> = <data>` and `New value: <key>\<name> = <data>`. Each `GROK` captures one line. `[ \t]*` is used instead of `\s+` so an empty old value (a newly added exclusion) can't swallow the next line. An exclusion being *removed* leaves the new value empty, so it never matches. 5013 renders the blocked setting on a `Value:` line.

**How grouping works.** Alerts group by the exact new value, so one exclusion pushed to many hosts is one alert with the host list. 5001 and local 5013 group per host.

## Suppression
Suppress by `setting`, `change` for 24h. Alerts missing a key field are not suppressed. The 12-hour lookback means each change is seen by roughly 24 runs, and suppression keeps that to one alert. A different exclusion path, a different setting, or a 5001 on another host still alerts.

## Known false positives / exclusions
- **5001 when Falcon is installed** and Defender steps down into passive mode on a new build. Expect it once per host at build time. If your build process is noisy, exclude 5001 for hosts whose `change` (host name) matches the build-time naming pattern, or drop 5001 and rely on the 5007 branch.
- **Software installers that add their own exclusion locally**, such as backup, database and some EDR products. They show up as one `local` alert with many hosts. Add the exact `change` value to an exclusion list in the WHERE.
- **A legacy GPO that keeps trying to set `DisableAntiSpyware`** on tamper-protected hosts produces repeated 5013s. Fix the GPO, because the setting is ignored on current platforms anyway.

## Triage
- **Local exclusion or protection off on a few hosts:** pull FDR for each host around `first_seen`. Find the process that made the change (`powershell` with `Set-MpPreference` or `Add-MpPreference`, `reg.exe`, or an unknown binary), then check what ran next from the excluded path. An exclusion is usually set up just before a payload is dropped there.
- **Tamper protection blocked:** the change failed, but the attempt is the signal. Find the process and treat the host as hands-on-keyboard until proven otherwise.
- **Policy scope on a few hosts:** check whether a GPO or Intune profile scoped to those hosts really changed (WE06, W13). If none did, the policy key was written by hand.

## Test
- Local exclusion: `Add-MpPreference -ExclusionPath C:\Temp\cp06test` on a lab host with tamper protection off, then remove it.
- Tamper attempt: with tamper protection on, `Set-MpPreference -DisableRealtimeMonitoring $true` should log 5013 and nothing changes. Check the `Value:` line parses into `setting`. If your build words it differently, adjust the third `GROK`.
