---
id: CP04
name: CrowdStrike sensor online in Reduced Functionality Mode on a host people use
category: controlplane
status: todo
language: esql
index: logs-yourorg-crowdstrike-data-default*
mitre: [T1685]
data_source: CrowdStrike FDR (SensorHeartbeat, SensorMetadataUpdate, OsVersionInfo, UserLogon)
suppression:
  fields: [host.id]
  duration: 24h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
**One question:** is a host that people use online right now with its Falcon sensor in Reduced Functionality Mode? RFM is when the sensor loads but runs with protection and visibility cut back, usually after a kernel or OS update it doesn't yet support. The host looks online but is lightly defended. Most RFM is transient, and most of what's left is on machines nobody uses, so the rule narrows to the cases that matter:

- **Anchor:** the sensor reports RFM. Heartbeats carry it as bit 1 of `SensorStateBitMap`; metadata and OS events carry it as `RFMState`.
- **Corroborating properties:**
  - **Still in RFM:** no normal report since the last RFM one.
  - **Online and stuck:** a heartbeat in the last 15 minutes, every heartbeat in the last 35 minutes in RFM, and online in RFM for at least 25 of them. A host that's just booting or briefly flipping doesn't qualify.
  - **A person uses it:** at least one human logon in the 7-day lookback. A device with no human logons is most likely stored, headless or unattended (servers, kiosks, VDI with nobody on it).
- **Exclusion:** during patch week (days 8 to 17 of the month, local time), RFM is expected while sensors catch up with new kernels, so it only alerts once the episode has lasted 12 hours.

## Query
Run every 30 minutes with a 7-day lookback.
```esql
FROM logs-yourorg-crowdstrike-data-default*
// 1 GATE: the events that report the sensor's state (heartbeats, metadata and OS updates), and user logons, from
// Windows and Linux.
| WHERE event.action IN ("sensorheartbeat", "sensormetadataupdate", "osversioninfo", "userlogon")
  AND data.event_platform IN ("Win", "Lin")
// 2 SHAPE: heartbeats carry RFM as bit 1 (value 2) of SensorStateBitMap; metadata and OS events carry RFMState.
// "Recent" is the last 35 minutes. A human logon is one your pipeline labels as a person's account (placeholder field).
| EVAL hb_rfm = event.action == "sensorheartbeat" AND (TO_INTEGER(data.SensorStateBitMap) / 2) % 2 == 1,
       hb_ok = event.action == "sensorheartbeat" AND (TO_INTEGER(data.SensorStateBitMap) / 2) % 2 == 0,
       is_recent = @timestamp >= NOW() - 35 minutes
| EVAL rfm_ts = CASE(hb_rfm OR data.RFMState == "1", @timestamp, NULL),
       ok_ts = CASE(hb_ok OR data.RFMState == "0", @timestamp, NULL),
       hb_ts = CASE(event.action == "sensorheartbeat", @timestamp, NULL),
       recent_hb_ts = CASE(event.action == "sensorheartbeat" AND is_recent, @timestamp, NULL),
       recent_rfm_hb_ts = CASE(hb_rfm AND is_recent, @timestamp, NULL),
       human_logon_ts = CASE(event.action == "userlogon" AND yourorg.user.account_type == "human", @timestamp, NULL)
// 3 REDUCE: one row per sensor: its RFM reports, its last normal report, its heartbeats and its human logons.
| STATS host.name = VALUES(host.name),
        platform = VALUES(data.event_platform),
        rfm_events = COUNT(rfm_ts),
        first_rfm = MIN(rfm_ts),
        last_rfm = MAX(rfm_ts),
        last_normal = MAX(ok_ts),
        last_heartbeat = MAX(hb_ts),
        recent_hbs = COUNT(recent_hb_ts),
        recent_rfm_hbs = COUNT(recent_rfm_hb_ts),
        first_recent_hb = MIN(recent_hb_ts),
        last_human_logon = MAX(human_logon_ts),
        human_logons = COUNT(human_logon_ts)
    BY host.id
// 4 DECIDE. Thresholds (source: set by the team from the heartbeat cadence and delivery lag): RFM reported, still in
// RFM, a heartbeat in the last 15 minutes, every recent heartbeat in RFM, online in RFM for 25+ minutes.
| WHERE rfm_events > 0
| EVAL names = TO_LOWER(COALESCE(MV_CONCAT(host.name, ","), ""))
// Kubernetes nodes (placeholder pattern). They have no human logons either, so the next line drops them as well.
| WHERE NOT (names LIKE "ip-100-*.ap-southeast-*.compute.internal*")
// Only hosts a human actually uses: at least one human logon in the 7 days. Excludes servers, headless, kiosk and
// unattended VDI machines that sit in RFM with nobody on them, which are most likely stored devices.
| WHERE human_logons > 0
| WHERE last_normal IS NULL OR last_rfm > last_normal
| EVAL mins_since_heartbeat = DATE_DIFF("minute", last_heartbeat, NOW()),
       online_rfm_minutes = DATE_DIFF("minute", first_recent_hb, NOW())
| WHERE mins_since_heartbeat <= 15
  AND recent_hbs > 0
  AND recent_rfm_hbs == recent_hbs
  AND online_rfm_minutes >= 25
// Patch week (days 8-17 of the month, local time: UTC+10 here, so +10 hours; use your offset): RFM is expected while
// sensors catch up with new kernels, so it only alerts once the episode has lasted 12 hours.
| EVAL episode_start = COALESCE(last_normal, first_rfm),
       rfm_episode_minutes = DATE_DIFF("minute", episode_start, NOW()),
       dom_local = DATE_EXTRACT("day_of_month", episode_start + 10 hours),
       in_patch_window = dom_local >= 8 AND dom_local <= 17
| WHERE NOT in_patch_window OR rfm_episode_minutes >= 720
// 6 OUTPUT
| KEEP host.id, host.name, platform, in_patch_window, episode_start, first_rfm, last_rfm,
       last_normal, last_heartbeat, rfm_episode_minutes, online_rfm_minutes, mins_since_heartbeat,
       recent_hbs, recent_rfm_hbs, last_human_logon, human_logons
```

**CrowdStrike (Falcon LogScale / Advanced Event Search)**, run every 30 minutes over the last 7 days. The human-logon test here approximates the pipeline's enrichment: an interactive, remote-interactive or cached logon (types 2, 10, 11) by a domain or local user account (`S-1-5-21-`), not a machine, window-manager or font-driver account.
```logscale
#event_simpleName=/^(SensorHeartbeat|SensorMetadataUpdate|OsVersionInfo|UserLogon)$/ event_platform=/^(Win|Lin)$/
// 2 SHAPE: which state each event reports. Heartbeats carry RFM as bit 1 of SensorStateBitMap; metadata and OS events
// carry RFMState. The heartbeat branch comes first, so a heartbeat is always counted as one.
| case {
    #event_simpleName=SensorHeartbeat
      | hb_ts := @timestamp
      | bitfield:extractFlags(field=SensorStateBitMap, output=[[1, InRFM]])
      | case { InRFM=true | rfm_ts := @timestamp | hb_rfm_ts := @timestamp; * | ok_ts := @timestamp; };
    #event_simpleName=UserLogon LogonType=/^(2|10|11)$/ UserSid=/^S-1-5-21-/ UserName!=/\$$|^(DWM|UMFD)-/i
      | human_ts := @timestamp;
    RFMState="1" | rfm_ts := @timestamp;
    RFMState="0" | ok_ts := @timestamp;
    *;
  }
// Heartbeats in the last 35 minutes (2,100,000 ms), all and in RFM.
| _now := now()
| case { test(hb_ts >= _now - 2100000) | recent_hb_ts := hb_ts; * }
| case { test(hb_rfm_ts >= _now - 2100000) | recent_rfm_hb_ts := hb_rfm_ts; * }
// 3 REDUCE: one row per sensor.
| groupBy([aid], function=[count(rfm_ts, as=rfm_events), min(rfm_ts, as=first_rfm), max(rfm_ts, as=last_rfm),
                           max(ok_ts, as=last_normal), max(hb_ts, as=last_heartbeat), count(recent_hb_ts, as=recent_hbs),
                           count(recent_rfm_hb_ts, as=recent_rfm_hbs), min(recent_hb_ts, as=first_recent_hb),
                           max(human_ts, as=last_human_logon), count(human_ts, as=human_logons),
                           collect([ComputerName, event_platform])], limit=max)
// 4 DECIDE. Thresholds (source: set by the team from the heartbeat cadence and delivery lag), as in the ES|QL version.
| rfm_events > 0
| human_logons > 0
| NOT ComputerName=/^ip-100-.*\.compute\.internal/i
| default(field=last_normal, value=0)
| test(last_rfm > last_normal)
| _now := now()
| mins_since_heartbeat := (_now - last_heartbeat) / 60000
| online_rfm_minutes := (_now - first_recent_hb) / 60000
| mins_since_heartbeat <= 15
| recent_hbs > 0
| test(recent_rfm_hbs == recent_hbs)
| online_rfm_minutes >= 25
// Patch week, in local time with daylight saving handled: days 8-17 only alert after 12 hours in RFM.
| case { last_normal > 0 | episode_start := last_normal; * | episode_start := first_rfm; }
| rfm_episode_minutes := (_now - episode_start) / 60000
| dom_local := formatTime("%d", field=episode_start, timezone="Australia/Sydney")
| case { test(dom_local >= 8 AND dom_local <= 17) | in_patch_window := "true"; * | in_patch_window := "false"; }
// Deliberately no * branch: this case is a filter. Outside patch week, or 12+ hours in RFM.
| case { in_patch_window="false"; rfm_episode_minutes >= 720; }
// 5 ENRICH: host name from the sensor inventory, in case these events don't carry ComputerName.
| match(file="aid_master_main.csv", field=aid, include=[ComputerName], strict=false)
// 6 OUTPUT
| select([aid, ComputerName, event_platform, in_patch_window, episode_start, first_rfm, last_rfm, last_normal, last_heartbeat,
          rfm_episode_minutes, online_rfm_minutes, mins_since_heartbeat, recent_hbs, recent_rfm_hbs, last_human_logon, human_logons])
```

## Rule settings
| | |
|---|---|
| Interval / lookback | every 30 minutes / 7 days. The lookback is the human-logon history; the RFM checks use the last 35 minutes and the current episode. |
| Suppression | `host.id` (`aid`) for 24h. RFM lasts until the host is fixed, so one alert per sensor a day is enough. |

**Cost.** Heartbeats are frequent, and the 7-day lookback reads a week of them. If the query is slow, read heartbeats for the last 24 hours only (`event.action == "sensorheartbeat" AND @timestamp >= NOW() - 24 hours` in the gate) and keep 7 days for the other events. Every decision except the episode length uses less than an hour of heartbeats, and the 12-hour patch-week test fits within 24.

## Telemetry assumptions
- `sensorheartbeat` with `data.SensorStateBitMap` (bit 1 is RFM); `sensormetadataupdate` and `osversioninfo` with `data.RFMState`.
- `userlogon` with the pipeline's account-type label (`yourorg.user.account_type` is a placeholder for your field; `human` for a person's account).
- `data.event_platform` (`Win`, `Lin`).

Confirm them over the last hour:
```esql
FROM logs-yourorg-crowdstrike-data-default*
| WHERE event.action IN ("sensorheartbeat", "sensormetadataupdate", "osversioninfo", "userlogon")
| STATS events = COUNT(*), sensors = COUNT_DISTINCT(host.id), with_bitmap = COUNT(data.SensorStateBitMap),
        with_rfm_state = COUNT(data.RFMState), human_logons = COUNT(*) WHERE yourorg.user.account_type == "human"
    BY event.action
```
```logscale
#event_simpleName=/^(SensorHeartbeat|SensorMetadataUpdate|OsVersionInfo|UserLogon)$/
| groupBy([#event_simpleName], function=[count(as=events), count(aid, distinct=true, as=sensors), count(SensorStateBitMap, as=with_bitmap),
                                        count(RFMState, as=with_rfm_state)], limit=max)
```
To check that a host leaving RFM reports it, look at one host's timeline: `aid=<aid> RFMState=*` in LogScale should show a `SensorMetadataUpdate` with `RFMState` 0, and its heartbeats' bit 1 should clear.

## Suppression
Suppress by `host.id` for 24h. Alerts missing a key field are not suppressed.

## Known false positives / exclusions
- A device that had a human logon in the last 7 days and is then shelved while in RFM. It alerts until it stops heartbeating.
- Patch week: RFM in the days after Patch Tuesday is expected; it alerts only after 12 hours.

## Blind spots
- **Hosts nobody logs into.** Servers, kiosks and unattended machines in RFM are left out on purpose. If server coverage matters, run a copy without the human-logon line, with a longer grace period.
- **A stored device brought back in RFM** alerts only after its first human logon.
- **Daylight saving** in the ES|QL version: `+ 10 hours` is standard time; in daylight saving local time is an hour later, which only matters for an episode that starts within an hour of midnight on day 8 or 17. The LogScale version uses the time zone and handles it.
- macOS sensors (`event_platform` `Mac`) are out of scope.

## Triage
- Identify the OS or kernel build that triggered RFM, and move the host to a sensor version that supports it. Until then, treat it as lightly protected and lean on the non-endpoint rules.
- `last_human_logon` and the user show who's working on an unprotected machine: tell them, or take it off the network until it's fixed.
- RFM that started without an OS or kernel change, or a sensor that stops heartbeating after RFM, can be tampering: check CS05.

## Test
Validate against a host the Falcon console shows in RFM, or move a lab host to an unsupported kernel and log on to it interactively. It should alert after 25 minutes online in RFM (12 hours during patch week).
