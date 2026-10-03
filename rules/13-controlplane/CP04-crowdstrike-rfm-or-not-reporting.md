---
id: CP04
name: CrowdStrike sensor stuck in Reduced Functionality Mode, or in RFM and no longer reporting
category: controlplane
status: todo
severity: high
language: esql
index: logs-crowdstrike.fdr-*
mitre: [T1562.001, T1562.008]
data_source: CrowdStrike FDR (OsVersionInfo, SensorMetadataUpdate, SensorHeartbeat)
suppression:
  fields: [host.id]
  duration: 24h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
Reduced Functionality Mode (RFM) is when the Falcon sensor loads but runs with protection and visibility cut back, usually after a kernel or OS update it does not yet support. A host in RFM looks online but is lightly defended. Most RFM is transient and clears once the update completes, so this rule only alerts on hosts that are still in RFM after a grace period.

The RFM state comes from the FDR stream. `OsVersionInfo` and `SensorMetadataUpdate` both carry `RFMState`, which the Elastic integration keeps as `crowdstrike.RFMState`. `SensorHeartbeat` does not carry it, so heartbeats are used only to tell whether the sensor is still alive after entering RFM.

Status is computed per sensor:
- **recovered**: a later event reported `RFMState` 0. Dropped by the rule.
- **rfm_sensor_alive**: still in RFM and heartbeated within the last 60 minutes. Online but lightly protected.
- **rfm_stale_or_offline**: in RFM and no heartbeat in the last 60 minutes. The host is off or the sensor stopped.

Heartbeat freshness is measured against the current time, not against the last RFM report. If RFM reports repeat while a host stays in RFM, comparing to the last report would mislabel live hosts as offline. The 60-minute window allows for FDR delivery lag; keep it above the lag you normally see.

## Query
Run hourly with a 24-hour lookback.
```esql
FROM logs-crowdstrike.fdr-*
| WHERE event.action IN ("SensorMetadataUpdate", "OsVersionInfo", "SensorHeartbeat")
| EVAL rfm_ts = CASE(crowdstrike.RFMState == "1", @timestamp, NULL),
       ok_ts = CASE(crowdstrike.RFMState == "0", @timestamp, NULL),
       hb_ts = CASE(event.action == "SensorHeartbeat", @timestamp, NULL)
| STATS hostnames = VALUES(host.name),
        rfm_events = COUNT(rfm_ts),
        first_rfm = MIN(rfm_ts),
        last_rfm = MAX(rfm_ts),
        last_normal = MAX(ok_ts),
        last_heartbeat = MAX(hb_ts)
    BY host.id
| WHERE rfm_events > 0
// hostname exclusions go after STATS: SensorMetadataUpdate may lack a hostname,
// and filtering on a missing field before STATS would silently drop those events
| EVAL names = TO_LOWER(COALESCE(MV_CONCAT(hostnames, ","), ""))
| WHERE NOT (names LIKE "*.ap-southeast-*.compute.internal*")      // every ap-southeast region
| EVAL status = CASE(
    last_normal IS NOT NULL AND last_normal > last_rfm, "recovered",
    last_heartbeat IS NOT NULL AND DATE_DIFF("minute", last_heartbeat, NOW()) <= 60, "rfm_sensor_alive",
    "rfm_stale_or_offline"),
       rfm_age_minutes = DATE_DIFF("minute", first_rfm, NOW()),
       mins_since_heartbeat = DATE_DIFF("minute", last_heartbeat, NOW())
// grace period: let OS and kernel updates finish before alerting
| WHERE status != "recovered" AND rfm_age_minutes >= 120
| KEEP host.id, hostnames, status, first_rfm, last_rfm, last_normal, last_heartbeat, rfm_age_minutes, mins_since_heartbeat
```
`host.id` is the sensor ID (`aid`), which survives renames and hostname reuse. Adjust the grace period to your patch cycle. The age is measured from the first RFM report in the lookback.

## Falcon LogScale version
The same detection written for Falcon Event Search or Next-Gen SIEM, if you run it in Falcon instead of Elastic.
```
#event_simpleName=/^(SensorMetadataUpdate|OsVersionInfo|SensorHeartbeat)$/
| case {
    #event_simpleName=SensorHeartbeat | hb_ts := @timestamp ;
    RFMState="1" | rfm_ts := @timestamp ;
    RFMState="0" | ok_ts := @timestamp ;
    * }
| groupBy([aid], function=[
    collect([ComputerName]),
    count(rfm_ts, as=RFMEvents),
    min(rfm_ts, as=FirstRFM),
    max(rfm_ts, as=LastRFM),
    max(ok_ts, as=LastNormal),
    max(hb_ts, as=LastHeartbeat)
  ], limit=max)
| RFMEvents > 0
| ComputerName!=/\.ap-southeast-\d+\.compute\.internal$/i
| case {
    test(LastNormal > LastRFM) | Status := "recovered" ;
    test(now() - LastHeartbeat <= 3600000) | Status := "rfm_sensor_alive" ;
    * | Status := "rfm_stale_or_offline" }
| Status != "recovered"
| test(now() - FirstRFM > 7200000)
| FirstRFM := formatTime(format="%F %T", field=FirstRFM, timezone="Australia/Sydney")
| LastRFM := formatTime(format="%F %T", field=LastRFM, timezone="Australia/Sydney")
| LastNormal := formatTime(format="%F %T", field=LastNormal, timezone="Australia/Sydney")
| LastHeartbeat := formatTime(format="%F %T", field=LastHeartbeat, timezone="Australia/Sydney")
```
Notes for the LogScale version:
- `case` takes the first matching branch, so the heartbeat branch comes first. Otherwise a heartbeat carrying `RFMState` would never be counted as a heartbeat.
- `ComputerName!=ap-southeast-2.compute.internal` is an exact match and excludes nothing; the regex above matches the EC2 hostname suffix.
- `OsVersionInfo` alone is emitted rarely, so a first-seen equal to last-seen means one event, not a short RFM window. That is why the recovery and heartbeat checks are needed.
- To confirm recovery is reported, check one host that left RFM: `aid=<aid> RFMState=* | table([@timestamp, #event_simpleName, RFMState])` should show a `SensorMetadataUpdate` with `RFMState` 0.

## Suppression
Suppress by `host.id` for 24h. Alerts missing a key field are not suppressed. RFM persists until the host is fixed, so one alert per sensor per day is enough.

## Known false positives / exclusions
- A host that left RFM without sending a new `OsVersionInfo` or `SensorMetadataUpdate` stays flagged. Confirm with one host's timeline that recovery produces a `SensorMetadataUpdate` with `RFMState` 0; if it does, the recovered status is reliable.
- The EC2 exclusions hide real protection gaps. Consider routing cloud instances to the cloud team instead of dropping them.
- Heartbeat volume makes this query heavy. Keep the lookback at 24 hours or less.

## Triage
- **rfm_sensor_alive:** identify the OS or kernel build that triggered RFM and move the host to a sensor version that supports it. Until then, treat the host as lightly protected and lean on the non-endpoint rules.
- **rfm_stale_or_offline:** check whether the machine is up elsewhere (recent AD logons, DHCP). If it is, investigate a possible sensor tamper (CS05, W05) and restore coverage.

## Test
Validate against a host the Falcon console shows in RFM, or move a lab host to an unsupported kernel.
