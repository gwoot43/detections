---
id: CP04
name: CrowdStrike sensor in Reduced Functionality Mode or no longer reporting
category: controlplane
status: todo
severity: high
language: esql
index: logs-crowdstrike.*
mitre: [T1562.001, T1562.008]
data_source: CrowdStrike Falcon sensor health / host status (and FDR gap analysis)
suppression:
  fields: [host.name]
  duration: 24h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
Reduced Functionality Mode (RFM) is when the Falcon sensor loads but runs with protection and visibility cut back, usually after a kernel or OS update it does not yet support. A host in RFM looks online but is lightly defended, and attackers exploit that window. A sensor that stops reporting altogether is a blind spot. Both are control-plane failures worth an alert, not just a dashboard tile.

## Data source note
RFM state is not reliably in the FDR event firehose. The dependable sources are the Falcon host-status data (the `reduced_functionality_mode` field on a device) and the sensor-health feed, pulled via the Falcon API or secondary Data Replicator feeds into Elastic. Confirm you ingest one of these before relying on branch A. Branch B needs only the FDR process stream you already have.

## Query A: RFM or degraded sensor state (needs host-status / sensor-health ingestion)
```esql
FROM logs-crowdstrike.* METADATA _id, _index, _version
| EVAL rfm = TO_LOWER(TO_STRING(COALESCE(crowdstrike.host.reduced_functionality_mode,
                                         crowdstrike.event.ReducedFunctionalityMode, ""))),
       state = TO_LOWER(TO_STRING(COALESCE(crowdstrike.host.status, crowdstrike.event.SensorState, "")))
| WHERE rfm IN ("yes", "true", "1") OR state RLIKE ".*(rfm|reduced|degraded|error).*"
| KEEP @timestamp, host.name, rfm, state, crowdstrike.host.os_version, crowdstrike.host.sensor_version
```

## Query B: host stopped reporting to Falcon while still alive elsewhere
Run daily. This reuses only FDR. It flags a host that sent process telemetry recently, then went quiet for hours, which pairs with CS05 (sensor uninstalled or stopped).
```esql
FROM logs-crowdstrike.fdr-*
| WHERE event.action == "ProcessRollup2"
| STATS last_seen = MAX(@timestamp), events = COUNT(*) BY host.name
| WHERE last_seen < NOW() - 12 hours
| KEEP host.name, last_seen, events
```
Cross-check the quiet hosts against a live signal the attacker cannot mute, such as recent AD authentication (event 4624) or a DHCP lease, so you alert only on hosts that are up but dark. Without that cross-check this also lists powered-off laptops.

## Suppression
Suppress by `host.name` for 24h. Alerts missing a key field are not suppressed. RFM persists until the host is fixed, so one alert per host per day is enough.

## Known false positives / exclusions
- RFM right after a mass OS or kernel rollout is expected but still a real protection gap; treat it as prioritise-the-patch, not dismiss.
- Branch B lists legitimately offline machines unless you require a second live signal. Decommissioned hosts: cross-check the retirement list.

## Triage
- RFM: identify the OS or kernel build that triggered it and update the sensor to a supporting version. Until fixed, treat the host as lightly protected and watch it with the non-endpoint rules.
- Not reporting while alive: investigate as a possible sensor tamper (CS05, W05) and restore coverage.

## Test
In a lab, move a host to an unsupported kernel to induce RFM, or confirm branch A fires against a host the Falcon console shows in RFM.
