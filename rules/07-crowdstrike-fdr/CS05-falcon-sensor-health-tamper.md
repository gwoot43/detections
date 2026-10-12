---
id: CS05
name: Falcon sensor uninstalled, stopped, or stopped reporting
category: crowdstrike-fdr
status: todo
severity: critical
language: esql
index: logs-crowdstrike.fdr-*
mitre: [T1685, T1070]
data_source: CrowdStrike FDR sensor uninstall and tamper events, ProcessRollup2
suppression:
  fields: [host.id]
  duration: 24h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
An endpoint whose sensor is removed or silenced is an endpoint an attacker wants dark. Two signals: explicit uninstall/stop events, and a host that was reporting and then goes silent while other signals suggest it is still up. Blind spots are as important as alerts.

## Query (explicit tamper)
```esql
FROM logs-crowdstrike.fdr-* METADATA _id, _index, _version
| EVAL cmd = TO_LOWER(COALESCE(process.command_line, "")), pname = TO_LOWER(COALESCE(process.name, "")),
       tamper_src = TO_LOWER(COALESCE(crowdstrike.SourceImageFileName, ""))
// SensorHeartbeat and AgentConnect are routine status events and are not used.
// systemd signals the Linux sensor on every shutdown and service restart, which Falcon records as SensorTampering.
| WHERE event.action == "AcUninstallConfirmation"
   OR event.action IN ("FalconHostFileTamperingInfo", "FalconHostRegTamperingInfo")
   OR (event.action == "SensorTampering" AND tamper_src NOT IN ("/usr/lib/systemd/systemd", "/lib/systemd/systemd"))
   OR (event.action == "ProcessRollup2" AND (cmd LIKE "*csuninstalltool*" OR (pname == "msiexec.exe" AND cmd LIKE "*falcon*" AND cmd LIKE "*/x*")))
| KEEP @timestamp, host.id, host.name, user.name, event.action, process.name, process.command_line, crowdstrike.SourceImageFileName, crowdstrike.TamperingAction, _id, _version, _index
```
Silent-host companion (run daily): compare hosts seen in the last 24h against the asset inventory / AD computer list, and alert on managed hosts that stopped sending FDR while still appearing active in AD authentication (event 4624) or DHCP.

## Suppression
Suppress by `host.id` for 24h. Alerts missing a key field are not suppressed. Sensor state events repeat until the host is fixed. `host.id` is the Falcon agent ID and is always present; `host.name` is filled only when the integration's host metadata enrichment is on.

## Known false positives / exclusions
- Planned decommissioning and reimaging. Cross-check against the retirement list.
- Laptops that are simply offline. The silent-host rule must require another live signal (recent AD logon, DHCP lease) before alerting.

## Triage
- A sensor removed outside a decommission ticket is treated as an intrusion on that host. Investigate via other telemetry (AD, network, cloud) since endpoint visibility is gone.

## Test
Uninstall the sensor on a lab host using the maintenance token.
