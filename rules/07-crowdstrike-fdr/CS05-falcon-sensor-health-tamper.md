---
id: CS05
name: Falcon sensor uninstalled, stopped, or stopped reporting
category: crowdstrike-fdr
status: todo
severity: critical
language: esql
index: logs-*
mitre: [T1562.001, T1070]
data_source: CrowdStrike sensor health events and FDR gap analysis
suppression:
  fields: [host.name]
  duration: 24h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
An endpoint whose sensor is removed or silenced is an endpoint an attacker wants dark. Two signals: explicit uninstall/stop events, and a host that was reporting and then goes silent while other signals suggest it is still up. Blind spots are as important as alerts.

## Query (explicit tamper; see also W05)
```esql
FROM logs-crowdstrike.fdr-* METADATA _id, _index, _version
| WHERE event.action IN ("SensorHeartbeat", "UninstallToken", "AgentConnect", "AgentDisconnect", "InstallTokenRevoked")
    OR (event.action == "ProcessRollup2" AND (TO_LOWER(process.command_line) LIKE "*csuninstalltool*" OR (TO_LOWER(process.name) == "msiexec.exe" AND TO_LOWER(process.command_line) LIKE "*falcon*" AND TO_LOWER(process.command_line) LIKE "*/x*")))
| KEEP @timestamp, host.name, user.name, event.action, process.name, process.command_line
```
Silent-host companion (run daily): compare hosts seen in the last 24h against the asset inventory / AD computer list, and alert on managed hosts that stopped sending FDR while still appearing active in AD authentication (event 4624) or DHCP.

## Suppression
Suppress by `host.name` for 24h. Alerts missing a key field are not suppressed. Sensor state events repeat until the host is fixed.

## Known false positives / exclusions
- Planned decommissioning and reimaging. Cross-check against the retirement list.
- Laptops that are simply offline. The silent-host rule must require another live signal (recent AD logon, DHCP lease) before alerting.

## Triage
- A sensor removed outside a decommission ticket is treated as an intrusion on that host. Investigate via other telemetry (AD, network, cloud) since endpoint visibility is gone.

## Test
Uninstall the sensor on a lab host using the maintenance token.
