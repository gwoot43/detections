---
id: CS05
name: Falcon sensor uninstalled, stopped, or stopped reporting
category: crowdstrike-fdr
status: todo
language: esql
index: logs-yourorg-crowdstrike-data-default*
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
FROM logs-yourorg-crowdstrike-data-default* METADATA _id, _index, _version
| EVAL cmd = TO_LOWER(COALESCE(process.command_line, "")), pname = TO_LOWER(COALESCE(process.name, "")),
       tamper_src = TO_LOWER(COALESCE(data.SourceImageFileName, ""))
// SensorHeartbeat and AgentConnect are routine status events and are not used.
// systemd signals the Linux sensor on every shutdown and service restart, which Falcon records as SensorTampering.
| WHERE event.action == "acuninstallconfirmation"
   OR event.action IN ("falconhostfiletamperinginfo", "falconhostregtamperinginfo")
   OR (event.action == "sensortampering" AND tamper_src NOT IN ("/usr/lib/systemd/systemd", "/lib/systemd/systemd"))
   OR (event.action == "processrollup2" AND (cmd LIKE "*csuninstalltool*" OR (pname == "msiexec.exe" AND cmd LIKE "*falcon*" AND cmd LIKE "*/x*")))
| KEEP @timestamp, host.id, host.name, user.name, event.action, process.name, process.command_line, data.SourceImageFileName, data.TamperingAction, _id, _version, _index
```

**CrowdStrike (Falcon LogScale / Advanced Event Search)**
```logscale
#event_simpleName=/^(AcUninstallConfirmation|FalconHostFileTamperingInfo|FalconHostRegTamperingInfo|SensorTampering|ProcessRollup2|SyntheticProcessRollup2)$/
| case {
    #event_simpleName=AcUninstallConfirmation
      | finding := "sensor uninstall confirmed";
    #event_simpleName=/^FalconHost(File|Reg)TamperingInfo$/
      | finding := "sensor file or registry tampering";
    #event_simpleName=SensorTampering !in(field="SourceImageFileName", ignoreCase=true, values=["/usr/lib/systemd/systemd", "/lib/systemd/systemd"])
      | finding := "sensor tampering";
    #event_simpleName=/ProcessRollup2$/ CommandLine=/csuninstalltool/i
      | finding := "CsUninstallTool run";
    #event_simpleName=/ProcessRollup2$/ FileName=/^msiexec\.exe$/i CommandLine=/falcon/i CommandLine=/\/x/i
      | finding := "msiexec uninstall of Falcon";
  }
| select([@timestamp, aid, ComputerName, UserName, #event_simpleName, finding, FileName, CommandLine, SourceImageFileName, TamperingAction])
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
