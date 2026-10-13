---
id: W05
name: Security protection turned off from the command line (Defender service or engine, firewall, safe boot)
category: endpoint-windows
status: todo
severity: critical
language: esql
index: logs-crowdstrike.fdr-*
mitre: [T1685, T1068]
data_source: CrowdStrike FDR ProcessRollup2
suppression:
  fields: [host.id]
  duration: 1h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
Ransomware operators turn protection off before they encrypt. From the command line that means one of four things, and the command line says which:
- **Defender's services** (`WinDefend`, `WdNisSvc`, `Sense`) stopped, deleted or set to disabled, by `sc`, `net` or PowerShell.
- **Defender's engine wiped** with `MpCmdRun -RemoveDefinitions -All`, or the service disabled with `MpCmdRun -DisableService`.
- **The Windows firewall switched off** with `netsh advfirewall ... state off` or `Set-NetFirewallProfile -Enabled False`.
- **Safe boot set**, so the next boot runs without security drivers.

The rule matches the service names and actions, not the tools, so it doesn't matter which program issues the command.

Neighbouring signals live elsewhere: Defender settings changes are CP06 (Defender's own event 5007), Falcon uninstall and tamper are CS05, and vulnerable driver loads are CS01.

## Query
```esql
FROM logs-crowdstrike.fdr-* METADATA _id, _index, _version
| WHERE event.action == "ProcessRollup2" AND host.os.type == "windows"
| EVAL cmd = TO_LOWER(process.command_line)
| WHERE ((cmd LIKE "*windefend*" OR cmd LIKE "*wdnissvc*" OR cmd LIKE "* sense*")
         AND (cmd LIKE "*stop*" OR cmd LIKE "*delete*" OR cmd LIKE "*disabled*"))
     OR (cmd LIKE "*-removedefinitions*" AND cmd LIKE "*-all*")
     OR cmd LIKE "*mpcmdrun*-disableservice*"
     OR cmd LIKE "*advfirewall*state off*" OR cmd LIKE "*set-netfirewallprofile*enabled false*"
     OR cmd LIKE "*/set*safeboot*"
| KEEP @timestamp, host.id, host.name, user.name, process.parent.name, process.name, process.command_line,
       process.hash.sha256, _id, _version, _index
```

This rule doesn't use rarity. Protection switched off on many hosts at once is a ransomware rollout, not a sign that it's normal.

## Suppression
Suppress by `host.id` for 1h. Alerts missing a key field are not suppressed. Tamper scripts issue many commands in seconds; one alert per host is the triage unit. `host.id` is the Falcon agent ID and is always present.

## Known false positives / exclusions
- Build or decommission scripts that stop Defender or the firewall on purpose. Exclude them by exact command line, never by parent: an attacker who owns SCCM or Intune pushes exactly this.
- Helpdesk setting safe mode for a repair. Ticket-gated. Removing safe boot (`/deletevalue`) doesn't match.
- `MpCmdRun -RemoveDefinitions -DynamicSignatures` is a Microsoft troubleshooting step and doesn't match; only `-All` does.

## Triage
- Isolate immediately. This is usually the last step before encryption. Check the same host for shadow copy deletion (W06) and remote execution (W08) in the hour before.

## Test
On a lab host, run `sc stop WinDefend` (tamper protection refuses it; the rule still fires), then `netsh advfirewall set allprofiles state off` and turn it back on.
