---
id: W05
name: Defender or security service stopped, Defender engine wiped, EDR-killer tooling, or safe boot configured
category: endpoint-windows
status: todo
severity: critical
language: esql
index: logs-yourorg-crowdstrike-data-default*
mitre: [T1685, T1068]
data_source: CrowdStrike FDR ProcessRollup2
suppression:
  fields: [host.id]
  duration: 1h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
Ransomware operators in 2026 disable EDR before encryption, usually through BYOVD EDR killers. The process-level precursors this rule keeps (stopping or deleting the Defender services, wiping the Defender engine with `MpCmdRun`, setting safe boot so the next boot runs without security drivers, running a known killer) are unambiguous. Pair with CS01 (driver loads) for the kernel side.

Two neighbouring signals are owned elsewhere, so they are not repeated here:
- **Defender settings changes** (`Set-MpPreference` disables, `Add-MpPreference` exclusions, the `DisableAntiSpyware` registry value) are CP06. It reads Defender's own event 5007, which records the outcome however the change was made, and needs the **Windows Defender** stream turned on in the Elastic Windows integration.
- **Falcon tamper** (uninstall with `CsUninstallTool` or `msiexec /x`, sensor stopped or tampered with) is CS05, which uses the sensor's own uninstall and tamper events.

Service creation with `sc create ... type= kernel` is not matched here either: WE08 sees every new service from user-writable paths (7045/4697), and CS01 sees the driver load.

## Query
```esql
FROM logs-yourorg-crowdstrike-data-default* METADATA _id, _index, _version
| WHERE event.action == "processrollup2" AND host.os.type == "windows"
| EVAL pname = TO_LOWER(process.name), cmd = TO_LOWER(process.command_line)
| WHERE
  // -RemoveDefinitions -DynamicSignatures is a Microsoft troubleshooting step; -All wipes the engine
     (cmd LIKE "*mpcmdrun*" AND ((cmd LIKE "*-removedefinitions*" AND cmd LIKE "*-all*") OR cmd LIKE "*-disableservice*"))
  OR (pname IN ("sc.exe", "net.exe", "net1.exe") AND (cmd LIKE "*stop*" OR cmd LIKE "*delete*" OR cmd LIKE "*config*")
      AND (cmd LIKE "*windefend*" OR cmd LIKE "*wdnissvc*" OR cmd LIKE "* sense*"))
  OR (pname == "bcdedit.exe" AND cmd LIKE "*/set*safeboot*")
| KEEP @timestamp, host.id, host.name, user.name, process.parent.name, pname, process.command_line, process.hash.sha256, _id, _version, _index
```

**CrowdStrike (Falcon LogScale / Advanced Event Search)**
```logscale
#event_simpleName=/^(ProcessRollup2|SyntheticProcessRollup2)$/ event_platform=Win
| case {
    // -RemoveDefinitions -DynamicSignatures is a Microsoft troubleshooting step; -All wipes the engine
    CommandLine=/mpcmdrun/i CommandLine=/-removedefinitions/i CommandLine=/-all/i;
    CommandLine=/mpcmdrun/i CommandLine=/-disableservice/i;
    FileName=/^(sc|net|net1)\.exe$/i CommandLine=/stop|delete|config/i CommandLine=/windefend|wdnissvc| sense/i;
    FileName=/^bcdedit\.exe$/i CommandLine=/\/set.*safeboot/i;
  }
| select([@timestamp, aid, ComputerName, UserName, ParentBaseFileName, FileName, CommandLine, SHA256HashData])
```
Maintain a value list of EDR-killer tool hashes from your threat intel feed and add `process.hash.sha256 IN (...)` as a further branch; names change too often to hard-code.

## Suppression
Suppress by `host.id` for 1h. Alerts missing a key field are not suppressed. Tamper scripts issue many commands in seconds. One alert per host is the triage unit, and other hosts still alert. `host.id` is the Falcon agent ID and is always present; `host.name` is filled only when the integration's host metadata enrichment is on.

## Known false positives / exclusions
- Build or decommission scripts that stop or reconfigure `WinDefend` explicitly. Exclude them by exact command line, never by parent alone: attackers who own SCCM or Intune push exactly this.
- Helpdesk booting a machine into safe mode for repair. Ticket-gated. Removing safe boot (`/deletevalue`) no longer matches.

## Triage
- Isolate immediately. This is the last step before encryption. Check for shadow copy deletion (W06) and lateral movement (W08) on the same host in the previous hour.
- Check the same host for the neighbouring signals: Defender settings weakened (CP06, needs the Windows Defender stream), Falcon uninstalled or tampered with (CS05), and a vulnerable driver loaded (CS01).

## Test
Run `sc stop WinDefend` or `bcdedit /set {current} safeboot minimal` (then `bcdedit /deletevalue {current} safeboot`) on a lab host. Tamper protection refuses the service stop; the rule still fires on the command.
