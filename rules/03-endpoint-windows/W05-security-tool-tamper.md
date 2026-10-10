---
id: W05
name: Defender or Falcon tampered with, EDR-killer tooling, or safe boot configured
category: endpoint-windows
status: todo
severity: critical
language: esql
index: logs-crowdstrike.fdr-*
mitre: [T1562.001, T1685, T1068]
data_source: CrowdStrike FDR ProcessRollup2
suppression:
  fields: [host.name]
  duration: 1h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
Ransomware operators in 2026 disable EDR before encryption, usually through BYOVD EDR killers. The process-level precursors (stopping the service, adding exclusions, setting safe boot, running a known killer) are unambiguous. Pair with CS01 (driver loads) for the kernel side.

## Query
```esql
FROM logs-crowdstrike.fdr-* METADATA _id, _index, _version
| WHERE event.action == "ProcessRollup2" AND host.os.type == "windows"
| EVAL pname = TO_LOWER(process.name), cmd = TO_LOWER(process.command_line)
| WHERE
     (cmd LIKE "*set-mppreference*" AND (cmd LIKE "*disable*" OR cmd LIKE "*exclusion*" OR cmd LIKE "*mapsreporting*"))
  OR (cmd LIKE "*add-mppreference*" AND cmd LIKE "*exclusion*")
  // -RemoveDefinitions -DynamicSignatures is a Microsoft troubleshooting step; -All wipes the engine
  OR (cmd LIKE "*mpcmdrun*" AND ((cmd LIKE "*-removedefinitions*" AND cmd LIKE "*-all*") OR cmd LIKE "*-disableservice*"))
  OR (cmd LIKE "*windows defender*" AND cmd LIKE "*disableantispyware*")
  OR (pname IN ("sc.exe", "net.exe", "net1.exe") AND (cmd LIKE "*stop*" OR cmd LIKE "*delete*" OR cmd LIKE "*config*")
      AND (cmd LIKE "*windefend*" OR cmd LIKE "*wdnissvc*" OR cmd LIKE "* sense*" OR cmd LIKE "*csagent*" OR cmd LIKE "*csfalconservice*"))
  OR cmd LIKE "*csuninstalltool*"
  OR (pname == "msiexec.exe" AND cmd LIKE "*/x*" AND cmd LIKE "*falcon*")
  OR (pname == "bcdedit.exe" AND cmd LIKE "*/set*safeboot*")
  OR (pname == "sc.exe" AND cmd LIKE "*create*" AND cmd LIKE "*type=*kernel*" AND (cmd LIKE """*\\temp\\*""" OR cmd LIKE """*\\users\\*""" OR cmd LIKE """*\\programdata\\*"""))
| KEEP @timestamp, host.name, user.name, process.parent.name, pname, process.command_line, process.hash.sha256
```
Maintain a value list of EDR-killer tool hashes from your threat intel feed and add `process.hash.sha256 IN (...)` as a further branch; names change too often to hard-code.

## Suppression
Suppress by `host.name` for 1h. Alerts missing a key field are not suppressed. Tamper scripts issue many commands in seconds. One alert per host is the triage unit, and other hosts still alert.

## Known false positives / exclusions
- Configuration management adding Defender exclusions under the CM agent parent. Exclude by parent and exact exclusion path, never by parent alone: attackers who own SCCM or Intune push exactly this.
- Helpdesk booting a machine into safe mode for repair. Ticket-gated. Removing safe boot (`/deletevalue`) no longer matches.

## Triage
- Isolate immediately. This is the last step before encryption. Check for shadow copy deletion (W06) and lateral movement (W08) on the same host in the previous hour.

## Test
Run the Atomic Red Team Defender tamper test (T1562.001) on a lab host. Tamper protection refuses it; the rule still fires.
