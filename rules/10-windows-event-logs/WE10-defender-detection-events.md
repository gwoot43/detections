---
id: WE10
name: Microsoft Defender AV detection, tamper, or protection disabled (event log)
category: windows-events
status: todo
severity: high
language: esql
index: logs-windows.defender-*
mitre: [T1562.001, T1059, T1204]
data_source: Windows Defender operational log events 1116/1117 (detection), 5001/5010/5012 (protection off), 1006/1015 (tamper)
---
## Why this is high fidelity
Where CrowdStrike is the primary EDR, Defender still runs and its operational log is a useful second opinion. A malware detection (1116/1117) is inherently high fidelity. Real-time protection or the antivirus being turned off (5001/5010/5012) and tamper-protection alerts (1006/1015) are defense impairment that should never happen silently on a managed host.

## Query
```esql
FROM logs-windows.defender-* METADATA _id, _index, _version
| WHERE event.code IN ("1116", "1117", "1006", "1007", "1015", "5001", "5010", "5012", "5013")
| EVAL threat = TO_LOWER(TO_STRING(COALESCE(winlog.event_data.ThreatName, ""))),
       action = TO_LOWER(TO_STRING(COALESCE(winlog.event_data.Action_Name, winlog.event_data.Action, "")))
| KEEP @timestamp, host.name, user.name, event.code, threat, action, winlog.event_data.Path, winlog.event_data.ProcessName, message
```
This needs the Defender operational channel shipped by the Elastic Windows integration. If Defender is in passive mode behind Falcon, 1116/1117 still fire for its scans and are worth ingesting.

## Known false positives / exclusions
- Detections on quarantined test files (EICAR) during validation. The protection-off events during a controlled Defender uninstall on decommissioned hosts; exclude by the decommission list.

## Triage
- A 1116 detection: confirm Falcon also saw it (CS04) and check the same host for the wider chain (W02/W03/W04). Protection turned off outside a change: treat as W05 handling and isolate.

## Test
Drop an EICAR file on a lab host and confirm 1116/1117 ship to Elastic.
