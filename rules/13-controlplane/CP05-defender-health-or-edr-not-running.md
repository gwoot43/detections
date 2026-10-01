---
id: CP05
name: Microsoft Defender health degraded or the MDE sensor not running
category: controlplane
status: todo
severity: high
language: esql
index: logs-windows.defender-*, logs-system.system-*
mitre: [T1562.001, T1562.008]
data_source: Windows Defender operational log and System service-control events
suppression:
  fields: [host.name, event.code]
  duration: 12h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
Where Defender runs alongside CrowdStrike, its health is a second coverage signal. Signatures or the engine going stale, real-time or behaviour monitoring switching off, tamper protection dropping, or the Defender for Endpoint sensor service (Sense) stopping all mean protection has quietly degraded. These are operational-log and service-control events, distinct from a malware detection (WE10) or a deliberate tamper command (W05).

## Query
```esql
FROM logs-windows.defender-*, logs-system.system-* METADATA _id, _index, _version
| WHERE
    (winlog.channel == "Microsoft-Windows-Windows Defender/Operational"
     AND event.code IN ("5008", "5010", "5012", "5101",      // engine failure, scanning off, AV off, engine outdated
                        "2001", "2003", "2004",               // signature/engine update failed or reverted
                        "1150", "1151", "3002", "5100"))      // endpoint health / real-time protection feature failed
 OR (winlog.channel == "System" AND event.code == "7036"
     AND TO_LOWER(TO_STRING(winlog.event_data.param1)) RLIKE ".*(windefend|sense|wdnissvc).*"
     AND TO_LOWER(TO_STRING(winlog.event_data.param2)) LIKE "*stopped*")
 OR (winlog.channel == "System" AND event.code IN ("7034", "7031")      // service crashed / terminated unexpectedly
     AND TO_LOWER(TO_STRING(winlog.event_data.param1)) RLIKE ".*(windefend|sense|wdnissvc).*")
| KEEP @timestamp, host.name, winlog.channel, event.code, winlog.event_data.param1, winlog.event_data.param2, message
```
The Defender operational channel and the System channel both need to be shipped by the Elastic Windows integration. Confirm the event codes your Defender version emits; the signature-update and health codes vary a little by build.

## Suppression
Suppress by `host.name`, `event.code` for 12h. Alerts missing a key field are not suppressed. A degraded host repeats the event until fixed; a different host or failure still alerts.

## Known false positives / exclusions
- Signature update blips on a host that was briefly offline, which self-correct. If this is noisy, require the condition to persist, or scope the stale-signature branch to hosts that are otherwise online.
- Planned Defender removal on decommissioned machines. Cross-check the retirement list.
- On estates where Defender is intentionally passive behind CrowdStrike, decide which of these codes still matter and trim the list.

## Triage
- The Sense service stopping is the Defender for Endpoint EDR going dark; treat it like CS05 and investigate for tamper (W05). Stale signatures or engine-off is a coverage gap to restore. Correlate with any detection the host raised just before it went quiet.

## Test
Stop the Defender service on a lab host, or let signatures age out, and confirm the events ship.
