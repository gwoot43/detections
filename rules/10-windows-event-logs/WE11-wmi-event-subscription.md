---
id: WE11
name: WMI permanent event subscription with a script or command consumer
category: windows-events
status: todo
severity: high
language: esql
index: logs-windows.*
mitre: [T1546.003]
data_source: Microsoft-Windows-WMI-Activity/Operational event 5861
suppression:
  fields: [host_key]
  duration: 24h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
Event 5861 records a new permanent WMI event binding. Bindings that run a command line or a script are a known persistence method and are rare on managed endpoints. Windows ships a small number of built-in consumers, which are excluded by name.

## Query
```esql
FROM logs-windows.* METADATA _id, _index, _version
| WHERE winlog.channel == "Microsoft-Windows-WMI-Activity/Operational" AND event.code == "5861"
| EVAL msg = TO_LOWER(TO_STRING(message)),
       host_key = TO_LOWER(MV_FIRST(SPLIT(winlog.computer_name, ".")))   // with event forwarding, host.name is the collector
| WHERE msg LIKE "*commandlineeventconsumer*" OR msg LIKE "*activescripteventconsumer*"
| WHERE NOT (msg LIKE "*bvtconsumer*")
| KEEP @timestamp, host_key, winlog.computer_name, winlog.channel, message
```
This channel is not collected by default. Collect it with a custom Windows event log input in the agent policy (or forward it with WEF), and check which data stream it lands in. If that is not under `logs-windows.*`, change `FROM` and `index:` together; a wildcard that matches nothing is not an error, so the rule would silently never fire.

## Suppression
Suppress by `host_key` for 24h. Alerts missing a key field are not suppressed. The same binding can be logged again on restart.

## Known false positives / exclusions
- Hardware vendor and management agents that register their own consumers. Baseline for two weeks and exclude by consumer name.

## Triage
- Read the consumer's command or script in the message. Remove the binding, find what created it, and check the host for other persistence (CS02, CS07).

## Test
Atomic Red Team T1546.003 on a lab host.
