---
id: X03
name: VPN logon anomaly followed by internal attack behaviour
category: correlation
status: todo
severity: high
language: esql
index: logs-*
mitre: [T1133, T1021, T1078]
data_source: F5 APM (N01/N02) + AD auth (I05/I06) + endpoint (W08/W09) joined on user
suppression:
  fields: [usr, host.name]
  duration: 4h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
Because APM is VPN-only, a VPN session is the entry point to the internal network. An anomalous VPN logon (impossible travel, or brute-force-then-success) followed by internal lateral movement or AD recon from the same user is a remote intrusion progressing. The VPN anomaly gives you the earliest possible catch.

## Query (pattern)
```esql
FROM logs-crowdstrike.fdr-* METADATA _id, _index, _version
| WHERE @timestamp > NOW() - 2 hours AND event.action == "ProcessRollup2"
| EVAL usr = TO_LOWER(user.name)
// endpoint side: reuse W08/W09 logic or match their rule tags
| WHERE process.name IN ("psexesvc.exe", "wmic.exe", "nltest.exe", "sharphound.exe") OR TO_LOWER(process.command_line) LIKE "*/node:*"
| LOOKUP JOIN vpn_anomalies_last_4h ON usr
| WHERE vpn_anomaly_at IS NOT NULL AND @timestamp >= vpn_anomaly_at
| KEEP @timestamp, usr, host.name, process.name, process.command_line, vpn_src_country, vpn_anomaly_at
```
Build `vpn_anomalies_last_4h` from N01/N02. Or an indicator-match rule keyed on user.

## Suppression
Suppress by `usr`, `host.name` for 4h. Alerts missing a key field are not suppressed. Correlation rule. It re-matches on every run while the lookback overlaps.

## Known false positives / exclusions
- An admin connecting via VPN from travel and doing legitimate remote administration. Scope the endpoint side to attack tooling and lateral movement, and exclude sanctioned admin accounts on jump hosts.

## Triage
- Terminate the VPN session, isolate the internal host, and treat as an active remote intrusion.

## Test
Connect to the lab VPN from an unusual location, then run a recon command internally as the same user.
