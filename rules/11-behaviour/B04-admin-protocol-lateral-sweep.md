---
id: B04
name: Remote-admin protocol sweep (lateral movement fan-out)
category: behaviour
status: todo
severity: high
language: esql
index: logs-crowdstrike.fdr-*
mitre: [T1021, T1570]
data_source: CrowdStrike FDR network connection events
suppression:
  fields: [host.name, process.name]
  duration: 2h
  missing_fields: do_not_suppress
---
## Why this is behavioural and high fidelity
When an operator moves laterally at scale with CrackMapExec, NetExec, Impacket or a PsExec loop, one host reaches many others on the remote-execution ports (SMB, WinRM, RDP, WMI/DCOM) in a short time. This detects that fan-out by counting distinct internal destinations on those ports from one process, independent of the tool. A workstation does not WinRM or RDP to dozens of machines in ten minutes.

## Query
Run every 10 minutes with a 15-minute lookback.
```esql
FROM logs-crowdstrike.fdr-*
| WHERE event.category == "network" AND network.direction IN ("egress", "outbound")
  AND host.os.type == "windows" AND destination.ip IS NOT NULL
  AND destination.port IN (5985, 5986, 3389, 135, 445)
  AND CIDR_MATCH(destination.ip, "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
| STATS targets = COUNT_DISTINCT(destination.ip),
        winrm = COUNT_DISTINCT(CASE(destination.port IN (5985, 5986), destination.ip, NULL)),
        rdp = COUNT_DISTINCT(CASE(destination.port == 3389, destination.ip, NULL)),
        conns = COUNT(*)
    BY host.name, process.name, user.name, BUCKET(@timestamp, 10 minutes)
| WHERE targets >= 15
```
Keep the source scoped to workstations if your servers legitimately fan out; add `AND host.name LIKE "ws-*"` or exclude server names inline.

## Suppression
Suppress by `host.name`, `process.name` for 2h. Alerts missing a key field are not suppressed. Aggregating rule. A sweep spans buckets; a new source still alerts.

## Known false positives / exclusions
- Admin jump hosts and management servers that administer many machines. Exclude them inline by host name.
- Patch and configuration tools using WinRM or WMI broadly. Exclude their process and host.

## Triage
- Find the process and account. Map to the destinations and check those for new services or shells (W08). Lateral sweep plus credential access on the source (B08) is hands-on-keyboard movement.

## Test
Run a CrackMapExec or NetExec sweep across a lab subnet from a lab host.
