---
id: L12
name: SSH fan-out from one host to many new internal hosts
category: endpoint-linux
status: todo
severity: high
language: esql
index: logs-crowdstrike.fdr-*
mitre: [T1021.004]
data_source: CrowdStrike FDR process events (Linux)
suppression:
  fields: [host.name, user.name]
  duration: 1h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
Hands-on-keyboard attackers and worms move by SSH to many hosts in a short time. A single host launching outbound `ssh` to a large number of distinct destinations in a few minutes is lateral movement. Normal admin and automation touch a stable, small set of hosts, so the distinct-destination count is what separates the two.

## Query
```esql
FROM logs-crowdstrike.fdr-*
| WHERE event.action == "ProcessRollup2" AND host.os.type == "linux"
  AND TO_LOWER(process.name) == "ssh"
| EVAL cmd = TO_LOWER(TO_STRING(process.command_line))
// pull the destination host token; refine to your ssh invocation style if needed
| STATS dests = COUNT_DISTINCT(cmd), sample = VALUES(cmd), n = COUNT(*)
    BY host.name, user.name, BUCKET(@timestamp, 10 minutes)
| WHERE dests >= 15
```
Counting distinct command lines approximates distinct destinations. If you can parse the target host into a field in the ingest pipeline, count that instead for accuracy.

## Suppression
Suppress by `host.name`, `user.name` for 1h. Alerts missing a key field are not suppressed. Aggregating rule; suppression stops overlapping lookbacks from re-alerting on the same burst.

## Known false positives / exclusions
- Configuration management and monitoring that SSH to many hosts (Ansible control nodes, backup orchestrators). Exclude those hosts and service accounts; they are the main source of noise here.

## Triage
- Identify the destinations and whether the source host and account should reach them. Check the source for initial access (L03) and credential access (L05), and the destinations for new logins.

## Test
From a lab host, SSH to 15 or more lab hosts within ten minutes.
