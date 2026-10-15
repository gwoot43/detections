---
id: L12
name: SSH fan-out from one host to many new internal hosts
category: endpoint-linux
status: todo
severity: high
language: esql
index: logs-crowdstrike.fdr-*
mitre: [T1021.004]
data_source: CrowdStrike FDR NetworkConnectIP4 (Linux)
suppression:
  fields: [host.id]
  duration: 1h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
Hands-on-keyboard attackers and worms move by SSH to many hosts in a short time. A single host opening SSH connections to a large number of distinct internal destinations in a few minutes is lateral movement. Normal admin and automation touch a stable, small set of hosts, so the distinct-destination count is what separates the two.

The count comes from outbound connections to port 22, not from `ssh` command lines. Automation such as Ansible runs many different `ssh` commands against the same host, so distinct command lines overstate destinations badly.

## Query
Run every 5 minutes with a 15-minute lookback.
```esql
FROM logs-crowdstrike.fdr-*
| WHERE event.action == "NetworkConnectIP4" AND host.os.type == "linux"
  AND destination.port == 22
  AND CIDR_MATCH(destination.ip, "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
// exclude Ansible control nodes, jump hosts and backup orchestrators here by host.id or host.name
| STATS dests = COUNT_DISTINCT(destination.ip), sample = VALUES(destination.ip), procs = VALUES(process.name), conns = COUNT(*),
        host.name = VALUES(host.name)
    BY host.id, BUCKET(@timestamp, 10 minutes)
| WHERE dests >= 15
```

**CrowdStrike (Falcon LogScale / Advanced Event Search)**
```logscale
#event_simpleName=NetworkConnectIP4 event_platform=Lin RemotePort=22
| cidr(RemoteAddressIP4, subnet=["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"])
// exclude Ansible control nodes, jump hosts and backup orchestrators here by aid or ComputerName
| bucket_start := @timestamp - (@timestamp % 600000)
| groupBy([aid, bucket_start], function=[count(RemoteAddressIP4, distinct=true, as=dests), count(as=conns),
                                       collect([RemoteAddressIP4, ContextBaseFileName, ComputerName])], limit=max)
| test(dests >= 15)
| bucket_start := formatTime(format="%F %T", field=bucket_start, timezone="Australia/Sydney")
```

## Suppression
Suppress by `host.id` for 1h. Alerts missing a key field are not suppressed. Aggregating rule; suppression stops overlapping lookbacks from re-alerting on the same burst. `host.id` is the Falcon agent ID and is always present; connection events carry no user, so the account is found in triage.

## Known false positives / exclusions
- Configuration management and monitoring that SSH to many hosts (Ansible control nodes, backup orchestrators, `check_ssh` pollers). Exclude those source hosts inline; they are the main source of noise here.

## Triage
- Identify the destinations and whether the source host should reach them. Find the account from the `ssh` ProcessRollup2 events on the source in the same window. Check the source for initial access (L03) and credential access (L05), and the destinations for new logins.

## Test
From a lab host, SSH to 15 or more lab hosts within ten minutes.
