---
id: B01
name: Internal port or host scanning by one process (outbound TCP to many hosts or many ports)
category: behaviour
status: todo
language: esql
index: logs-yourorg-crowdstrike-data-default*
mitre: [T1046, T1018]
data_source: CrowdStrike FDR NetworkConnectIP4
suppression:
  fields: [host.name, process.name]
  duration: 2h
  missing_fields: do_not_suppress
---
## Why this is behavioural and high fidelity
**One question:** is one process on a host scanning the internal network? Whatever runs the scan (nmap's connect scan, an IP scanner, a PowerShell loop, an implant's built-in scanner, a worm), it opens TCP connections to many internal hosts or many ports. The rule counts, per process name and host in 2-hour buckets, how many internal hosts and ports it reached:

| Shape | In one 2-hour bucket | Look-alikes |
|---|---|---|
| Host sweep | 100+ internal hosts on 5+ ports | Monitoring, discovery, event collection and automation servers (excluded) |
| Port scan | 200+ ports | Very few: normal programs use a handful of ports |

- **Anchor:** outbound TCP connections (`ConnectionDirection` 0) to internal addresses on service ports.
- **Corroborating property:** the fan-out, over 2 hours, which is long enough to catch a scan that's paced to stay quiet.
- **Exclusions:** the servers that scan by design, a jump-box process, and a few business applications that fan out (placeholders).

TCP only, by choice: UDP scans and raw-packet scans (nmap `-sS` or `-sU` as admin, masscan) make no TCP connection Falcon records. CS18 catches the known scanners by name.

## Query
Run hourly with a 2-hour lookback.
```esql
FROM logs-yourorg-crowdstrike-data-default*
// 1 GATE: outbound TCP connections to internal addresses (private ranges and 100.64.0.0/10) on service ports. Chatter
// ports (DNS, NTP, RPC endpoint mapper, NetBIOS, SSDP, mDNS, LLMNR) and dynamic RPC (49152 and up) left out. The host
// name is the grouping key, so it must be there.
| WHERE network.transport == "tcp"
  AND event.action == "networkconnectip4"
  AND data.ConnectionDirection == "0"
  AND host.name IS NOT NULL
  // Hosts that scan by design (placeholders). LIKE without a * is an exact match, so the * covers numbered hosts.
  AND NOT host.name LIKE "<network_monitoring_host>*"   // network monitoring
  AND NOT host.name LIKE "<event_collector_host>*"      // Windows Event Collector
  AND NOT host.name LIKE "<gateway_monitoring_host>*"   // gateway monitoring
  AND NOT host.name LIKE "<app_backend_host>*"          // business application back end
  AND NOT host.name LIKE "<dr_monitoring_host>*"        // secondary data centre monitoring
  AND NOT host.name LIKE "<discovery_server_host>*"     // ServiceNow network discovery (MID servers)
  AND NOT host.name LIKE "<automation_host>*"           // Ansible, non-production
  // A MID server on the jump boxes: that host and java.exe only.
  AND NOT (host.name LIKE "<jumpbox_host>*" AND process.name IS NOT NULL AND process.name == "java.exe")
  AND destination.port < 49152
  AND destination.port NOT IN (53, 123, 135, 137, 138, 1900, 5353, 5355)
  // Business applications and agents that fan out (placeholders; Microsoft.Tri.Sensor.exe is the Defender for
  // Identity sensor). A connection with no process name stays in.
  AND (process.name IS NULL OR process.name NOT IN ("<announcement_capture>.exe", "Microsoft.Tri.Sensor.exe",
                                                    "<scheduled_task_service>.exe", "<periodic_task_host>.exe",
                                                    "<scheduled_task_host>.exe"))
  AND CIDR_MATCH(destination.ip, "10.0.0.0/8", "100.64.0.0/10", "172.16.0.0/12", "192.168.0.0/16")
// 2 SHAPE: connections from a process Falcon didn't name are grouped per host as "unknown", so the key is never empty.
| EVAL process.name = COALESCE(process.name, "unknown")
// 3 REDUCE: per 2-hour bucket, process and host: how many internal hosts and ports it reached.
| STATS targets = COUNT_DISTINCT(destination.ip, 100),
        ports = COUNT_DISTINCT(destination.port, 1000),
        first_seen = MIN(@timestamp)
    BY bucket = BUCKET(@timestamp, 120 minutes), process.name, host.name, protocol = network.transport
// 4 DECIDE: a host sweep (100+ hosts on 5+ ports) or a port scan (200+ ports). Thresholds (source: tuned by the team on
// production data, 2-hour buckets); record the date range measured here.
| WHERE (targets >= 100 AND ports >= 5) OR ports >= 200
// 6 OUTPUT
| KEEP bucket, host.name, process.name, protocol, targets, ports, first_seen
| SORT ports DESC
```

**CrowdStrike (Falcon LogScale / Advanced Event Search)**, run hourly over the last 2 hours:
```logscale
#event_simpleName=NetworkConnectIP4
// 1 GATE: outbound TCP (Protocol 6, ConnectionDirection 0) to internal addresses on service ports, chatter ports and
// dynamic RPC left out; the business applications that fan out (placeholders).
| Protocol=6 ConnectionDirection=0 aid=*
| cidr(RemoteAddressIP4, subnet=["10.0.0.0/8", "100.64.0.0/10", "172.16.0.0/12", "192.168.0.0/16"])
| RemotePort < 49152
| !in(field="RemotePort", values=["53", "123", "135", "137", "138", "1900", "5353", "5355"])
| !in(field="ContextBaseFileName", ignoreCase=true, values=["<announcement_capture>.exe", "Microsoft.Tri.Sensor.exe",
                                                          "<scheduled_task_service>.exe", "<periodic_task_host>.exe",
                                                          "<scheduled_task_host>.exe"])
// 2 SHAPE: the 2-hour bucket, and "unknown" for a process Falcon didn't name.
| bucket_raw := @timestamp / 7200000
| bucket := math:floor(bucket_raw)
| default(field=ContextBaseFileName, value="unknown")
// 3 REDUCE: per bucket, process and host.
| groupBy([bucket, aid, ContextBaseFileName], function=[count(RemoteAddressIP4, distinct=true, as=targets),
                                                        count(RemotePort, distinct=true, as=ports), min(@timestamp, as=first_seen)],
          limit=max)
// 4 DECIDE: host sweep or port scan. Thresholds (source: tuned by the team on production data, 2-hour buckets).
// Deliberately no * branch: an event passes if any branch matches.
| case { test(targets >= 100) | test(ports >= 5); test(ports >= 200); }
// 5 ENRICH: host name from the sensor inventory, then the hosts that scan by design and the jump-box pair (placeholders).
| match(file="aid_master_main.csv", field=aid, include=[ComputerName], strict=false)
| NOT ComputerName=/^(<network_monitoring_host>|<event_collector_host>|<gateway_monitoring_host>|<app_backend_host>|<dr_monitoring_host>|<discovery_server_host>|<automation_host>)/i
| NOT (ComputerName=/^<jumpbox_host>/i AND ContextBaseFileName=/^java\.exe$/i)
// 6 OUTPUT
| select([bucket, aid, ComputerName, ContextBaseFileName, targets, ports, first_seen])
```
In LogScale the host exclusions run after the grouping, on the few rows that pass, so they don't need a host name on every connection event.

## Rule settings
| | |
|---|---|
| Interval / lookback | hourly / 2 hours. Buckets are fixed 2-hour clock windows. |
| Suppression | `host.name`, `process.name` for 2h |

## Telemetry assumptions
- `networkconnectip4` with `destination.ip`, `destination.port`, `network.transport` (from Falcon's `Protocol`) and `data.ConnectionDirection` (0 is outbound).
- `host.name` on connection events (it's the grouping key), and `process.name`, which older sensors often leave empty; those connections count as `unknown`.

Confirm them over the last hour, and see how many connections arrive without a process name:
```esql
FROM logs-yourorg-crowdstrike-data-default*
| WHERE event.action == "networkconnectip4"
| STATS events = COUNT(*), with_host = COUNT(host.name), with_process = COUNT(process.name)
    BY network.transport, data.ConnectionDirection
```
```logscale
#event_simpleName=NetworkConnectIP4
| groupBy([Protocol, ConnectionDirection], function=[count(as=events), count(ContextBaseFileName, as=with_process)], limit=max)
```

## Baseline and threshold source
The thresholds were tuned on production data. To re-check them, or to find the next exclusion, run stages 0 to 3 over a few days and end with `SORT ports DESC | LIMIT 50`, then `SORT targets DESC | LIMIT 50`. The busiest legitimate process on a host becomes a host + process exclusion (like the jump-box line) rather than a whole-host one.

## Suppression
Suppress by `host.name`, `process.name` for 2h. Alerts missing a key field are not suppressed. The hourly runs overlap, so a scan seen in two runs folds into one alert.

## Known false positives / exclusions
- The excluded hosts are whole hosts: monitoring, collection, discovery and automation servers. A compromised one scanning is invisible to this rule. Where one program does the scanning, narrow the line to host + process, like the jump-box one.
- Business applications that connect to many internal hosts. Exclude them by process name.
- `unknown` groups every unnamed process on a host together, so two busy programs can add up. The pivot query shows what they were.

## Blind spots
- UDP scans, and raw-packet scans run as admin (nmap `-sS` or `-sU`, masscan, zmap). CS18 catches them by name; D04's decoys catch anything that touches them.
- A scan that crosses a 2-hour bucket edge is split in two, and each half may stay under the thresholds.
- A scan paced slower than 100 hosts or 200 ports per 2 hours.
- All processes of one name on a host count together (every `powershell.exe`, for example).

## Triage
- Read `ports` and `targets`: 445, 3389, 22 and 5985 across many hosts usually come before lateral movement; check B04 on the same host.
- Find the process: its start event on that host around `first_seen` gives the path, command line, parent and user. A shell, a script interpreter, or a binary in `Downloads`, `Temp` or `/tmp` scanning is reconnaissance. So is an IP scanner run by an account that isn't IT.

Pivot query, from an hour before `first_seen` to the end of the bucket:
```esql
FROM logs-yourorg-crowdstrike-data-default*
| WHERE host.name == "<host.name>" AND event.action IN ("processrollup2", "networkconnectip4")
  AND (process.name == "<process.name>" OR data.ContextBaseFileName == "<process.name>")
| KEEP @timestamp, event.action, user.name, process.executable, process.command_line, process.parent.name, destination.ip,
       destination.port, data.ContextProcessId, data.TargetProcessId
| SORT @timestamp ASC
```
```logscale
#event_simpleName=/^(ProcessRollup2|NetworkConnectIP4)$/ aid="<aid>"
| FileName="<process name>" or ContextBaseFileName="<process name>"
| select([@timestamp, #event_simpleName, UserName, ImageFileName, CommandLine, ParentBaseFileName, RemoteAddressIP4, RemotePort, TargetProcessId, ContextProcessId])
```

## Test
From a lab host:
- `nmap -sT -p 1-1000 <lab host>`: a port scan (200+ ports).
- `nmap -sT -Pn -p 22,80,135,139,443,445,3389 <lab /24>`: a host sweep (100+ hosts on 5+ ports).
- A PowerShell loop testing a few ports across a lab /24 (`Test-NetConnection` in a `foreach`): a host sweep with no scanner involved.
- `nmap -sS <lab /24>` as admin: nothing here, by design. CS18 alerts by name.
