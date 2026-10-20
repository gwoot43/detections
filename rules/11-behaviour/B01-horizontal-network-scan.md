---
id: B01
name: Internal scanning by behaviour - a port scan of a few hosts, a sweep of many, or a reverse-DNS sweep, from one process (Falcon) or one address with probes unanswered (Palo Alto)
category: behaviour
status: todo
severity: high
language: esql
index: logs-yourorg-crowdstrike-data-default*
mitre: [T1046, T1018]
data_source: CrowdStrike FDR NetworkConnectIP4 and DnsRequest; Palo Alto PAN-OS traffic logs as a second source
suppression:
  fields: [host.id, finding]
  duration: 1h
  missing_fields: do_not_suppress
---
## Why this is behavioural and high fidelity
**One question:** is one process scanning the internal network? Any internal scan, whatever runs it (nmap, masscan, an IP scanner, a PowerShell loop, an implant's built-in scanner, a worm), does one of three things. The rule looks for each per process instance (host + process ID), so one busy process can't lend its count to another:

| `finding` | What the process did in the window | Why it's a scan |
|---|---|---|
| port scan of one or a few hosts | Tried 30+ ports, on at most 5 internal hosts | Nothing legitimate tries 30 ports on a handful of machines |
| sweep of many hosts | Tried 50+ internal hosts, or 10+ hosts on 10+ ports | A hunt for one service (SMB, RDP, SSH, WinRM) across subnets, or a mixed scan |
| reverse-DNS sweep of internal addresses | Looked up the names of 50+ internal addresses | Scanners name the hosts they find. The lookups go through the normal resolver, so this shows even when the scan itself sends raw packets that Falcon doesn't record as connections |

The three labels answer the same question with different evidence, so they stay in one rule.

This rule is the worked example of the detection standard ([ES|QL](../../docs/DETECTION-STRUCTURE-ESQL.md), [CQL](../../docs/DETECTION-STRUCTURE-CQL.md)). Each stage of the query is numbered to match it:
- **Gate:** only filters the index answers: event type, port ranges, `CIDR_MATCH`, exact registered domains, and the grouping key present. No function touches a field before the rows are cut down. DNS and internal connections are the busiest events in FDR, so this is what keeps the rule cheap.
- **Reduce:** one `STATS`, keyed on host and Falcon process ID, both required by the gate. Each count is a conditional aggregate, so there's no shaping stage at all.
- **Decide:** every threshold in one place, labelled as it's decided.
- **Enrich:** exclusions run on the few rows that survive, as host + process (or host + finding) pairs, never a whole host.
- **Output:** the entity, the counts, and ten sample ports and addresses. Everything else is in the triage pivot query.

**The firewall sees what Falcon can't.** The Palo Alto query starts from sessions that got nothing back: denied, or never completed. Scans are mostly that, because they hit closed ports and empty addresses. Monitoring and management servers get answers, so they rarely pile up dozens of unanswered probes. It also covers scans from devices without Falcon (a rogue laptop, a compromised appliance) and raw-packet scans, but only between zones the firewall sits between.

## Query
```esql
FROM logs-yourorg-crowdstrike-data-default*
// 1 GATE: connections to internal addresses on service ports (chatter ports and dynamic RPC left out), and reverse
// lookups of the 10, 172 and 192 ranges by exact registered domain. Every row must carry the grouping key.
| WHERE ((event.action == "networkconnectip4" AND destination.port < 49152
          AND NOT destination.port IN (53, 123, 137, 138, 1900, 5353, 5355)
          AND CIDR_MATCH(destination.ip, "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
         OR (event.action == "dnsrequest"
             AND dns.question.registered_domain IN ("10.in-addr.arpa", "172.in-addr.arpa", "192.in-addr.arpa")))
  AND host.id IS NOT NULL AND data.ContextProcessId IS NOT NULL
// 3 REDUCE: one row per process instance. Conditional counts, so connections and lookups are counted apart in one pass.
// The RLIKE keeps only the private parts of 172 and 192, and runs on the few reverse lookups the gate let through.
| STATS targets = COUNT_DISTINCT(destination.ip) WHERE event.action == "networkconnectip4",
        ports = COUNT_DISTINCT(destination.port) WHERE event.action == "networkconnectip4",
        ptr_names = COUNT_DISTINCT(dns.question.name) WHERE dns.question.registered_domain == "10.in-addr.arpa"
          OR dns.question.name RLIKE ".*\\.((1[6-9]|2[0-9]|3[01])\\.172|168\\.192)\\.in-addr\\.arpa\\.?",
        sample_ports = TOP(destination.port, 10, "asc") WHERE event.action == "networkconnectip4",
        sample_targets = TOP(destination.ip, 10, "asc") WHERE event.action == "networkconnectip4",
        process.name = VALUES(data.ContextBaseFileName), host.name = VALUES(host.name), first_seen = MIN(@timestamp)
    BY host.id, data.ContextProcessId
// 4 DECIDE: each scan shape on its own threshold, labelled here so every threshold lives in one place.
// Thresholds: starting values, not yet baselined. Replace each with your p99 from the baseline query below plus a buffer,
// and record the date range measured in this comment.
| EVAL finding = CASE(ports >= 30 AND targets <= 5, "port scan of one or a few hosts",
                      targets >= 50 OR (targets >= 10 AND ports >= 10), "sweep of many hosts",
                      ptr_names >= 50, "reverse-DNS sweep of internal addresses",
                      NULL)
| WHERE finding IS NOT NULL
// 5 ENRICH: DNS events carry no process name, so a process seen only in lookups reads "unknown". Then drop the
// host + process (or host + finding) pairs that scan by design, on survivors only. Placeholders.
| EVAL process.name = COALESCE(MV_MIN(process.name), "unknown")
| WHERE NOT ((host.id == "<vuln_scanner_aid>" AND process.name == "<scanner_process>")
          OR (host.id == "<monitoring_aid>" AND process.name == "<monitoring_process>")
          OR (host.id == "<log_collector_aid>" AND finding == "reverse-DNS sweep of internal addresses"))
// 6 OUTPUT: the entity, the decision counts and a short sample. The detail is in the triage pivot query.
| KEEP host.id, host.name, finding, process.name, data.ContextProcessId, targets, ports, ptr_names, sample_ports, sample_targets,
       first_seen
```

**CrowdStrike (Falcon LogScale / Advanced Event Search)**, run over the last 12 minutes:
```logscale
#event_simpleName=/^(NetworkConnectIP4|DnsRequest)$/
// 1 GATE: the grouping key present; internal connections, or reverse lookups of internal ranges. A regex on the address
// instead of cidr(): functions can't be joined with "or", and each event type lacks the other's field.
| aid=* ContextProcessId=*
| RemoteAddressIP4=/^(10|172\.(1[6-9]|2\d|3[01])|192\.168)\./ or DomainName=/\.(10|(1[6-9]|2\d|3[01])\.172|168\.192)\.in-addr\.arpa\.?$/i
// Chatter ports and dynamic RPC (49152 and up) left out. Lookups have no RemotePort, so both negated filters pass them.
| NOT (RemotePort >= 49152)
| !in(field="RemotePort", values=["53", "123", "137", "138", "1900", "5353", "5355"])
// 3 REDUCE: one row per process instance. count(field) only counts events that have the field, so connections and
// lookups are counted apart without a shaping step.
| groupBy([aid, ContextProcessId], function=[count(RemoteAddressIP4, distinct=true, as=targets), count(RemotePort, distinct=true, as=ports),
                                             count(DomainName, distinct=true, as=ptr_names), min(@timestamp, as=first_seen),
                                             collect([ComputerName, ContextBaseFileName])], limit=max)
// 4 DECIDE: each scan shape on its own threshold, labelled here so every threshold lives in one place.
// Thresholds: starting values, not yet baselined. Replace each with your p99 from the baseline query below plus a buffer.
| case {
    ports >= 30 targets <= 5 | finding := "port scan of one or a few hosts";
    targets >= 50 | finding := "sweep of many hosts";
    targets >= 10 ports >= 10 | finding := "sweep of many hosts";
    ptr_names >= 50 | finding := "reverse-DNS sweep of internal addresses";
    * | finding := "none";
  }
| finding != "none"
// 5 ENRICH: name the process, then drop the host + process (or host + finding) pairs that scan by design. Placeholders.
| default(field=ContextBaseFileName, value="unknown")
| NOT (aid="<vuln_scanner_aid>" AND ContextBaseFileName="<scanner_process>")
| NOT (aid="<monitoring_aid>" AND ContextBaseFileName="<monitoring_process>")
| NOT (aid="<log_collector_aid>" AND finding="reverse-DNS sweep of internal addresses")
// 6 OUTPUT
| select([aid, ComputerName, finding, ContextBaseFileName, ContextProcessId, targets, ports, ptr_names, first_seen])
```

## Rule settings
| Query | Interval | Lookback | Suppression | Severity |
|---|---|---|---|---|
| Falcon (ES\|QL above) | 10 min | 12 min | `host.id`, `finding` for 1h | high |
| Falcon (LogScale above) | 10 min | 12 min | `aid`, `finding` for 1h | high |
| Palo Alto (below) | 10 min | 15 min | `source.ip`, `finding` for 1h | high |
| Known scanners by name (below) | 15 min | 15 min | `host.id`, `process.name` for 1h | medium |

The schedule is the window: every count is "in the last 10 minutes". The two extra minutes of lookback absorb ingest lag; the overlap between runs folds into one alert through suppression. Firewall logs arrive later than FDR, hence 15 minutes.

## Telemetry assumptions
- **Events:** `networkconnectip4` with `destination.ip` and `destination.port`; `dnsrequest` with `dns.question.name` and `dns.question.registered_domain`.
- **The grouping key:** `data.ContextProcessId`, Falcon's process ID, on both events. It is the same value as the process's own `data.TargetProcessId` on its `processrollup2`, which is how the pivot finds the command line. If your pipeline maps it to `process.entity_id` instead, use that, in the gate and the `BY` alike.
- **Process name:** `data.ContextBaseFileName` on connections, which older sensors don't send. DNS events never carry it.
- **Case:** registered domains are matched in lowercase, which is how Windows and Linux resolvers send them.

Confirm them over the last hour before deploying. Each `with_` count should equal `events` on the rows where the field belongs:
```esql
FROM logs-yourorg-crowdstrike-data-default*
| WHERE event.action IN ("networkconnectip4", "dnsrequest")
| STATS events = COUNT(*), hosts = COUNT_DISTINCT(host.id), with_pid = COUNT(data.ContextProcessId),
        with_address = COUNT(destination.ip), with_port = COUNT(destination.port), with_name = COUNT(data.ContextBaseFileName),
        with_registered_domain = COUNT(dns.question.registered_domain)
    BY event.action
```
```logscale
#event_simpleName=/^(NetworkConnectIP4|DnsRequest)$/
| groupBy([#event_simpleName, event_platform], function=[count(), count(aid, distinct=true, as=hosts), count(ContextProcessId, as=with_pid),
                                                        count(RemoteAddressIP4, as=with_address), count(ContextBaseFileName, as=with_name)],
          limit=max)
```
If `with_registered_domain` is zero, gate the lookups on the record type instead (`data.RequestType`, 12 is PTR), which is also an exact match. Don't fall back to `LIKE "*.in-addr.arpa*"`: a leading wildcard reads every lookup.

## Baseline and threshold source
The thresholds above are starting values, not measurements. Measure each shape on your own data before enabling, and write the result next to the threshold.

Run stages 0 to 3 with the window rebuilt as 10-minute buckets, one day at a time (it keeps a row for every process in every window, which is heavy), over at least five working days. Take the highest p99 of the days, and record whether patch nights or a scheduled scan fell in the range:
```esql
FROM logs-yourorg-crowdstrike-data-default*
| WHERE ((event.action == "networkconnectip4" AND destination.port < 49152
          AND NOT destination.port IN (53, 123, 137, 138, 1900, 5353, 5355)
          AND CIDR_MATCH(destination.ip, "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
         OR (event.action == "dnsrequest"
             AND dns.question.registered_domain IN ("10.in-addr.arpa", "172.in-addr.arpa", "192.in-addr.arpa")))
  AND host.id IS NOT NULL AND data.ContextProcessId IS NOT NULL
// The rule's 10-minute window, rebuilt as a bucket so a whole day can be measured in one search.
| EVAL win = DATE_TRUNC(10 minutes, @timestamp)
| STATS targets = COUNT_DISTINCT(destination.ip) WHERE event.action == "networkconnectip4",
        ports = COUNT_DISTINCT(destination.port) WHERE event.action == "networkconnectip4",
        ptr_names = COUNT_DISTINCT(dns.question.name) WHERE dns.question.registered_domain == "10.in-addr.arpa"
          OR dns.question.name RLIKE ".*\\.((1[6-9]|2[0-9]|3[01])\\.172|168\\.192)\\.in-addr\\.arpa\\.?"
    BY host.id, data.ContextProcessId, win
| EVAL mixed = LEAST(targets, ports)
// Second STATS, baseline only: each shape's metric across the windows (mixed: the smaller of hosts and ports, which the
// "10+ hosts on 10+ ports" shape tests). Each is measured only where that activity happened at all; most processes never
// do a reverse lookup, and counting their zeros would hide the tail.
| STATS windows = COUNT(*),
        port_scan_p95 = PERCENTILE(ports, 95) WHERE targets > 0 AND targets <= 5,
        port_scan_p99 = PERCENTILE(ports, 99) WHERE targets > 0 AND targets <= 5,
        port_scan_max = MAX(ports) WHERE targets > 0 AND targets <= 5,
        sweep_p95 = PERCENTILE(targets, 95) WHERE targets > 0, sweep_p99 = PERCENTILE(targets, 99) WHERE targets > 0,
        sweep_max = MAX(targets) WHERE targets > 0,
        mixed_p95 = PERCENTILE(mixed, 95) WHERE mixed > 0, mixed_p99 = PERCENTILE(mixed, 99) WHERE mixed > 0,
        mixed_max = MAX(mixed) WHERE mixed > 0,
        ptr_p95 = PERCENTILE(ptr_names, 95) WHERE ptr_names > 0, ptr_p99 = PERCENTILE(ptr_names, 99) WHERE ptr_names > 0,
        ptr_max = MAX(ptr_names) WHERE ptr_names > 0
```
```logscale
#event_simpleName=/^(NetworkConnectIP4|DnsRequest)$/
| aid=* ContextProcessId=*
| RemoteAddressIP4=/^(10|172\.(1[6-9]|2\d|3[01])|192\.168)\./ or DomainName=/\.(10|(1[6-9]|2\d|3[01])\.172|168\.192)\.in-addr\.arpa\.?$/i
| NOT (RemotePort >= 49152)
| !in(field="RemotePort", values=["53", "123", "137", "138", "1900", "5353", "5355"])
// The rule's 10-minute window, rebuilt as a bucket so a whole day can be measured in one search.
| win := math:floor(@timestamp / 600000)
| groupBy([aid, ContextProcessId, win], function=[count(RemoteAddressIP4, distinct=true, as=targets), count(RemotePort, distinct=true, as=ports),
                                                  count(DomainName, distinct=true, as=ptr_names)], limit=max)
// Baseline: one shape at a time, over the windows where it happened at all. As written, the reverse-DNS sweep.
// Port scan: filter targets >= 1 targets <= 5 and measure ports. Sweep: targets >= 1, measure targets.
// Mixed sweep: ports >= 10, measure targets.
| ptr_names >= 1
| [count(), percentile(field=ptr_names, percentiles=[50, 95, 99]), max(ptr_names)]
```
Set each threshold just above its p99, with a buffer for ingest lag (a window can hold up to 12 minutes of events). A max equal to a subnet's size (254, 256) is a sweep in your baseline, not normal activity: find out what it was before you set anything above it. The Palo Alto query is baselined the same way, grouped by `source.ip`.

To see which processes sit closest to each threshold (and which pairs the exclusions need), run stages 0 to 3 of the rule and end with `SORT targets DESC | LIMIT 50`, then the same for `ports` and `ptr_names`.

## Second source: Palo Alto traffic logs
Run every 10 minutes with a 15-minute lookback. It starts from unanswered sessions only, which keeps it small:
```esql
FROM logs-panw.panos-*
// 1 GATE: internal sessions on service ports that got nothing back: denied or dropped, or never completed (no application).
// != drops sessions with no recorded action, which is intended: they aren't evidence of a probe.
| WHERE panw.panos.type == "TRAFFIC" AND destination.port < 49152
  AND (panw.panos.action != "allow" OR network.application IN ("incomplete", "insufficient-data"))
  AND CIDR_MATCH(source.ip, "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
  AND CIDR_MATCH(destination.ip, "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
  // A vulnerability scanner probing the range it's meant to scan (placeholders: its address, then its scope).
  // The same scanner probing anywhere else still alerts.
  AND NOT (CIDR_MATCH(source.ip, "198.51.100.10/32") AND CIDR_MATCH(destination.ip, "198.51.100.0/24"))
// 3 REDUCE: one row per source address: how many hosts and ports went unanswered.
| STATS targets = COUNT_DISTINCT(destination.ip), ports = COUNT_DISTINCT(destination.port),
        sample_ports = TOP(destination.port, 10, "asc"), sample_targets = TOP(destination.ip, 10, "asc"), first_seen = MIN(@timestamp)
    BY source.ip
// 4 DECIDE: the same shapes, counted on unanswered probes only. Thresholds: starting values, not yet baselined
// (baseline as for the Falcon query, grouped by source.ip).
| EVAL finding = CASE(ports >= 30 AND targets <= 5, "port scan of one or a few hosts",
                      targets >= 50 OR (targets >= 10 AND ports >= 10), "sweep of many hosts",
                      NULL)
| WHERE finding IS NOT NULL
// 6 OUTPUT
| KEEP source.ip, finding, targets, ports, sample_ports, sample_targets, first_seen
```
Suppress by `source.ip`, `finding` for 1h. Field names are the Elastic PAN-OS integration's; confirm `panw.panos.action` and the `incomplete` application value in your data. If zone protection's reconnaissance protection is on, PAN-OS also writes its own threat logs for this ("TCP Port Scan", "Host Sweep"); those can be passed through as they are.

## Filename fallback: known scanners by name (optional)
Run every 15 minutes with a 15-minute lookback. It's a separate query so the scan rule doesn't read every process start. Names are matched exactly or by prefix, which the index answers cheaply:
```esql
FROM logs-yourorg-crowdstrike-data-default* METADATA _id, _index, _version
// 1 GATE: GUI and command-line scanners by the names they ship under (versioned names by prefix), minus a host and
// the scanner it runs by design (placeholders). Never the whole host: anything else started there still alerts.
| WHERE event.action == "processrollup2"
  AND (process.name IN ("nmap.exe", "nmap", "masscan.exe", "masscan", "rustscan.exe", "rustscan", "zmap", "naabu.exe", "naabu",
                        "advanced_ip_scanner.exe", "advanced_port_scanner.exe", "netscan.exe")
       OR process.name LIKE "nbtscan*" OR process.name LIKE "fscan*" OR process.name LIKE "ipscan*")
  AND NOT (host.id IN ("<network_team_aid>", "<security_team_aid>") AND process.name IN ("<approved_scanner>"))
// 6 OUTPUT
| KEEP @timestamp, host.id, host.name, user.name, process.name, process.executable, process.command_line, process.parent.name,
       _id, _version, _index
```
```logscale
#event_simpleName=ProcessRollup2
// 1 GATE: the same names, any case, minus a host and the scanner it runs by design (one line per host; placeholders).
| FileName=/^(nmap|masscan|rustscan|zmap|naabu|nbtscan[-._a-z0-9]*|fscan[_a-z0-9]*|advanced_ip_scanner|advanced_port_scanner|netscan|ipscan[-_.a-z0-9]*)(\.exe)?$/i
| NOT (aid="<network_team_aid>" AND FileName="<approved_scanner>")
| NOT (aid="<security_team_aid>" AND FileName="<approved_scanner>")
// 6 OUTPUT
| select([@timestamp, aid, ComputerName, UserName, FileName, CommandLine, ParentBaseFileName, TargetProcessId])
```
Medium severity, suppress by `host.id`, `process.name` for 1h. It needs `process.name` on process starts. The ES|QL version matches the names as they ship (lowercase); a re-cased copy (`NMAP.EXE`) needs adding to the list, or it falls to the behaviour query.

## Suppression
Suppress by `host.id`, `finding` for 1h. Alerts missing a key field are not suppressed. Scans are often run several times in a row; those fold into one alert per host and kind of scan, and a climbing count is worth reading.

## Known false positives / exclusions
Exclusions are pairs, never a whole host: a host and the one process that scans there by design, or a host and the one finding it produces. A stolen admin account, or any other process on a scanner host, still alerts.
- Vulnerability scanners, asset discovery, monitoring, backup and management servers: the host and its scanning service.
- Log collectors and SIEM forwarders that add reverse-DNS names to the events they ship: the host and the reverse-DNS finding.
- A management script on a host you didn't expect (an admin's workstation running a PowerShell loop over many servers). That's still worth a look: it's also what an intruder does.

The standard keeps exclusions in one central list (a lookup index or file) rather than in each rule. This library has no lookups yet, so they're written inline as placeholders; when a central list exists, replace the step 5 `WHERE NOT` (and the LogScale `NOT` lines) with a lookup on host and process.

## Blind spots
- In Falcon: a raw-packet scan with name resolution off (`-n`). The Palo Alto query sees it if it crosses the firewall; D04's decoy hosts see any scan that touches them; the name query sees known scanners.
- UDP scans of the left-out chatter ports (NetBIOS name sweeps on 137 and similar). IP scanners that do this also resolve names, which the reverse-DNS sweep sees.
- Services on 49152 and up, and scans that only probe them.
- A slow scan spread over more than the window (`--scan-delay`, `-T1`) stays under each threshold. If that's a concern, run a second copy hourly with a 65-minute lookback, baselined on 1-hour buckets (change the bucket in the baseline query); don't just scale the 10-minute thresholds.
- A scan split across several processes, each below the thresholds (a worm spawning one process per target). The per-process key is what keeps busy hosts from adding up; the cost is this.
- Reverse lookups in uppercase (`IN-ADDR.ARPA`), which some custom resolvers send. The discovery query shows whether you have any.

## Triage
- Read `finding` and the shape: `ports` and `sample_ports` (what it was looking for), `targets` and `sample_targets` (where it looked). 445, 3389, 22 and 5985 usually come before lateral movement: check B04 on the same host for what followed.
- Run the pivot query for the process: its start (path, command line, parent, user) and everything it connected to or looked up. A shell, a script interpreter, or a binary in `Downloads`, `Temp` or `/tmp` scanning is reconnaissance. So is an IP scanner run on a server by an account that isn't IT.
- From the Palo Alto query, find the device behind `source.ip` (DHCP, Falcon, switch port). An address with no Falcon sensor is a device you don't manage.

Pivot query, from an hour before `first_seen` (the process may have started earlier) to the alert. The process's own start carries its ID as `TargetProcessId`; its connections and lookups carry it as `ContextProcessId`:
```esql
FROM logs-yourorg-crowdstrike-data-default*
| WHERE host.id == "<host.id>"
  AND (data.TargetProcessId == "<data.ContextProcessId>" OR data.ContextProcessId == "<data.ContextProcessId>")
  AND event.action IN ("processrollup2", "syntheticprocessrollup2", "networkconnectip4", "dnsrequest")
| KEEP @timestamp, event.action, user.name, process.executable, process.command_line, process.parent.name, destination.ip,
       destination.port, dns.question.name
| SORT @timestamp ASC
```
```logscale
#event_simpleName=/^(ProcessRollup2|SyntheticProcessRollup2|NetworkConnectIP4|DnsRequest)$/ aid="<aid>"
| TargetProcessId="<ContextProcessId>" or ContextProcessId="<ContextProcessId>"
| select([@timestamp, #event_simpleName, UserName, ImageFileName, CommandLine, ParentBaseFileName, RemoteAddressIP4, RemotePort, DomainName])
```

## Test
From a lab host:
- `nmap -sT -p 1-1000 <lab host>`: "port scan of one or a few hosts".
- `nmap -sT -p 445 <lab /24>`: "sweep of many hosts".
- `nmap -sS <lab /24>` as admin: "reverse-DNS sweep" (nmap names each live host unless run with `-n`), and a sweep in the Palo Alto query if it crosses the firewall.
- A PowerShell loop testing port 445 across a lab /24 (`Test-NetConnection` in a `foreach`): "sweep of many hosts", with no scanner involved.
- Advanced IP Scanner on a lab subnet: the name query, and a reverse-DNS sweep when it resolves names.
- Run the pivot query on one of the alerts and confirm it returns the scanner's start event: that proves the process ID links.
