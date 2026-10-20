---
id: B01
name: Internal scanning by behaviour - a mixed scan, a port scan of a few hosts, a sweep of many hosts, or a reverse-DNS sweep, from one process (Falcon) or one address with probes unanswered (Palo Alto)
category: behaviour
status: todo
severity: high
language: esql
index: logs-yourorg-crowdstrike-data-default*
mitre: [T1046, T1018]
data_source: CrowdStrike FDR NetworkConnectIP4, and DnsRequest in a separate reverse-DNS query; Palo Alto PAN-OS traffic logs as a second source
suppression:
  fields: [host.id, finding]
  duration: 1h
  missing_fields: do_not_suppress
---
## Why this is behavioural and high fidelity
**One question:** is one process scanning the internal network? Any scan that makes connections, whatever runs it (nmap, an IP scanner, a PowerShell loop, an implant's built-in scanner, a worm), has one of three shapes. The rule counts the internal hosts and ports each process instance (host + process ID) tried, so one busy process can't lend its count to another, then classifies the shape, most specific first:

| `finding` | Shape in the window | Look-alikes | Severity |
|---|---|---|---|
| `mixed_scan` | 10+ internal hosts on 10+ ports | Almost only vulnerability scanners, which are excluded by host + process | critical |
| `port_scan` | 20+ ports on at most 5 hosts | Very few: normal applications rarely touch 20 service ports on one host | high |
| `host_sweep` | 50+ internal hosts | Management, monitoring, domain controllers, backup and vulnerability scanners | medium |
| `ptr_sweep` (separate query) | Names of 50+ internal addresses looked up | IP address management, monitoring, log collectors that name the addresses they ship | medium |

**One rule, three connection shapes.** The scope, gate and reduce are the same for every connection shape, so three rules would run the same expensive search three times. The shapes differ in their look-alikes, so each gets its own threshold and severity after the reduce.

**Reverse-DNS sweeps in their own query.** Tools that resolve names through the operating system (Advanced IP Scanner, PowerShell sweeps, nmap with `--system-dns`) look up the name of each host they find. That shows a ping sweep even when its packets don't make connections. The query is kept separate because it reads a different event, so nothing is searched twice, and it stays cheap: it only ever reads reverse lookups of internal ranges, never the rest of DNS (see "Why it's cheap" under the query).

This rule is the worked example of the detection standard ([ES|QL](../../docs/DETECTION-STRUCTURE-ESQL.md), [CQL](../../docs/DETECTION-STRUCTURE-CQL.md)). Each stage of the query is numbered to match it:
- **Gate:** only filters the index answers: event type, port ranges, `CIDR_MATCH`, and the grouping key present. No function touches a field before the rows are cut down.
- **Reduce:** one `STATS`, keyed on host and Falcon process ID, both required by the gate.
- **Decide:** every threshold in one place, labelled as it's decided.
- **Enrich:** exclusions run on the few rows that survive, as host + process pairs, never a whole host; then severity by shape.
- **Output:** the entity, the counts, and ten sample ports and addresses. Everything else is in the triage pivot query.

**The firewall sees what Falcon can't.** The Palo Alto query starts from sessions that got nothing back: denied, or never completed. Scans are mostly that, because they hit closed ports and empty addresses. Monitoring and management servers get answers, so they rarely pile up dozens of unanswered probes. It also covers scans from devices without Falcon (a rogue laptop, a compromised appliance) and raw-packet scans, but only between zones the firewall sits between.

## Query
```esql
FROM logs-yourorg-crowdstrike-data-default*
// 1 GATE: connections to internal addresses (private ranges and 100.64.0.0/10, the shared range some Kubernetes and cloud
// networks use) on service ports. Chatter ports (DNS, NTP, NetBIOS datagrams, SSDP, mDNS, LLMNR) and dynamic RPC
// (49152 and up) left out. Every row must carry the grouping key.
| WHERE event.action == "networkconnectip4" AND destination.port < 49152
  AND NOT destination.port IN (53, 123, 137, 138, 1900, 5353, 5355)
  AND CIDR_MATCH(destination.ip, "10.0.0.0/8", "100.64.0.0/10", "172.16.0.0/12", "192.168.0.0/16")
  AND host.id IS NOT NULL AND data.ContextProcessId IS NOT NULL
// 3 REDUCE: one row per process instance: how many internal hosts and ports it tried, with a capped sample of each.
| STATS targets = COUNT_DISTINCT(destination.ip), ports = COUNT_DISTINCT(destination.port),
        sample_ports = TOP(destination.port, 10, "asc"), sample_targets = TOP(destination.ip, 10, "asc"),
        process.name = VALUES(data.ContextBaseFileName), host.name = VALUES(host.name), first_seen = MIN(@timestamp)
    BY host.id, data.ContextProcessId
// 4 DECIDE: classify the shape, most specific first. Each shape has its own threshold, and they all live here.
// Thresholds: starting values, not yet baselined. Replace each from its shape's baseline and top talkers (below), and
// record the date range measured in this comment.
| EVAL finding = CASE(targets >= 10 AND ports >= 10, "mixed_scan",
                      targets <= 5 AND ports >= 20, "port_scan",
                      targets >= 50, "host_sweep",
                      NULL)
| WHERE finding IS NOT NULL
// 5 ENRICH: older sensors send no process name ("unknown"). Drop the host + process pairs that scan by design
// (placeholders), then set severity by shape.
| EVAL process.name = COALESCE(MV_MIN(process.name), "unknown")
| WHERE NOT ((host.id == "<vuln_scanner_aid>" AND process.name == "<scanner_process>")
          OR (host.id == "<monitoring_aid>" AND process.name == "<monitoring_process>"))
| EVAL severity = CASE(finding == "mixed_scan", "critical", finding == "port_scan", "high", "medium")
// 6 OUTPUT: the entity, the decision counts and a short sample. The detail is in the triage pivot query.
| KEEP host.id, host.name, finding, severity, process.name, data.ContextProcessId, targets, ports, sample_ports, sample_targets,
       first_seen
```

**CrowdStrike (Falcon LogScale / Advanced Event Search)**, run over the last 12 minutes:
```logscale
#event_simpleName=NetworkConnectIP4
// 1 GATE: the grouping key present; internal addresses (private ranges and 100.64.0.0/10) on service ports, with
// chatter ports and dynamic RPC (49152 and up) left out.
| aid=* ContextProcessId=*
| cidr(RemoteAddressIP4, subnet=["10.0.0.0/8", "100.64.0.0/10", "172.16.0.0/12", "192.168.0.0/16"])
| RemotePort < 49152
| !in(field="RemotePort", values=["53", "123", "137", "138", "1900", "5353", "5355"])
// 3 REDUCE: one row per process instance: how many internal hosts and ports it tried.
| groupBy([aid, ContextProcessId], function=[count(RemoteAddressIP4, distinct=true, as=targets), count(RemotePort, distinct=true, as=ports),
                                             min(@timestamp, as=first_seen), collect([ComputerName, ContextBaseFileName])], limit=max)
// 4 DECIDE + 5 ENRICH: classify the shape, most specific first, with its severity. Every threshold lives here.
// Thresholds: starting values, not yet baselined. Replace each from its shape's baseline and top talkers (below).
| case {
    targets >= 10 ports >= 10 | finding := "mixed_scan" | severity := "critical";
    targets <= 5 ports >= 20 | finding := "port_scan" | severity := "high";
    targets >= 50 | finding := "host_sweep" | severity := "medium";
    * | finding := "none";
  }
| finding != "none"
// 5 ENRICH: name the process, then drop the host + process pairs that scan by design. Placeholders.
| default(field=ContextBaseFileName, value="unknown")
| NOT (aid="<vuln_scanner_aid>" AND ContextBaseFileName="<scanner_process>")
| NOT (aid="<monitoring_aid>" AND ContextBaseFileName="<monitoring_process>")
// 6 OUTPUT
| select([aid, ComputerName, finding, severity, ContextBaseFileName, ContextProcessId, targets, ports, first_seen])
```

## Reverse-DNS sweep (separate query)
Run every 10 minutes with a 12-minute lookback, as its own rule.
```esql
FROM logs-yourorg-crowdstrike-data-default*
// 1 GATE: reverse lookups of the 10, 100, 172 and 192 ranges, by exact registered domain. The index answers this, so the
// query reads only those lookups, never the rest of DNS. Every row must carry the grouping key.
| WHERE event.action == "dnsrequest"
  AND dns.question.registered_domain IN ("10.in-addr.arpa", "100.in-addr.arpa", "172.in-addr.arpa", "192.in-addr.arpa")
  AND host.id IS NOT NULL AND data.ContextProcessId IS NOT NULL
// 3 REDUCE: one row per process instance: how many internal addresses it named. The RLIKE keeps only the private parts
// of 100, 172 and 192, and runs on the few lookups the gate let through.
| STATS ptr_names = COUNT_DISTINCT(dns.question.name) WHERE dns.question.registered_domain == "10.in-addr.arpa"
          OR dns.question.name RLIKE ".*\\.((6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\\.100|(1[6-9]|2[0-9]|3[01])\\.172|168\\.192)\\.in-addr\\.arpa\\.?",
        host.name = VALUES(host.name), first_seen = MIN(@timestamp)
    BY host.id, data.ContextProcessId
// 4 DECIDE. Threshold: starting value, not yet baselined. Replace it from the baseline and top talkers below.
| WHERE ptr_names >= 50
// 5 ENRICH: DNS events carry no process name; the pivot query finds it. A log collector that names the addresses in the
// events it ships is excluded for this finding only, and its connections are still judged above. Placeholders.
| EVAL finding = "ptr_sweep", severity = "medium"
| WHERE NOT (host.id == "<log_collector_aid>" AND finding == "ptr_sweep")
// 6 OUTPUT
| KEEP host.id, host.name, finding, severity, data.ContextProcessId, ptr_names, first_seen
```
```logscale
#event_simpleName=DnsRequest
// 1 GATE: reverse lookups (record type 12) first. It's an exact match, the cheapest test there is, and it drops almost
// every DNS event. The regex then runs only on what's left, and last the grouping key.
| RequestType=12
| DomainName=/\.(10|(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.100|(1[6-9]|2\d|3[01])\.172|168\.192)\.in-addr\.arpa\.?$/i
| aid=* ContextProcessId=*
// 3 REDUCE: one row per process instance: how many internal addresses it named.
| groupBy([aid, ContextProcessId], function=[count(DomainName, distinct=true, as=ptr_names), min(@timestamp, as=first_seen),
                                             collect([ComputerName])], limit=max)
// 4 DECIDE. Threshold: starting value, not yet baselined. Replace it from the baseline and top talkers below.
| ptr_names >= 50
// 5 ENRICH: the log collector exclusion, for this finding only. Placeholder.
| finding := "ptr_sweep" | severity := "medium"
| NOT (aid="<log_collector_aid>" AND finding="ptr_sweep")
// 6 OUTPUT
| select([aid, ComputerName, finding, severity, ContextProcessId, ptr_names, first_seen])
```

**Why it's cheap.** What made DNS heavy before was checking every DNS event's name with a regex. Here:
- **Elastic:** the gate is exact matches on indexed fields, so Elasticsearch finds the matching lookups through the index and reads only those. Cost follows the number of internal reverse lookups (the discovery query below counts them), not DNS volume. This needs `dns.question.registered_domain` to be an indexed keyword in your mapping, not a runtime field.
- **LogScale:** there's no index, so each run still reads the window's `DnsRequest` events. But the first test is an exact match on `RequestType`, which costs about the same per event as the event-type tag. The regex, the grouping and everything after run only on internal reverse lookups, a tiny fraction of DNS.

## Rule settings
| Query | Interval | Lookback | Suppression | Severity |
|---|---|---|---|---|
| Falcon (ES\|QL above) | 10 min | 12 min | `host.id`, `finding` for 1h | by shape, from `severity` |
| Falcon (LogScale above) | 10 min | 12 min | `aid`, `finding` for 1h | by shape, from `severity` |
| Reverse-DNS sweep (ES\|QL and LogScale) | 10 min | 12 min | `host.id` (`aid`), `finding` for 1h | medium |
| Palo Alto (below) | 10 min | 15 min | `source.ip`, `finding` for 1h | by shape, from `severity` |
| Known scanners by name (below) | 15 min | 15 min | `host.id`, `process.name` for 1h | medium |

In Elastic, set the rule's severity to high and add a severity override on the `severity` column (`critical`, `high`, `medium`). In Falcon, if the scheduled search can't take severity from a field, set it to high and read `severity` in the alert.

The schedule is the window: every count is "in the last 10 minutes". The two extra minutes of lookback absorb ingest lag; the overlap between runs folds into one alert through suppression. Firewall logs arrive later than FDR, hence 15 minutes. Because `finding` is in the suppression key, a sweep that grows into a mixed scan raises a new alert at the higher severity instead of folding into the old one.

## Telemetry assumptions
- **Event:** `networkconnectip4` with `destination.ip` and `destination.port`. Falcon records connections made through the operating system's network stack; raw-packet scans don't produce them.
- **The grouping key:** `data.ContextProcessId`, Falcon's process ID. It is the same value as the process's own `data.TargetProcessId` on its `processrollup2`, which is how the pivot finds the command line. If your pipeline maps it to `process.entity_id` instead, use that, in the gate and the `BY` alike.
- **Process name:** `data.ContextBaseFileName`, which older sensors don't send. DNS events never carry it.
- **Reverse lookups:** `dnsrequest` with `dns.question.name` and `dns.question.registered_domain`, matched in lowercase, which is how Windows and Linux resolvers send them. Falcon records lookups made through the operating system's resolver. nmap uses its own resolver unless run with `--system-dns`, so its lookups may never appear; the Test section checks this.

Confirm them over the last hour before deploying. Each `with_` count should be close to `events`:
```esql
FROM logs-yourorg-crowdstrike-data-default*
| WHERE event.action == "networkconnectip4"
| STATS events = COUNT(*), hosts = COUNT_DISTINCT(host.id), with_pid = COUNT(data.ContextProcessId),
        with_address = COUNT(destination.ip), with_port = COUNT(destination.port), with_name = COUNT(data.ContextBaseFileName)
```
```logscale
#event_simpleName=NetworkConnectIP4
| groupBy([event_platform], function=[count(), count(aid, distinct=true, as=hosts), count(ContextProcessId, as=with_pid),
                                      count(RemoteAddressIP4, as=with_address), count(ContextBaseFileName, as=with_name)], limit=max)
```

For the reverse-DNS query, the lookups it reads in an hour. Divide by six for what each run reads: that's its cost.
```esql
FROM logs-yourorg-crowdstrike-data-default*
| WHERE event.action == "dnsrequest"
  AND dns.question.registered_domain IN ("10.in-addr.arpa", "100.in-addr.arpa", "172.in-addr.arpa", "192.in-addr.arpa")
| STATS lookups = COUNT(*), hosts = COUNT_DISTINCT(host.id), with_pid = COUNT(data.ContextProcessId)
    BY dns.question.registered_domain
```
```logscale
#event_simpleName=DnsRequest
| RequestType=12
| groupBy([event_platform], function=[count(as=ptr_lookups), count(aid, distinct=true, as=hosts), count(ContextProcessId, as=with_pid)],
          limit=max)
```
If the ES|QL query returns nothing but LogScale shows reverse lookups, `dns.question.registered_domain` isn't populated in your index. Gate on `data.RequestType` (12 is PTR) instead, written to match its mapping (`== "12"` for a keyword, `== 12` for a number). Either is an exact match the index answers. Don't fall back to `LIKE "*.in-addr.arpa*"`: a leading wildcard reads every lookup.

## Baseline and threshold source
The thresholds above are starting values, not measurements. Measure each shape on your own data before enabling, and write the result next to the threshold. Run each query below over one day at a time (they keep a row for every process in every 10-minute window, which is heavy), on at least five working days, and record whether patch nights or a scheduled scan fell in the range.

**Percentiles per shape.** Stages 0 to 3 with the window rebuilt as 10-minute buckets, then each shape's metric across the windows:
```esql
FROM logs-yourorg-crowdstrike-data-default*
| WHERE event.action == "networkconnectip4" AND destination.port < 49152
  AND NOT destination.port IN (53, 123, 137, 138, 1900, 5353, 5355)
  AND CIDR_MATCH(destination.ip, "10.0.0.0/8", "100.64.0.0/10", "172.16.0.0/12", "192.168.0.0/16")
  AND host.id IS NOT NULL AND data.ContextProcessId IS NOT NULL
// The rule's 10-minute window, rebuilt as a bucket so a whole day can be measured in one search.
| EVAL win = DATE_TRUNC(10 minutes, @timestamp)
| STATS targets = COUNT_DISTINCT(destination.ip), ports = COUNT_DISTINCT(destination.port) BY host.id, data.ContextProcessId, win
| EVAL mixed = LEAST(targets, ports)
// Second STATS, baseline only: each shape's metric across the windows. mixed_scan tests the smaller of hosts and ports;
// port_scan tests ports on windows with at most 5 hosts; host_sweep tests hosts.
| STATS windows = COUNT(*),
        mixed_scan_p95 = PERCENTILE(mixed, 95), mixed_scan_p99 = PERCENTILE(mixed, 99), mixed_scan_max = MAX(mixed),
        port_scan_p95 = PERCENTILE(ports, 95) WHERE targets <= 5, port_scan_p99 = PERCENTILE(ports, 99) WHERE targets <= 5,
        port_scan_max = MAX(ports) WHERE targets <= 5,
        host_sweep_p95 = PERCENTILE(targets, 95), host_sweep_p99 = PERCENTILE(targets, 99), host_sweep_max = MAX(targets)
```
```logscale
#event_simpleName=NetworkConnectIP4
| aid=* ContextProcessId=*
| cidr(RemoteAddressIP4, subnet=["10.0.0.0/8", "100.64.0.0/10", "172.16.0.0/12", "192.168.0.0/16"])
| RemotePort < 49152
| !in(field="RemotePort", values=["53", "123", "137", "138", "1900", "5353", "5355"])
// The rule's 10-minute window, rebuilt as a bucket so a whole day can be measured in one search.
| win := math:floor(@timestamp / 600000)
| groupBy([aid, ContextProcessId, win], function=[count(RemoteAddressIP4, distinct=true, as=targets), count(RemotePort, distinct=true, as=ports)],
          limit=max)
// Baseline: one shape at a time. As written, host_sweep (targets).
// port_scan: add a "targets <= 5" filter and measure ports. mixed_scan: add "ports >= 10" and measure targets.
| [count(), percentile(field=targets, percentiles=[50, 95, 99]), max(targets)]
```

**Top talkers.** A p99 over thousands of process-windows doesn't show that the same few SCCM, monitoring or backup processes peak high every day, and those are what the threshold has to clear. This shows each host + process's busiest window over the day, keyed on the process name rather than its ID, so a service that restarts still adds up and each row is an exclusion pair ready to use:
```esql
FROM logs-yourorg-crowdstrike-data-default*
| WHERE event.action == "networkconnectip4" AND destination.port < 49152
  AND NOT destination.port IN (53, 123, 137, 138, 1900, 5353, 5355)
  AND CIDR_MATCH(destination.ip, "10.0.0.0/8", "100.64.0.0/10", "172.16.0.0/12", "192.168.0.0/16")
  AND host.id IS NOT NULL AND data.ContextProcessId IS NOT NULL
| EVAL win = DATE_TRUNC(10 minutes, @timestamp)
| STATS targets = COUNT_DISTINCT(destination.ip), ports = COUNT_DISTINCT(destination.port),
        process.name = VALUES(data.ContextBaseFileName) BY host.id, data.ContextProcessId, win
| EVAL process.name = COALESCE(MV_MIN(process.name), "unknown"), mixed = LEAST(targets, ports)
// Second STATS, baseline only: each host + process's busiest window, per shape. Sort by each peak in turn.
| STATS peak_mixed = MAX(mixed), peak_ports_few_hosts = MAX(ports) WHERE targets <= 5, peak_targets = MAX(targets),
        windows = COUNT(*)
    BY host.id, process.name
| SORT peak_targets DESC
| LIMIT 50
```
```logscale
#event_simpleName=NetworkConnectIP4
| aid=* ContextProcessId=*
| cidr(RemoteAddressIP4, subnet=["10.0.0.0/8", "100.64.0.0/10", "172.16.0.0/12", "192.168.0.0/16"])
| RemotePort < 49152
| !in(field="RemotePort", values=["53", "123", "137", "138", "1900", "5353", "5355"])
| win := math:floor(@timestamp / 600000)
| groupBy([aid, ContextProcessId, win], function=[count(RemoteAddressIP4, distinct=true, as=targets), count(RemotePort, distinct=true, as=ports),
                                                  collect([ContextBaseFileName])], limit=max)
// Top talkers, baseline only: each host + process's busiest window. Sort by peak_ports as well.
| default(field=ContextBaseFileName, value="unknown")
| groupBy([aid, ContextBaseFileName], function=[max(targets, as=peak_targets), max(ports, as=peak_ports), count(as=windows)],
          limit=max)
| sort(peak_targets, order=desc, limit=50)
```

**Reverse-DNS sweep.** The same two views. DNS events carry no process name, so its top talkers are per host:
```esql
FROM logs-yourorg-crowdstrike-data-default*
| WHERE event.action == "dnsrequest"
  AND dns.question.registered_domain IN ("10.in-addr.arpa", "100.in-addr.arpa", "172.in-addr.arpa", "192.in-addr.arpa")
  AND host.id IS NOT NULL AND data.ContextProcessId IS NOT NULL
// The rule's 10-minute window, rebuilt as a bucket so a whole day can be measured in one search.
| EVAL win = DATE_TRUNC(10 minutes, @timestamp)
| STATS ptr_names = COUNT_DISTINCT(dns.question.name) WHERE dns.question.registered_domain == "10.in-addr.arpa"
          OR dns.question.name RLIKE ".*\\.((6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\\.100|(1[6-9]|2[0-9]|3[01])\\.172|168\\.192)\\.in-addr\\.arpa\\.?"
    BY host.id, data.ContextProcessId, win
// Baseline only: windows with at least one internal reverse lookup (the gate also lets through public parts of 100,
// 172 and 192).
| WHERE ptr_names > 0
// Second STATS, baseline only: the distribution across windows. For top talkers, replace this STATS with
// "STATS peak_ptr = MAX(ptr_names), windows = COUNT(*) BY host.id | SORT peak_ptr DESC | LIMIT 50".
| STATS windows = COUNT(*), ptr_p50 = PERCENTILE(ptr_names, 50), ptr_p95 = PERCENTILE(ptr_names, 95),
        ptr_p99 = PERCENTILE(ptr_names, 99), ptr_max = MAX(ptr_names)
```
```logscale
#event_simpleName=DnsRequest
| RequestType=12
| DomainName=/\.(10|(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.100|(1[6-9]|2\d|3[01])\.172|168\.192)\.in-addr\.arpa\.?$/i
| aid=* ContextProcessId=*
// The rule's 10-minute window, rebuilt as a bucket so a whole day can be measured in one search.
| win := math:floor(@timestamp / 600000)
| groupBy([aid, ContextProcessId, win], function=[count(DomainName, distinct=true, as=ptr_names)], limit=max)
// Baseline: the distribution across windows. For top talkers, replace the last line with
// "groupBy([aid], function=[max(ptr_names, as=peak_ptr), count(as=windows)], limit=max) | sort(peak_ptr, order=desc, limit=50)".
| [count(), percentile(field=ptr_names, percentiles=[50, 95, 99]), max(ptr_names)]
```
A sweep only names the hosts that answer, so a sweep of a sparsely used subnet produces fewer lookups than it has addresses. If your subnets are sparse and the baseline is low, set this threshold lower than 50.

**Setting each threshold:** exclude the legitimate top talkers as host + process pairs (step 5), then set the threshold just above the highest peak left, with a buffer for ingest lag (a window can hold up to 12 minutes of events). Check it against the p99. A peak equal to a subnet's size (254, 256) is a sweep, not normal activity: find out what it was before you set anything above it. The Palo Alto query is baselined the same way, grouped by `source.ip`.

## Second source: Palo Alto traffic logs
Run every 10 minutes with a 15-minute lookback. It starts from unanswered sessions only, which keeps it small:
```esql
FROM logs-panw.panos-*
// 1 GATE: internal sessions on service ports that got nothing back: denied or dropped, or never completed (no application).
// != drops sessions with no recorded action, which is intended: they aren't evidence of a probe.
| WHERE panw.panos.type == "TRAFFIC" AND destination.port < 49152
  AND (panw.panos.action != "allow" OR network.application IN ("incomplete", "insufficient-data"))
  AND CIDR_MATCH(source.ip, "10.0.0.0/8", "100.64.0.0/10", "172.16.0.0/12", "192.168.0.0/16")
  AND CIDR_MATCH(destination.ip, "10.0.0.0/8", "100.64.0.0/10", "172.16.0.0/12", "192.168.0.0/16")
  // A vulnerability scanner probing the range it's meant to scan (placeholders: its address, then its scope).
  // The same scanner probing anywhere else still alerts.
  AND NOT (CIDR_MATCH(source.ip, "198.51.100.10/32") AND CIDR_MATCH(destination.ip, "198.51.100.0/24"))
// 3 REDUCE: one row per source address: how many hosts and ports went unanswered.
| STATS targets = COUNT_DISTINCT(destination.ip), ports = COUNT_DISTINCT(destination.port),
        sample_ports = TOP(destination.port, 10, "asc"), sample_targets = TOP(destination.ip, 10, "asc"), first_seen = MIN(@timestamp)
    BY source.ip
// 4 DECIDE: the same shapes, counted on unanswered probes only. Thresholds: starting values, not yet baselined
// (baseline as for the Falcon query, grouped by source.ip).
| EVAL finding = CASE(targets >= 10 AND ports >= 10, "mixed_scan",
                      targets <= 5 AND ports >= 20, "port_scan",
                      targets >= 50, "host_sweep",
                      NULL)
| WHERE finding IS NOT NULL
// 5 ENRICH
| EVAL severity = CASE(finding == "mixed_scan", "critical", finding == "port_scan", "high", "medium")
// 6 OUTPUT
| KEEP source.ip, finding, severity, targets, ports, sample_ports, sample_targets, first_seen
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
Suppress by `host.id`, `finding` for 1h. Alerts missing a key field are not suppressed. Scans are often run several times in a row; those fold into one alert per host and shape, and a climbing count is worth reading.

## Known false positives / exclusions
Exclusions are pairs, never a whole host: a host and the one process that scans there by design. A stolen admin account, or any other process on a scanner host, still alerts.
- Vulnerability scanners, asset discovery, monitoring, backup and management servers: the host and its scanning service. The top-talkers query lists them.
- Monitoring scrapers in Kubernetes (Prometheus and similar) reach many pods on many ports in 100.64.0.0/10 or a private range: the scraper's host and process.
- Log collectors and SIEM forwarders that add reverse-DNS names to the events they ship look like a reverse-DNS sweep. DNS events carry no process name, so the pair is the host and `ptr_sweep`. The host still alerts on every connection shape.
- A process with no name (older sensors) reads `unknown`, so a pair exclusion can't match it; it alerts until the sensor is updated.
- A management script on a host you didn't expect (an admin's workstation running a PowerShell loop over many servers). That's still worth a look: it's also what an intruder does.

The standard keeps exclusions in one central list (a lookup index or file) rather than in each rule. This library has no lookups yet, so they're written inline as placeholders; when a central list exists, replace the step 5 `WHERE NOT` (and the LogScale `NOT` lines) with a lookup on host and process.

## Blind spots
- **Raw-packet scans and ping sweeps.** Falcon's connection events come from the operating system's network stack. A scanner running as admin or root that builds its own packets (nmap `-sS`, its default as admin; masscan; zmap) never makes a connection. Neither do ICMP pings or ARP requests. So the Falcon connection query sees none of them. Run without admin rights, nmap falls back to real connections and is caught. What covers the rest, and its limits:
  - **Reverse-DNS query:** ping sweeps and raw scans by tools that name each live host through the operating system's resolver (Advanced IP Scanner, PowerShell sweeps, nmap with `--system-dns`). Not nmap by default, which uses its own resolver, and nothing run with name resolution off (`-n`).
  - **Palo Alto query:** raw TCP and UDP probes that cross the firewall. It doesn't see ICMP (no port, so its gate drops it), ARP, or anything inside one subnet.
  - **D04 option B** (OpenCanary's portscan module): raw scans that touch a decoy, wherever they come from. D04 option A is built on Falcon connections and has this rule's blind spot.
  - **The name fallback:** the known scanners, unless renamed.
  - **Left over:** a renamed raw-packet scanner, or an ICMP or ARP sweep, that doesn't resolve names through the OS, inside one subnet with no decoy in it.
- Reverse lookups in uppercase (`IN-ADDR.ARPA`), which some custom resolvers send.
- **nbtscan and NetBIOS name sweeps on UDP 137**, and anything else that only uses the left-out chatter ports. They're left out because ordinary Windows traffic fills them. The name fallback matches nbtscan.
- Services on 49152 and up, and scans that only probe them.
- **`port_scan` is an approximation** of "many ports on one host": 20+ ports across at most 5 hosts. Exact per-host port counts need a second `STATS` keyed on the address. Add it only if the approximation causes false positives.
- A slow scan spread over more than the window (`--scan-delay`, `-T1`) stays under each threshold. If that's a concern, run a second copy hourly with a 65-minute lookback, baselined on 1-hour buckets (change the bucket in the baseline queries). Don't just scale the 10-minute thresholds.
- A scan split across several processes, each below the thresholds (a worm spawning one process per target). The per-process key is what keeps busy hosts from adding up; the cost is this.

## Triage
- Read `finding` and the shape: `ports` and `sample_ports` (what it was looking for), `targets` and `sample_targets` (where it looked). 445, 3389, 22 and 5985 usually come before lateral movement: check B04 on the same host for what followed.
- Run the pivot query for the process: its start (path, command line, parent, user) and everything it connected to. A shell, a script interpreter, or a binary in `Downloads`, `Temp` or `/tmp` scanning is reconnaissance. So is an IP scanner run on a server by an account that isn't IT.
- From the Palo Alto query, find the device behind `source.ip` (DHCP, Falcon, switch port). An address with no Falcon sensor is a device you don't manage.

Pivot query, from an hour before `first_seen` (the process may have started earlier) to the alert. The process's own start carries its ID as `TargetProcessId`; its connections and lookups carry it as `ContextProcessId`. For a `ptr_sweep`, this is where the process name comes from:
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
- `nmap -sT -p 1-1000 <lab host>`: `port_scan`.
- `nmap -sT --top-ports 20 <lab /24>`, with 10 or more live hosts in it: `mixed_scan`.
- `nmap -sT -Pn -p 445 <lab /24>`: `host_sweep`.
- A PowerShell loop testing port 445 across a lab /24 (`Test-NetConnection` in a `foreach`): `host_sweep`, with no scanner involved.
- `nmap -sS <lab /24>` as admin: nothing from the Falcon connection query, by design (see Blind spots). The name fallback alerts, and the Palo Alto query does if the scan crosses the firewall.
- `nmap -sL --system-dns <lab /24>`: `ptr_sweep`. A list scan sends nothing to the hosts and only looks up all 256 names, so it tests the DNS query on its own.
- `nmap -sL <lab /24>` (nmap's own resolver): check whether any `dnsrequest` events appear from the lab host. If none do, nmap's default sweeps are only seen by the other queries.
- Advanced IP Scanner on a lab subnet: the name fallback, `host_sweep` or `mixed_scan` from the ports it probes on each host, and `ptr_sweep` when 50+ hosts answer.
- Run the pivot query on one of the alerts and confirm it returns the scanner's start event: that proves the process ID links.
