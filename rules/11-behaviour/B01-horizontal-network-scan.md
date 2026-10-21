---
id: B01
name: Internal scanning by behaviour - a mixed scan, a port scan of a few hosts or a sweep of many hosts from one process, optionally a reverse-DNS sweep, with known scanners by name as a fallback (Falcon)
category: behaviour
status: todo
language: esql
index: logs-yourorg-crowdstrike-data-default*
mitre: [T1046, T1018]
data_source: CrowdStrike FDR NetworkConnectIP4 and ProcessRollup2 (detection A); plus DnsRequest (detection B)
suppression:
  fields: [host.id, finding]
  duration: 1h
  missing_fields: do_not_suppress
---
## Why this is behavioural and high fidelity
**One question:** is one process scanning the internal network? Whatever runs the scan (nmap, an IP scanner, a PowerShell loop, an implant's built-in scanner, a worm), it has one of a few shapes. The rule counts what each process instance (host + process ID) did in the window, so one busy process can't lend its count to another, then classifies it, most specific first:

| `finding` | What the process did in the window | Look-alikes |
|---|---|---|
| `mixed_scan` | Tried 10+ internal hosts on 10+ ports | Almost only vulnerability scanners, which are excluded by host + process |
| `port_scan` | Tried 20+ ports on fewer than 10 hosts (10+ hosts on 10+ ports is a mixed scan) | Very few: normal applications rarely touch 20 service ports on one host |
| `host_sweep` | Tried 50+ internal hosts | Management, monitoring, domain controllers, backup and vulnerability scanners |
| `ptr_sweep` (detection B only) | Looked up the names of 50+ internal addresses | IP address management, monitoring, log collectors that name the addresses they ship |
| `named_scanner` | Started as a known scanner, with none of the shapes above | The network and security teams' own tools, excluded by host + tool |

**Activity first, filename fallback.** The name catches what the behaviour can't see: raw-packet scans (nmap `-sS` as admin, masscan) that make no connections, and runs below the thresholds. The behaviour catches what the name can't: a renamed copy. Both are grouped on the same process, so a known scanner that also shows a shape is one alert, with the shape as `finding` and `named_starts` above zero.

**Two detections. Deploy one of them.**
- **A: connections, with the name fallback.** The cheaper of the two.
- **B: connections and DNS, with the name fallback.** Everything A finds, plus `ptr_sweep`. Tools that resolve names through the operating system (Advanced IP Scanner, PowerShell sweeps, nmap with `--system-dns`) look up each host they find. That shows a ping sweep even when its packets make no connections. The DNS half stays cheap: it only reads reverse lookups of internal ranges, never the rest of DNS (see "What it costs").

Both follow the detection standard ([ES|QL](../../docs/DETECTION-STRUCTURE-ESQL.md), [CQL](../../docs/DETECTION-STRUCTURE-CQL.md)), with each stage numbered to match it. The gate is only filters the index answers, each scoped to its own event type, with the process ID required. One reduce, keyed on host and Falcon process ID. Every threshold in one place. Exclusions as host + process pairs on the survivors, never a whole host.

## Detection A: connections, with the name fallback
Run every 10 minutes with a 12-minute lookback.
```esql
FROM logs-yourorg-crowdstrike-data-default*
// 1 GATE: each event type's own filters, in its own branch.
// Connections to internal addresses (private ranges and 100.64.0.0/10, the shared range some Kubernetes and cloud
// networks use) on service ports. Chatter ports (DNS, NTP, NetBIOS datagrams, SSDP, mDNS, LLMNR) and dynamic RPC
// (49152 and up) left out.
// Filename fallback: a known scanner starting, by exact name or prefix, which the index answers, so no other process
// start is read. Every row must carry its process ID.
| WHERE ((event.action == "networkconnectip4" AND destination.port < 49152
          AND NOT destination.port IN (53, 123, 137, 138, 1900, 5353, 5355)
          AND CIDR_MATCH(destination.ip, "10.0.0.0/8", "100.64.0.0/10", "172.16.0.0/12", "192.168.0.0/16")
          AND data.ContextProcessId IS NOT NULL)
         OR (event.action == "processrollup2" AND data.TargetProcessId IS NOT NULL
             AND (process.name IN ("nmap.exe", "nmap", "masscan.exe", "masscan", "rustscan.exe", "rustscan", "zmap", "naabu.exe",
                                   "naabu", "advanced_ip_scanner.exe", "advanced_port_scanner.exe", "netscan.exe")
                  OR process.name LIKE "nbtscan*" OR process.name LIKE "fscan*" OR process.name LIKE "ipscan*")))
  AND host.id IS NOT NULL
// 2 SHAPE: one process ID across both events: the process's own ID on its start, the ID it acts under on its connections.
| EVAL process.entity_id = CASE(event.action == "processrollup2", data.TargetProcessId, data.ContextProcessId)
// 3 REDUCE: one row per process instance: how many internal hosts and ports it tried, with a capped sample of each, and
// whether it started as a known scanner.
| STATS targets = COUNT_DISTINCT(destination.ip) WHERE event.action == "networkconnectip4",
        ports = COUNT_DISTINCT(destination.port) WHERE event.action == "networkconnectip4",
        named_starts = COUNT(*) WHERE event.action == "processrollup2",
        sample_ports = TOP(destination.port, 10, "asc") WHERE event.action == "networkconnectip4",
        sample_targets = TOP(destination.ip, 10, "asc") WHERE event.action == "networkconnectip4",
        started_as = VALUES(process.name) WHERE event.action == "processrollup2",
        connected_as = VALUES(data.ContextBaseFileName), host.name = VALUES(host.name), first_seen = MIN(@timestamp)
    BY host.id, process.entity_id
// 4 DECIDE: classify, most specific first, so port_scan needs no host cap (mixed_scan has already taken 10+ hosts);
// the name only when no shape fired. Every threshold lives here.
// Thresholds: starting values, not yet baselined. Replace each from the baseline and top talkers (below), and record
// the date range measured in this comment.
| EVAL finding = CASE(targets >= 10 AND ports >= 10, "mixed_scan",
                      ports >= 20, "port_scan",
                      targets >= 50, "host_sweep",
                      named_starts > 0, "named_scanner",
                      NULL)
| WHERE finding IS NOT NULL
// 5 ENRICH: the name from the start event, else from the connections (older sensors send none: "unknown"). Drop the
// host + process pairs that scan by design (placeholders; a tool that reads "unknown" needs a host + finding pair
// instead).
| EVAL process.name = COALESCE(MV_MIN(started_as), MV_MIN(connected_as), "unknown")
| WHERE NOT ((host.id == "<vuln_scanner_aid>" AND process.name == "<scanner_process>")
          OR (host.id == "<monitoring_aid>" AND process.name == "<monitoring_process>")
          OR (host.id == "<network_team_aid>" AND process.name == "<approved_scanner>"))
// 6 OUTPUT: the entity, the decision counts and a short sample. The detail is in the triage pivot query.
| KEEP host.id, host.name, finding, process.name, process.entity_id, named_starts, targets, ports, sample_ports,
       sample_targets, first_seen
```
```logscale
#event_simpleName=/^(NetworkConnectIP4|ProcessRollup2)$/
// 1 GATE + 2 SHAPE: each event type's own filters in its own branch, then pid: the process's own ID on its start, the
// ID it acts under on its connections.
| aid=*
// Deliberately no * branch: this case is the gate, and an event matching neither branch is dropped. Don't add one.
| case {
    // Connections to internal addresses on service ports (chatter ports and dynamic RPC left out).
    #event_simpleName=NetworkConnectIP4 ContextProcessId=*
      | cidr(RemoteAddressIP4, subnet=["10.0.0.0/8", "100.64.0.0/10", "172.16.0.0/12", "192.168.0.0/16"])
      | RemotePort < 49152
      | !in(field="RemotePort", values=["53", "123", "137", "138", "1900", "5353", "5355"])
      | pid := ContextProcessId;
    // Filename fallback: a known scanner starting, by exact name or prefix, any case.
    #event_simpleName=ProcessRollup2 TargetProcessId=*
      | in(field="FileName", values=["nmap", "nmap.exe", "masscan", "masscan.exe", "rustscan", "rustscan.exe", "zmap", "naabu",
                                     "naabu.exe", "advanced_ip_scanner.exe", "advanced_port_scanner.exe", "netscan.exe",
                                     "nbtscan*", "fscan*", "ipscan*"], ignoreCase=true)
      | pid := TargetProcessId | named := 1;
  }
// 3 REDUCE: one row per process instance: hosts and ports tried, and whether it started as a known scanner.
| groupBy([aid, pid], function=[count(RemoteAddressIP4, distinct=true, as=targets), count(RemotePort, distinct=true, as=ports),
                                count(named, as=named_starts), min(@timestamp, as=first_seen),
                                collect([ComputerName, FileName, ContextBaseFileName])], limit=max)
// 4 DECIDE: classify, most specific first, so port_scan needs no host cap (mixed_scan has already taken 10+ hosts);
// the name only when no shape fired.
// Thresholds: starting values, not yet baselined. Replace each from the baseline and top talkers (below).
| case {
    targets >= 10 ports >= 10 | finding := "mixed_scan";
    ports >= 20 | finding := "port_scan";
    targets >= 50 | finding := "host_sweep";
    named_starts >= 1 | finding := "named_scanner";
    * | finding := "none";
  }
| finding != "none"
// 5 ENRICH: the name from the start event, else from the connections; then drop the host + process pairs that scan by
// design. Placeholders.
| case { FileName=* | process_name := FileName; ContextBaseFileName=* | process_name := ContextBaseFileName; * | process_name := "unknown"; }
| NOT (aid="<vuln_scanner_aid>" AND process_name="<scanner_process>")
| NOT (aid="<monitoring_aid>" AND process_name="<monitoring_process>")
| NOT (aid="<network_team_aid>" AND process_name="<approved_scanner>")
// 6 OUTPUT
| select([aid, ComputerName, finding, process_name, pid, named_starts, targets, ports, first_seen])
```

## Detection B: connections and DNS, with the name fallback
Run every 10 minutes with a 12-minute lookback. Detection A plus a third branch for reverse lookups, all grouped on the same process.
```esql
FROM logs-yourorg-crowdstrike-data-default*
// 1 GATE: each event type's own filters, in its own branch. Connections and the filename fallback as in detection A;
// reverse lookups by exact record type (12, PTR), which the index answers, so the rest of DNS is never read. Every row
// must carry its process ID.
| WHERE ((event.action == "networkconnectip4" AND destination.port < 49152
          AND NOT destination.port IN (53, 123, 137, 138, 1900, 5353, 5355)
          AND CIDR_MATCH(destination.ip, "10.0.0.0/8", "100.64.0.0/10", "172.16.0.0/12", "192.168.0.0/16")
          AND data.ContextProcessId IS NOT NULL)
         OR (event.action == "dnsrequest" AND data.RequestType == "12" AND data.ContextProcessId IS NOT NULL)
         OR (event.action == "processrollup2" AND data.TargetProcessId IS NOT NULL
             AND (process.name IN ("nmap.exe", "nmap", "masscan.exe", "masscan", "rustscan.exe", "rustscan", "zmap", "naabu.exe",
                                   "naabu", "advanced_ip_scanner.exe", "advanced_port_scanner.exe", "netscan.exe")
                  OR process.name LIKE "nbtscan*" OR process.name LIKE "fscan*" OR process.name LIKE "ipscan*")))
  AND host.id IS NOT NULL
// 2 SHAPE: one process ID across all three events: its own ID on its start, the ID it acts under otherwise.
| EVAL process.entity_id = CASE(event.action == "processrollup2", data.TargetProcessId, data.ContextProcessId)
// 3 REDUCE: one row per process instance. Conditional counts keep the events apart in one pass. The RLIKE keeps
// reverse lookups of internal ranges only, and runs on the reverse lookups the gate let through, never on all of DNS.
| STATS targets = COUNT_DISTINCT(destination.ip) WHERE event.action == "networkconnectip4",
        ports = COUNT_DISTINCT(destination.port) WHERE event.action == "networkconnectip4",
        ptr_names = COUNT_DISTINCT(data.DomainName) WHERE data.DomainName RLIKE
          ".*\\.(10|(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\\.100|(1[6-9]|2[0-9]|3[01])\\.172|168\\.192)\\.in-addr\\.arpa\\.?",
        named_starts = COUNT(*) WHERE event.action == "processrollup2",
        sample_ports = TOP(destination.port, 10, "asc") WHERE event.action == "networkconnectip4",
        sample_targets = TOP(destination.ip, 10, "asc") WHERE event.action == "networkconnectip4",
        started_as = VALUES(process.name) WHERE event.action == "processrollup2",
        connected_as = VALUES(data.ContextBaseFileName), host.name = VALUES(host.name), first_seen = MIN(@timestamp)
    BY host.id, process.entity_id
// 4 DECIDE: classify, most specific first, so port_scan needs no host cap (mixed_scan has already taken 10+ hosts);
// the name only when no shape fired. Every threshold lives here.
// Thresholds: starting values, not yet baselined. Replace each from the baseline and top talkers (below), and record
// the date range measured in this comment.
| EVAL finding = CASE(targets >= 10 AND ports >= 10, "mixed_scan",
                      ports >= 20, "port_scan",
                      targets >= 50, "host_sweep",
                      ptr_names >= 50, "ptr_sweep",
                      named_starts > 0, "named_scanner",
                      NULL)
| WHERE finding IS NOT NULL
// 5 ENRICH: the name from the start event, else from the connections (DNS events and older sensors carry none:
// "unknown"; the pivot query finds it). Drop the host + process pairs that scan by design, and log collectors for the
// reverse-DNS finding only (placeholders).
| EVAL process.name = COALESCE(MV_MIN(started_as), MV_MIN(connected_as), "unknown")
| WHERE NOT ((host.id == "<vuln_scanner_aid>" AND process.name == "<scanner_process>")
          OR (host.id == "<monitoring_aid>" AND process.name == "<monitoring_process>")
          OR (host.id == "<network_team_aid>" AND process.name == "<approved_scanner>")
          OR (host.id == "<log_collector_aid>" AND finding == "ptr_sweep"))
// 6 OUTPUT: the entity, the decision counts and a short sample. The detail is in the triage pivot query.
| KEEP host.id, host.name, finding, process.name, process.entity_id, named_starts, targets, ports, ptr_names,
       sample_ports, sample_targets, first_seen
```
```logscale
#event_simpleName=/^(NetworkConnectIP4|DnsRequest|ProcessRollup2)$/
// 1 GATE + 2 SHAPE: each event type's own filters in its own branch, then pid: the process's own ID on its start, the
// ID it acts under otherwise.
| aid=*
// Deliberately no * branch: this case is the gate, and an event matching neither branch is dropped. Don't add one.
| case {
    // Connections to internal addresses on service ports (chatter ports and dynamic RPC left out).
    #event_simpleName=NetworkConnectIP4 ContextProcessId=*
      | cidr(RemoteAddressIP4, subnet=["10.0.0.0/8", "100.64.0.0/10", "172.16.0.0/12", "192.168.0.0/16"])
      | RemotePort < 49152
      | !in(field="RemotePort", values=["53", "123", "137", "138", "1900", "5353", "5355"])
      | pid := ContextProcessId;
    // Reverse lookups first (record type 12, an exact match that drops almost every DNS event), then the internal
    // ranges by regex on the few that are left.
    #event_simpleName=DnsRequest RequestType=12 ContextProcessId=*
      | DomainName=/\.(10|(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.100|(1[6-9]|2\d|3[01])\.172|168\.192)\.in-addr\.arpa\.?$/i
      | pid := ContextProcessId;
    // Filename fallback: a known scanner starting, by exact name or prefix, any case.
    #event_simpleName=ProcessRollup2 TargetProcessId=*
      | in(field="FileName", values=["nmap", "nmap.exe", "masscan", "masscan.exe", "rustscan", "rustscan.exe", "zmap", "naabu",
                                     "naabu.exe", "advanced_ip_scanner.exe", "advanced_port_scanner.exe", "netscan.exe",
                                     "nbtscan*", "fscan*", "ipscan*"], ignoreCase=true)
      | pid := TargetProcessId | named := 1;
  }
// 3 REDUCE: one row per process instance. count(field) only counts events that have the field, so each event type is
// counted apart.
| groupBy([aid, pid], function=[count(RemoteAddressIP4, distinct=true, as=targets), count(RemotePort, distinct=true, as=ports),
                                count(DomainName, distinct=true, as=ptr_names), count(named, as=named_starts),
                                min(@timestamp, as=first_seen), collect([ComputerName, FileName, ContextBaseFileName])], limit=max)
// 4 DECIDE: classify, most specific first, so port_scan needs no host cap (mixed_scan has already taken 10+ hosts);
// the name only when no shape fired.
// Thresholds: starting values, not yet baselined. Replace each from the baseline and top talkers (below).
| case {
    targets >= 10 ports >= 10 | finding := "mixed_scan";
    ports >= 20 | finding := "port_scan";
    targets >= 50 | finding := "host_sweep";
    ptr_names >= 50 | finding := "ptr_sweep";
    named_starts >= 1 | finding := "named_scanner";
    * | finding := "none";
  }
| finding != "none"
// 5 ENRICH: the name from the start event, else from the connections; then drop the host + process pairs that scan by
// design, and log collectors for the reverse-DNS finding only. Placeholders.
| case { FileName=* | process_name := FileName; ContextBaseFileName=* | process_name := ContextBaseFileName; * | process_name := "unknown"; }
| NOT (aid="<vuln_scanner_aid>" AND process_name="<scanner_process>")
| NOT (aid="<monitoring_aid>" AND process_name="<monitoring_process>")
| NOT (aid="<network_team_aid>" AND process_name="<approved_scanner>")
| NOT (aid="<log_collector_aid>" AND finding="ptr_sweep")
// 6 OUTPUT
| select([aid, ComputerName, finding, process_name, pid, named_starts, targets, ports, ptr_names, first_seen])
```

**What it costs.**
- **The name fallback (A and B):** in Elastic, the names are exact or prefix matches the index answers, so only the starts of those tools are read. In LogScale, each run reads the window's `ProcessRollup2` events, far fewer than connections, and tests them with an exact `in()` match, not a regex.
- **The DNS half (B):** what made DNS heavy before was checking every lookup's name with a regex. Both versions now test the record type first, an exact match, and only reverse lookups (a small share of DNS) reach the regex and the grouping. In Elastic, the index answers the record-type match, so the rest of DNS is never read; the discovery query shows how many reverse lookups that is. This needs `data.RequestType` to be indexed in your mapping, not a runtime field. In LogScale, each run reads the window's `DnsRequest` events, but the exact `RequestType` test drops almost all of them.

## Rule settings
| | Detection A | Detection B |
|---|---|---|
| Interval / lookback | 10 min / 12 min | 10 min / 12 min |
| Suppression | `host.id` (`aid`), `finding` for 1h | `host.id` (`aid`), `finding` for 1h |

The schedule is the window: every count is "in the last 10 minutes". The two extra minutes of lookback absorb ingest lag; the overlap between runs folds into one alert through suppression. Because `finding` is in the suppression key, a sweep that grows into a mixed scan raises a new alert.

## Telemetry assumptions
- **Connections:** `networkconnectip4` with `destination.ip` and `destination.port`. Falcon records connections made through the operating system's network stack; raw-packet scans don't produce them.
- **Process starts:** `processrollup2` with `process.name` (the file name) and `data.TargetProcessId`.
- **Reverse lookups (B):** `dnsrequest` with Falcon's raw fields `data.RequestType` (12 is PTR) and `data.DomainName`, which may end in a dot; the regex allows for it. Names are matched in lowercase, which is how Windows and Linux resolvers send them. The rule doesn't use ECS `dns.question.*`, which a pipeline that doesn't map DNS to ECS won't have. Falcon records lookups made through the operating system's resolver. nmap uses its own resolver unless run with `--system-dns`, so its lookups may never appear; the Test section checks this.
- **The process ID:** a process's start carries its ID as `data.TargetProcessId`; its connections and lookups carry the same value as `data.ContextProcessId`. Step 2 puts them in one column. If your pipeline already sets `process.entity_id` that way on all three events, gate on it and drop step 2.
- **Process name:** `process.name` on starts, `data.ContextBaseFileName` on connections (older sensors don't send it). DNS events never carry one.

Confirm them over the last hour before deploying. The `with_` counts should be close to `events` on the rows where the field belongs, and the `dnsrequest` row's `events` is roughly what B's DNS half reads per hour:
```esql
FROM logs-yourorg-crowdstrike-data-default*
| WHERE event.action IN ("networkconnectip4", "processrollup2") OR (event.action == "dnsrequest" AND data.RequestType == "12")
| STATS events = COUNT(*), hosts = COUNT_DISTINCT(host.id), with_context_pid = COUNT(data.ContextProcessId),
        with_target_pid = COUNT(data.TargetProcessId), with_address = COUNT(destination.ip), with_port = COUNT(destination.port),
        with_name = COUNT(data.ContextBaseFileName), with_process_name = COUNT(process.name), with_domain = COUNT(data.DomainName)
    BY event.action
```
```logscale
#event_simpleName=/^(NetworkConnectIP4|DnsRequest|ProcessRollup2)$/
| groupBy([#event_simpleName, event_platform], function=[count(), count(aid, distinct=true, as=hosts),
                                                        count(ContextProcessId, as=with_context_pid), count(TargetProcessId, as=with_target_pid),
                                                        count(RemoteAddressIP4, as=with_address), count(ContextBaseFileName, as=with_name),
                                                        count(FileName, as=with_file_name), count(RequestType, as=with_request_type)],
          limit=max)
```
If the ES|QL query returns no `dnsrequest` row but LogScale shows reverse lookups, check how `data.RequestType` is stored. Raw FDR values are strings, hence `== "12"`; if your mapping made it a number, use `== 12`. This shows the stored values and whether `data.DomainName` is there (one hour of DNS, grouped by a handful of record types):
```esql
FROM logs-yourorg-crowdstrike-data-default*
| WHERE event.action == "dnsrequest"
| STATS lookups = COUNT(*), with_domain = COUNT(data.DomainName), with_pid = COUNT(data.ContextProcessId) BY data.RequestType
| SORT lookups DESC
```
```logscale
#event_simpleName=DnsRequest
| groupBy([RequestType], function=[count(as=lookups), count(DomainName, as=with_domain), count(ContextProcessId, as=with_pid)], limit=max)
```
Don't gate on `LIKE "*.in-addr.arpa*"` instead: a leading wildcard reads every lookup.

## Baseline and threshold source
The thresholds are starting values, not measurements. Measure each shape before enabling, and write the result next to the threshold; the name fallback has no threshold. These queries run detection B's connection and DNS stages with the window rebuilt as 10-minute buckets; the connection counts are the same as A's. Run them over one day at a time (they keep a row for every process in every window, which is heavy), on at least five working days, and record whether patch nights or a scheduled scan fell in the range.
```esql
FROM logs-yourorg-crowdstrike-data-default*
| WHERE ((event.action == "networkconnectip4" AND destination.port < 49152
          AND NOT destination.port IN (53, 123, 137, 138, 1900, 5353, 5355)
          AND CIDR_MATCH(destination.ip, "10.0.0.0/8", "100.64.0.0/10", "172.16.0.0/12", "192.168.0.0/16"))
         OR (event.action == "dnsrequest" AND data.RequestType == "12"))
  AND host.id IS NOT NULL AND data.ContextProcessId IS NOT NULL
// The rule's 10-minute window, rebuilt as a bucket so a whole day can be measured in one search.
| EVAL win = DATE_TRUNC(10 minutes, @timestamp)
| STATS targets = COUNT_DISTINCT(destination.ip) WHERE event.action == "networkconnectip4",
        ports = COUNT_DISTINCT(destination.port) WHERE event.action == "networkconnectip4",
        ptr_names = COUNT_DISTINCT(data.DomainName) WHERE data.DomainName RLIKE
          ".*\\.(10|(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\\.100|(1[6-9]|2[0-9]|3[01])\\.172|168\\.192)\\.in-addr\\.arpa\\.?",
        process.name = VALUES(data.ContextBaseFileName)
    BY host.id, data.ContextProcessId, win
| EVAL mixed = LEAST(targets, ports), process.name = COALESCE(MV_MIN(process.name), "unknown")
// Second STATS, baseline only: each shape's metric across the windows where that activity happened at all (counting
// zeros would hide the tail). For top talkers instead, replace this STATS with:
//   STATS peak_mixed = MAX(mixed), peak_ports_few_hosts = MAX(ports) WHERE targets < 10, peak_targets = MAX(targets),
//         peak_ptr = MAX(ptr_names), windows = COUNT(*) BY host.id, process.name
//   | SORT peak_targets DESC | LIMIT 50
| STATS windows = COUNT(*),
        mixed_scan_p95 = PERCENTILE(mixed, 95) WHERE mixed > 0, mixed_scan_p99 = PERCENTILE(mixed, 99) WHERE mixed > 0,
        mixed_scan_max = MAX(mixed),
        port_scan_p95 = PERCENTILE(ports, 95) WHERE targets > 0 AND targets < 10,
        port_scan_p99 = PERCENTILE(ports, 99) WHERE targets > 0 AND targets < 10,
        port_scan_max = MAX(ports) WHERE targets > 0 AND targets < 10,
        host_sweep_p95 = PERCENTILE(targets, 95) WHERE targets > 0, host_sweep_p99 = PERCENTILE(targets, 99) WHERE targets > 0,
        host_sweep_max = MAX(targets),
        ptr_sweep_p95 = PERCENTILE(ptr_names, 95) WHERE ptr_names > 0, ptr_sweep_p99 = PERCENTILE(ptr_names, 99) WHERE ptr_names > 0,
        ptr_sweep_max = MAX(ptr_names)
```
```logscale
#event_simpleName=/^(NetworkConnectIP4|DnsRequest)$/
| aid=* ContextProcessId=*
// Deliberately no * branch: the same connection and DNS gate as detection B.
| case {
    #event_simpleName=NetworkConnectIP4
      | cidr(RemoteAddressIP4, subnet=["10.0.0.0/8", "100.64.0.0/10", "172.16.0.0/12", "192.168.0.0/16"])
      | RemotePort < 49152
      | !in(field="RemotePort", values=["53", "123", "137", "138", "1900", "5353", "5355"]);
    #event_simpleName=DnsRequest RequestType=12
      | DomainName=/\.(10|(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.100|(1[6-9]|2\d|3[01])\.172|168\.192)\.in-addr\.arpa\.?$/i;
  }
// The rule's 10-minute window, rebuilt as a bucket so a whole day can be measured in one search.
| win := math:floor(@timestamp / 600000)
| groupBy([aid, ContextProcessId, win], function=[count(RemoteAddressIP4, distinct=true, as=targets), count(RemotePort, distinct=true, as=ports),
                                                  count(DomainName, distinct=true, as=ptr_names), collect([ContextBaseFileName])],
          limit=max)
// Baseline: one shape at a time, over the windows where it happened. As written, host_sweep (targets).
// port_scan: filter "targets >= 1 targets <= 9" and measure ports. mixed_scan: "ports >= 10", measure targets.
// ptr_sweep: "ptr_names >= 1", measure ptr_names. For top talkers instead, replace the last two lines with:
//   default(field=ContextBaseFileName, value="unknown")
//   | groupBy([aid, ContextBaseFileName], function=[max(targets, as=peak_targets), max(ports, as=peak_ports),
//             max(ptr_names, as=peak_ptr), count(as=windows)], limit=max)
//   | sort(peak_targets, order=desc, limit=50)
| targets >= 1
| [count(), percentile(field=targets, percentiles=[50, 95, 99]), max(targets)]
```
**Setting each threshold.** A p99 over thousands of process-windows doesn't show that the same few SCCM, monitoring or backup processes peak high every day, and those are what the threshold has to clear. So run the top-talkers view too. It's keyed on the process name rather than its ID, so a service that restarts still adds up, and each row is an exclusion pair ready to use.
1. Exclude the legitimate top talkers as host + process pairs (step 5).
2. Set the threshold just above the highest peak left, with a buffer for ingest lag (a window can hold up to 12 minutes of events).
3. Check it against the p99.

A peak equal to a subnet's size (254, 256) is a sweep, not normal activity: find out what it was before you set anything above it. A reverse-DNS sweep only names the hosts that answer, so if your subnets are sparsely used, `ptr_sweep` may need a threshold below 50.

## Suppression
Suppress by `host.id`, `finding` for 1h. Alerts missing a key field are not suppressed. Scans are often run several times in a row; those fold into one alert per host and finding, and a climbing count is worth reading.

## Known false positives / exclusions
Exclusions are pairs, never a whole host: a host and the one process that scans there by design. A stolen admin account, or any other process on a scanner host, still alerts.
- Vulnerability scanners, asset discovery, monitoring, backup and management servers: the host and its scanning service. The top-talkers view lists them.
- The network and security teams' own scanners (nmap, Advanced IP Scanner): their hosts and that tool.
- Monitoring scrapers in Kubernetes (Prometheus and similar) reach many pods on many ports in 100.64.0.0/10 or a private range: the scraper's host and process.
- Log collectors and SIEM forwarders that add reverse-DNS names to the events they ship look like a reverse-DNS sweep (B). DNS events carry no process name, so the pair is the host and `ptr_sweep`. The host still alerts on every connection shape.
- **Name pairs fail when the name is `unknown`.** A tool whose connections come from a sensor that doesn't send `ContextBaseFileName` reads `unknown`, and a host + process exclusion never matches it. Spot-check in the top-talkers view that each tool you exclude resolves to a name. If it doesn't, exclude it on host + finding instead, as for log collectors.
- A management script on a host you didn't expect (an admin's workstation running a PowerShell loop over many servers). That's still worth a look: it's also what an intruder does.

The standard keeps exclusions in one central list (a lookup index or file) rather than in each rule. This library has no lookups yet, so they're written inline as placeholders; when a central list exists, replace the step 5 `WHERE NOT` (and the LogScale `NOT` lines) with a lookup on host and process.

## Blind spots
- **Renamed raw-packet scanners, and ping sweeps.** A scanner running as admin or root that builds its own packets (nmap `-sS`, its default as admin; masscan; zmap) never makes a connection. Neither do ICMP pings or ARP requests. Run without admin rights, nmap falls back to real connections and is caught by its shape.
  - **`named_scanner`** catches the known tools by name, whatever they send. It misses renamed copies.
  - **Detection B** catches a sweep when the tool names each live host through the operating system's resolver (Advanced IP Scanner, PowerShell sweeps, nmap with `--system-dns`). It doesn't catch nmap by default, which uses its own resolver, or anything run with name resolution off (`-n`).
  - **D04 option B** (OpenCanary's portscan module) catches raw scans that touch a decoy, wherever they come from.
  - **Uncovered:** a renamed raw-packet scanner, or a ping sweep by a tool not on the list that doesn't resolve names through the OS, that touches no decoy.
- **A known scanner started before the lookback.** Only its start event carries the name, so a long-running scan is named in the first run's alert only; later runs judge it by its shape.
- **nbtscan and NetBIOS name sweeps on UDP 137**, and anything else that only uses the left-out chatter ports. They're left out because ordinary Windows traffic fills them. nbtscan itself is caught by name.
- Services on 49152 and up, and scans that only probe them.
- **`port_scan` is an approximation** of "many ports on one host": 20+ ports across fewer than 10 hosts. Exact per-host port counts need a second `STATS` keyed on the address. Add it only if the approximation causes false positives.
- A slow scan spread over more than the window (`--scan-delay`, `-T1`) stays under each threshold. If that's a concern, run a second copy hourly with a 65-minute lookback, baselined on 1-hour buckets (change the bucket in the baseline queries). Don't just scale the 10-minute thresholds.
- A scan split across several processes, each below the thresholds (a worm spawning one process per target). The per-process key is what keeps busy hosts from adding up; the cost is this.
- Reverse lookups in uppercase (`IN-ADDR.ARPA`), which some custom resolvers send (B). In ES|QL, scanner names in a different case from how they ship (`NMAP.EXE`); LogScale ignores case.

## Triage
- Read `finding` and the shape: `ports` and `sample_ports` (what it was looking for), `targets` and `sample_targets` (where it looked). 445, 3389, 22 and 5985 usually come before lateral movement: check B04 on the same host for what followed. `named_starts` above zero means it's a known scanner as well.
- Run the pivot query for the process: its start (path, command line, parent, user) and everything it connected to or looked up. A shell, a script interpreter, or a binary in `Downloads`, `Temp` or `/tmp` scanning is reconnaissance. So is an IP scanner run on a server by an account that isn't IT.

Pivot query, from an hour before `first_seen` (the process may have started earlier) to the alert, with the alert's `process.entity_id` (`pid` in LogScale):
```esql
FROM logs-yourorg-crowdstrike-data-default*
| WHERE host.id == "<host.id>"
  AND (data.TargetProcessId == "<process.entity_id>" OR data.ContextProcessId == "<process.entity_id>")
  AND event.action IN ("processrollup2", "syntheticprocessrollup2", "networkconnectip4", "dnsrequest")
| KEEP @timestamp, event.action, user.name, process.executable, process.command_line, process.parent.name, destination.ip,
       destination.port, data.DomainName
| SORT @timestamp ASC
```
```logscale
#event_simpleName=/^(ProcessRollup2|SyntheticProcessRollup2|NetworkConnectIP4|DnsRequest)$/ aid="<aid>"
| TargetProcessId="<pid>" or ContextProcessId="<pid>"
| select([@timestamp, #event_simpleName, UserName, ImageFileName, CommandLine, ParentBaseFileName, RemoteAddressIP4, RemotePort, DomainName])
```

## Test
From a lab host:
- `nmap -sT -p 1-1000 <lab host>`: `port_scan`, with `named_starts` 1 (A and B).
- `nmap -sT --top-ports 20 <lab /24>`, with 10 or more live hosts in it: `mixed_scan` (A and B).
- `nmap -sT -Pn -p 445 <lab /24>`: `host_sweep` (A and B).
- `nmap -sS <lab /24>` as admin: `named_scanner` (A and B). Then the same with the binary renamed: nothing, by design (see Blind spots).
- A PowerShell loop testing port 445 across a lab /24 (`Test-NetConnection` in a `foreach`): `host_sweep`, with no scanner involved.
- `nmap -sL --system-dns <lab /24>`: `ptr_sweep` (B). A list scan sends nothing to the hosts and only looks up all 256 names, so it tests the DNS half on its own.
- `nmap -sn <lab /24>` (a ping sweep with nmap's own resolver): check whether any `dnsrequest` events appear from the lab host. If none do, `ptr_sweep` is not nmap coverage on your sensors, only coverage of tools that use the system resolver.
- Advanced IP Scanner on a lab subnet: `host_sweep` or `mixed_scan` from the ports it probes, `ptr_sweep` (B) when 50+ hosts answer, or `named_scanner` if neither.
- Run the pivot query on one of the alerts and confirm it returns the scanner's start event: that proves the process ID links.
