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
Any internal scan, whatever runs it (nmap, masscan, an IP scanner, a PowerShell loop, an implant's built-in scanner, a worm), does one of three things. The rule looks for each, per process instance (host + process ID), so one busy process can't lend its count to another and a host's processes are never lumped together:

| `finding` | What the process did in the window | Why it's a scan |
|---|---|---|
| port scan of one or a few hosts | Tried 30+ ports, on at most 5 internal hosts | Nothing legitimate tries 30 ports on a handful of machines |
| sweep of many hosts | Tried 50+ internal hosts, or 10+ hosts on 10+ ports | A hunt for one service (SMB, RDP, SSH, WinRM) across subnets, or a mixed scan |
| reverse-DNS sweep of internal addresses | Looked up the names of 50+ internal addresses | Scanners name the hosts they find. The lookups go through the normal resolver, so this shows even when the scan itself sends raw packets that Falcon doesn't record as connections |

**Kept cheap on purpose.** DNS and internal connections are the busiest events in FDR, so the query filters on indexed values before doing any work, and counts once per process:
- Internal connections only, minus the ports that make up most internal chatter and aren't how a scan looks for services: DNS, NTP, NetBIOS datagrams, SSDP, mDNS, LLMNR, and the dynamic RPC range (49152 and up), where Windows clients reach a server's RPC services.
- Reverse lookups matched on their exact registered domain (`10.in-addr.arpa` and so on), not by searching every lookup name.
- Sample lists capped at ten values.

**Exclusions:** the hosts that scan or resolve names by design, by Falcon agent ID (placeholders).

**The firewall sees what Falcon can't.** The Palo Alto query below starts from sessions that got nothing back: denied, or never completed. Scans are mostly that, because they hit closed ports and empty addresses. Monitoring and management servers get answers, so they rarely pile up dozens of unanswered probes, and normal traffic barely enters the query. It also covers scans from devices without Falcon (a rogue laptop, a compromised appliance) and raw-packet scans, but only between zones the firewall sits between.

## Query
Run every 10 minutes with a 12-minute lookback.
```esql
FROM logs-yourorg-crowdstrike-data-default*
// Cheap, indexed anchors: connections to internal addresses on service ports (chatter ports and dynamic RPC left out),
// and reverse lookups of internal ranges (resolver traffic, so visible even when the scan sends raw packets).
| WHERE ((event.action == "networkconnectip4" AND destination.port < 49152
          AND NOT destination.port IN (53, 123, 137, 138, 1900, 5353, 5355)
          AND CIDR_MATCH(destination.ip, "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
         OR (event.action == "dnsrequest"
             AND dns.question.registered_domain IN ("10.in-addr.arpa", "172.in-addr.arpa", "192.in-addr.arpa")))
  // vulnerability scanners, asset discovery, monitoring, name-resolving log collectors, network and security teams (placeholders)
  AND NOT host.id IN ("<vuln_scanner_aid>", "<asset_discovery_aid>", "<monitoring_aid>", "<log_collector_aid>", "<network_team_aid>",
                      "<security_team_aid>")
// The requesting process. Reverse lookups narrowed to the private parts of 172 and 192 (only the few PTR rows get here).
| EVAL pid = COALESCE(process.entity_id, data.ContextProcessId),
       ptr = CASE(event.action == "dnsrequest"
                    AND TO_LOWER(dns.question.name) RLIKE ".*\\.(10|(1[6-9]|2[0-9]|3[01])\\.172|168\\.192)\\.in-addr\\.arpa\\.?",
                  dns.question.name, NULL)
// One row per process: how many hosts and ports it tried, and how many internal names it looked up.
| STATS targets = COUNT_DISTINCT(destination.ip), ports = COUNT_DISTINCT(destination.port), ptr_names = COUNT_DISTINCT(ptr),
        sample_ports = TOP(destination.port, 10, "asc"), sample_targets = TOP(destination.ip, 10, "asc"),
        process.name = VALUES(COALESCE(process.name, data.ContextBaseFileName)), first_seen = MIN(@timestamp), host.name = VALUES(host.name)
    BY host.id, pid
// Each scan shape on its own threshold.
| EVAL port_scan = ports >= 30 AND targets <= 5, sweep = targets >= 50 OR (targets >= 10 AND ports >= 10), ptr_sweep = ptr_names >= 50
| WHERE port_scan OR sweep OR ptr_sweep
| EVAL finding = CASE(port_scan, "port scan of one or a few hosts", sweep, "sweep of many hosts", "reverse-DNS sweep of internal addresses")
| KEEP host.id, host.name, finding, process.name, pid, targets, ports, ptr_names, sample_ports, sample_targets, first_seen
```

**CrowdStrike (Falcon LogScale / Advanced Event Search)**, run over the last 12 minutes:
```logscale
#event_simpleName=/^(NetworkConnectIP4|DnsRequest)$/
// vulnerability scanners, asset discovery, monitoring, name-resolving log collectors, network and security teams (placeholders)
| !in(field="aid", values=["<vuln_scanner_aid>", "<asset_discovery_aid>", "<monitoring_aid>", "<log_collector_aid>", "<network_team_aid>",
                           "<security_team_aid>"])
| case {
    // Connections to internal addresses on service ports (chatter ports and dynamic RPC left out).
    #event_simpleName=NetworkConnectIP4
      | test(RemotePort < 49152)
      | !in(field="RemotePort", values=["53", "123", "137", "138", "1900", "5353", "5355"])
      | cidr(RemoteAddressIP4, subnet=["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"])
      | target := RemoteAddressIP4 | port := RemotePort;
    // Reverse lookups (record type 12) first, which is cheap; then the private ranges, on those few names only.
    #event_simpleName=DnsRequest RequestType=12
      | DomainName=/\.(10|(1[6-9]|2[0-9]|3[01])\.172|168\.192)\.in-addr\.arpa\.?$/i
      | ptr := DomainName;
  }
// One row per process: how many hosts and ports it tried, and how many internal names it looked up.
| groupBy([aid, ContextProcessId], function=[count(target, distinct=true, as=targets), count(port, distinct=true, as=ports),
                                             count(ptr, distinct=true, as=ptr_names), min(@timestamp, as=first_seen),
                                             collect([ComputerName, ContextBaseFileName])], limit=max)
// Each scan shape on its own threshold.
| test((ports >= 30 AND targets <= 5) OR targets >= 50 OR (targets >= 10 AND ports >= 10) OR ptr_names >= 50)
| case {
    test(ports >= 30 AND targets <= 5) | finding := "port scan of one or a few hosts";
    test(targets >= 50 OR (targets >= 10 AND ports >= 10)) | finding := "sweep of many hosts";
    * | finding := "reverse-DNS sweep of internal addresses";
  }
```

**Same behaviour in Palo Alto traffic logs**, run every 10 minutes with a 15-minute lookback. It starts from unanswered sessions only, which keeps it small:
```esql
FROM logs-panw.panos-*
// Anchor: internal sessions on service ports that got nothing back: denied or dropped, or never completed (no application).
| WHERE panw.panos.type == "TRAFFIC" AND destination.port < 49152
  AND (panw.panos.action != "allow" OR network.application IN ("incomplete", "insufficient-data"))
  AND CIDR_MATCH(source.ip, "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
  AND CIDR_MATCH(destination.ip, "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
  // vulnerability scanners and asset discovery (placeholder range: replace with yours)
  AND NOT CIDR_MATCH(source.ip, "198.51.100.0/24")
// One row per source: how many hosts and ports went unanswered.
| STATS targets = COUNT_DISTINCT(destination.ip), ports = COUNT_DISTINCT(destination.port),
        sample_ports = TOP(destination.port, 10, "asc"), sample_targets = TOP(destination.ip, 10, "asc"), first_seen = MIN(@timestamp)
    BY source.ip
// The same shapes, counted on unanswered probes only.
| WHERE (ports >= 30 AND targets <= 5) OR targets >= 50 OR (targets >= 10 AND ports >= 10)
| EVAL finding = CASE(ports >= 30 AND targets <= 5, "port scan of one or a few hosts", "sweep of many hosts")
```
Suppress by `source.ip`, `finding` for 1h. Field names are the Elastic PAN-OS integration's; confirm `panw.panos.action` and the `incomplete` application value in your data. If zone protection's reconnaissance protection is on, PAN-OS also writes its own threat logs for this ("TCP Port Scan", "Host Sweep"); those can be passed through as they are.

**Known scanners by name (optional filename fallback)**, run every 15 minutes with a 15-minute lookback. It's a separate query so the scan rule doesn't read every process start. Names are matched exactly or by prefix, which the index answers cheaply:
```esql
FROM logs-yourorg-crowdstrike-data-default* METADATA _id, _index, _version
// GUI and command-line scanners, by the names they ship under (versioned names by prefix).
| WHERE event.action == "processrollup2"
  AND (process.name IN ("nmap.exe", "nmap", "masscan.exe", "masscan", "rustscan.exe", "rustscan", "zmap", "naabu.exe", "naabu",
                        "advanced_ip_scanner.exe", "advanced_port_scanner.exe", "netscan.exe")
       OR process.name LIKE "nbtscan*" OR process.name LIKE "fscan*" OR process.name LIKE "ipscan*")
  AND NOT host.id IN ("<network_team_aid>", "<security_team_aid>")
| KEEP @timestamp, host.id, host.name, user.name, process.name, process.executable, process.command_line, process.parent.name,
       _id, _version, _index
```
```logscale
#event_simpleName=ProcessRollup2
| FileName=/^(nmap|masscan|rustscan|zmap|naabu|nbtscan[-._a-z0-9]*|fscan[_a-z0-9]*|advanced_ip_scanner|advanced_port_scanner|netscan|ipscan[-_.a-z0-9]*)(\.exe)?$/i
| !in(field="aid", values=["<network_team_aid>", "<security_team_aid>"])
| table([@timestamp, aid, ComputerName, UserName, FileName, CommandLine, ParentBaseFileName])
```
Medium severity, suppress by `host.id`, `process.name` for 1h. It needs `process.name` on process starts; if your index only has `process.executable`, match that with a suffix (`LIKE "*\\nmap.exe"`), which costs more.

**Check before deploying:**
- **Registered domain on DNS events.** The reverse-lookup filter needs `dns.question.registered_domain`. If your index doesn't have it, use the record type instead (`data.RequestType == 12`, PTR). Either is an indexed exact match; avoid going back to `LIKE "*.in-addr.arpa*"`.
- **Raw-packet scans.** Run `nmap -sT <lab subnet>` (connections) and `nmap -sS <lab subnet>` as admin (raw packets) from a lab host, and compare what arrives. The connect scan should give "port scan" or "sweep". The SYN scan should give "reverse-DNS sweep" (nmap names each live host unless run with `-n`), and a sweep in the Palo Alto query if it crosses the firewall.
- **Process IDs on your index.** `pid` uses `process.entity_id`, falling back to `data.ContextProcessId`. Confirm that a scan's connections and lookups share one value.

## Suppression
Suppress by `host.id`, `finding` for 1h. Alerts missing a key field are not suppressed. Aggregating rule: each run overlaps the last by two minutes. Scans are often run several times in a row; those fold into one alert per host and kind of scan.

## Known false positives / exclusions
- Hosts that scan or fan out by design: vulnerability scanners, asset discovery, monitoring, backup and management servers, and the network and security teams. Exclude them by Falcon agent ID (placeholders above), not by user, so a stolen admin account on another host still alerts. In the Palo Alto query, most of these never pile up unanswered probes; exclude vulnerability scanners by address.
- Log collectors and SIEM forwarders that add reverse-DNS names to the events they ship, which looks like a reverse-DNS sweep. Exclude those hosts the same way.
- A management script on a host you didn't expect (an admin's workstation running a PowerShell loop over many servers). That's still worth a look: it's also what an intruder does.

## Blind spot
- In Falcon: a raw-packet scan with name resolution off (`-n`). The Palo Alto query sees it if it crosses the firewall; D04's decoy hosts see any scan that touches them; the name query sees known scanners.
- UDP scans of the left-out chatter ports (NetBIOS name sweeps on 137 and similar). IP scanners that do this also resolve names, which the reverse-DNS sweep sees.
- A slow scan spread over more than the window (`--scan-delay`, `-T1`) stays under each threshold. If that's a concern, run a second copy hourly with a 1-hour lookback and doubled thresholds.

## Triage
- Read `finding` and the process: `process.name`, then its start event by `pid` for the path, command line and parent. A shell, a script interpreter, or a binary in `Downloads`, `Temp` or `/tmp` scanning is reconnaissance. So is an IP scanner run on a server by an account that isn't IT.
- Read the shape: `ports` and `sample_ports` (what it was looking for), `targets` and `sample_targets` (where it looked). 445, 3389, 22 and 5985 usually come before lateral movement: check B04 on the same host for what followed.
- From the Palo Alto query, find the device behind `source.ip` (DHCP, Falcon, switch port). An address with no Falcon sensor is a device you don't manage.

## Test
From a lab host:
- `nmap -sT -p 1-1000 <lab host>`: "port scan of one or a few hosts".
- `nmap -sT -p 445 <lab /24>`: "sweep of many hosts".
- `nmap -sS <lab /24>` as admin: "reverse-DNS sweep".
- A PowerShell loop testing port 445 across a lab /24 (`Test-NetConnection` in a `foreach`): "sweep of many hosts", with no scanner involved.
- Advanced IP Scanner on a lab subnet: the name query, and a reverse-DNS sweep when it resolves names.
