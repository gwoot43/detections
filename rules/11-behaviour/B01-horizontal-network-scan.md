---
id: B01
name: Internal scanning by behaviour - a port scan of one host, a sweep of many, or a reverse-DNS sweep, from one process (Falcon) or one address with most probes unanswered (Palo Alto)
category: behaviour
status: todo
severity: high
language: esql
index: logs-yourorg-crowdstrike-data-default*
mitre: [T1046, T1018]
data_source: CrowdStrike FDR NetworkConnectIP4, DnsRequest and ProcessRollup2; Palo Alto PAN-OS traffic logs as a second source
suppression:
  fields: [host.id, finding]
  duration: 1h
  missing_fields: do_not_suppress
---
## Why this is behavioural and high fidelity
Any internal scan, whatever runs it (nmap, masscan, an IP scanner, a PowerShell loop, an implant's built-in scanner, a worm), does one of three things. The rule looks for each, per process instance (host + process ID), so one busy process can't lend its count to another and a host's processes are never lumped together:

| `finding` | What the process did in 10 minutes | Why it's a scan |
|---|---|---|
| port scan of one host | Tried 30+ ports on one internal host (below the dynamic RPC range) | Nothing legitimate tries 30 ports on one machine |
| sweep of many hosts | Tried 50+ internal hosts, or 100+ host:port endpoints in total | A hunt for one service (SMB, RDP, SSH, WinRM) across subnets, or a mixed scan |
| reverse-DNS sweep of internal addresses | Looked up the names of 50+ internal addresses | Scanners name the hosts they find. The lookups go through the normal resolver, so this shows even when the scan itself sends raw packets that Falcon doesn't record as connections |
| known scanner started (by name) | A known scanner started, with no scan shape yet | The filename fallback, for GUI scanners and scans too small for the thresholds. Medium severity |

- **Dynamic RPC ports** (49152 and up) don't count towards ports: Windows clients reach a server's RPC services there, so a process talking to a domain controller would otherwise look like a port scan.
- **Exclusions:** the hosts that scan or resolve names by design, by Falcon agent ID (placeholders).

**The firewall sees what Falcon can't.** The Palo Alto query below looks for the same shapes from one source address, with one more test: most of the probes got nothing back. A scan mostly hits closed ports and empty addresses, so the session is reset, denied or never completes. Monitoring and management servers get answers from the hosts they poll. That one ratio separates them without a list. It also covers scans from devices without Falcon (a rogue laptop, a compromised appliance) and raw-packet scans, but only between zones the firewall sits between.

## Query
Run every 5 minutes with a 10-minute lookback.
```esql
FROM logs-yourorg-crowdstrike-data-default*
// Connections to internal addresses, reverse-DNS lookups (resolver traffic, so visible even when the scan sends raw packets),
// and process starts (for the filename fallback). Joined below on the process (host + process ID).
| WHERE ((event.action == "networkconnectip4" AND CIDR_MATCH(destination.ip, "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
         OR (event.action == "dnsrequest" AND dns.question.name LIKE "*.in-addr.arpa*")
         OR event.action IN ("processrollup2", "syntheticprocessrollup2"))
  // vulnerability scanners, asset discovery, monitoring, name-resolving log collectors, network and security teams (placeholders)
  AND NOT host.id IN ("<vuln_scanner_aid>", "<asset_discovery_aid>", "<monitoring_aid>", "<log_collector_aid>", "<network_team_aid>",
                      "<security_team_aid>")
| EVAL start = event.action LIKE "*processrollup2",
       // The process: its own ID on a start event, the requesting process's on connections and lookups.
       pid = CASE(start, COALESCE(process.entity_id, data.TargetProcessId), COALESCE(process.entity_id, data.ContextProcessId)),
       // Dynamic RPC ports (49152+) are where Windows clients reach a server's RPC services; they'd inflate the port count.
       port = CASE(destination.port < 49152, destination.port, NULL),
       // Reverse lookups of internal addresses (10/8, 172.16/12, 192.168/16).
       ptr = CASE(event.action == "dnsrequest"
                    AND TO_LOWER(dns.question.name) RLIKE ".*\\.(10|(1[6-9]|2[0-9]|3[01])\\.172|168\\.192)\\.in-addr\\.arpa\\.?",
                  TO_LOWER(dns.question.name), NULL),
       // Filename fallback: known scanners, including GUI ones that take no arguments.
       named = start AND TO_LOWER(COALESCE(process.executable, "")) RLIKE """.*[\\/](nmap|masscan|rustscan|zmap|naabu|nbtscan(-[0-9.]+)?|fscan(32|64)?(_[a-z0-9]+)?|advanced_ip_scanner|advanced_port_scanner|netscan|ipscan(-[-_.a-z0-9]+)?)(\.exe)?""",
       pname = TO_LOWER(COALESCE(process.name, data.ContextBaseFileName))
| WHERE event.action == "networkconnectip4" OR ptr IS NOT NULL OR named
// One row per process and target: how many ports it tried on that host (lookups and starts have no target).
| STATS ports = COUNT_DISTINCT(port), port_list = VALUES(port), ptr_names = COUNT_DISTINCT(ptr), named = MAX(CASE(named, 1, 0)),
        process.name = VALUES(pname), process.executable = VALUES(process.executable), process.command_line = VALUES(process.command_line),
        first_seen = MIN(@timestamp), host.name = VALUES(host.name)
    BY host.id, pid, destination.ip
// One row per process: the most ports on any one host, how many hosts, and how many internal names it looked up.
| STATS max_ports_one_host = MAX(ports), targets = COUNT(destination.ip), endpoints = SUM(ports), ptr_names = SUM(ptr_names),
        named = MAX(named), port_list = VALUES(port_list), sample_targets = VALUES(destination.ip), process.name = VALUES(process.name),
        process.executable = VALUES(process.executable), process.command_line = VALUES(process.command_line),
        first_seen = MIN(first_seen), host.name = VALUES(host.name)
    BY host.id, pid
// Behaviour first, each scan shape on its own threshold. Then the filename fallback.
| EVAL port_scan = max_ports_one_host >= 30, sweep = targets >= 50 OR endpoints >= 100, ptr_sweep = ptr_names >= 50
| WHERE port_scan OR sweep OR ptr_sweep OR named == 1
| EVAL finding = CASE(port_scan, "port scan of one host",
                      sweep, "sweep of many hosts",
                      ptr_sweep, "reverse-DNS sweep of internal addresses",
                      "known scanner started (by name)"),
       known_tool = named == 1,
       severity = CASE(port_scan OR sweep OR ptr_sweep, "high", "medium"),
       sample_targets = MV_SLICE(sample_targets, 0, 9)
| KEEP host.id, host.name, finding, severity, known_tool, process.name, process.executable, process.command_line, max_ports_one_host,
       targets, endpoints, ptr_names, port_list, sample_targets, pid, first_seen
```

**CrowdStrike (Falcon LogScale / Advanced Event Search)**, run over the last 10 minutes:
```logscale
#event_simpleName=/^(NetworkConnectIP4|DnsRequest|ProcessRollup2|SyntheticProcessRollup2)$/
// vulnerability scanners, asset discovery, monitoring, name-resolving log collectors, network and security teams (placeholders)
| !in(field="aid", values=["<vuln_scanner_aid>", "<asset_discovery_aid>", "<monitoring_aid>", "<log_collector_aid>", "<network_team_aid>",
                           "<security_team_aid>"])
| case {
    // Connections to internal addresses. Dynamic RPC ports (49152+) don't count towards ports.
    #event_simpleName=NetworkConnectIP4
      | cidr(RemoteAddressIP4, subnet=["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"])
      | falconPID := ContextProcessId | target := RemoteAddressIP4 | real_target := RemoteAddressIP4 | pname := lower(ContextBaseFileName)
      | case { test(RemotePort < 49152) | port := RemotePort; *; };
    // Reverse lookups of internal addresses: visible even when the scan sends raw packets.
    #event_simpleName=DnsRequest DomainName=/\.(10|(1[6-9]|2[0-9]|3[01])\.172|168\.192)\.in-addr\.arpa\.?$/i
      | falconPID := ContextProcessId | target := "none" | ptr := lower(DomainName);
    // Filename fallback: known scanners, including GUI ones that take no arguments.
    ImageFileName=/[\\\/](nmap|masscan|rustscan|zmap|naabu|nbtscan(-[0-9.]+)?|fscan(32|64)?(_[a-z0-9]+)?|advanced_ip_scanner|advanced_port_scanner|netscan|ipscan(-[-_.a-z0-9]+)?)(\.exe)?$/i
      | falconPID := TargetProcessId | target := "none" | named := 1 | pname := lower(FileName);
  }
// One row per process and target: how many ports it tried on that host.
| groupBy([aid, falconPID, target], function=[count(port, distinct=true, as=ports), count(real_target, distinct=true, as=hit),
                                              count(ptr, distinct=true, as=ptr_names), max(named, as=named),
                                              min(@timestamp, as=first_seen), collect([ComputerName, pname, ImageFileName, CommandLine, port])],
          limit=max)
// One row per process: the most ports on any one host, how many hosts, and how many internal names it looked up.
| groupBy([aid, falconPID], function=[max(ports, as=max_ports_one_host), sum(hit, as=targets), sum(ports, as=endpoints),
                                      sum(ptr_names, as=ptr_names), max(named, as=named), min(first_seen, as=first_seen),
                                      collect([ComputerName, pname, ImageFileName, CommandLine, port])], limit=max)
| default(field=[max_ports_one_host, targets, endpoints, ptr_names, named], value=0)
// Behaviour first, each scan shape on its own threshold. Then the filename fallback.
| test(max_ports_one_host >= 30 OR targets >= 50 OR endpoints >= 100 OR ptr_names >= 50 OR named > 0)
| case {
    test(max_ports_one_host >= 30) | finding := "port scan of one host" | severity := "high";
    test(targets >= 50 OR endpoints >= 100) | finding := "sweep of many hosts" | severity := "high";
    test(ptr_names >= 50) | finding := "reverse-DNS sweep of internal addresses" | severity := "high";
    * | finding := "known scanner started (by name)" | severity := "medium";
  }
```

**Same behaviour in Palo Alto traffic logs**, run every 10 minutes with a 15-minute lookback. One source address, the same shapes, and most probes unanswered:
```esql
FROM logs-panw.panos-*
// Anchor: sessions between internal addresses, from traffic logs.
| WHERE panw.panos.type == "TRAFFIC"
  AND CIDR_MATCH(source.ip, "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
  AND CIDR_MATCH(destination.ip, "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
  // vulnerability scanners and asset discovery (placeholder range: replace with yours)
  AND NOT CIDR_MATCH(source.ip, "198.51.100.0/24")
// A probe that got nothing back: denied or dropped by policy, or a session the firewall never saw complete (no application).
| EVAL unanswered = panw.panos.action != "allow" OR network.application IN ("incomplete", "insufficient-data"),
       port = CASE(destination.port < 49152, destination.port, NULL)
// One row per source and target: ports tried, and how many got nothing back.
| STATS ports = COUNT_DISTINCT(port), unanswered_ports = COUNT_DISTINCT(CASE(unanswered, port, NULL)), port_list = VALUES(port)
    BY source.ip, destination.ip
// One row per source: the scan shape, and the share of probes that got nothing back.
| STATS max_ports_one_host = MAX(ports), targets = COUNT(*), endpoints = SUM(ports), unanswered = SUM(unanswered_ports),
        port_list = VALUES(port_list), sample_targets = VALUES(destination.ip)
    BY source.ip
| EVAL unanswered_share = ROUND(unanswered / endpoints::double, 2)
// A scan shape where at least half the probes got nothing back. Monitoring and management servers get answers.
| WHERE (max_ports_one_host >= 30 OR targets >= 50 OR endpoints >= 100) AND unanswered_share >= 0.5
| EVAL finding = CASE(max_ports_one_host >= 30, "port scan of one host", "sweep of many hosts"),
       sample_targets = MV_SLICE(sample_targets, 0, 9)
```
Suppress by `source.ip`, `finding` for 1h. Field names are the Elastic PAN-OS integration's; confirm `panw.panos.action` and the `incomplete` application value in your data. If zone protection's reconnaissance protection is on, PAN-OS also writes its own threat logs for this ("TCP Port Scan", "Host Sweep"); those can be passed through as they are.

**Check before deploying:**
- **Raw-packet scans.** Run `nmap -sT <lab subnet>` (connections) and `nmap -sS <lab subnet>` as admin (raw packets) from a lab host, and compare what arrives. The connect scan should give "port scan" or "sweep". The SYN scan should give "reverse-DNS sweep" (nmap names each live host unless run with `-n`), and a sweep in the Palo Alto query if it crosses the firewall.
- **Process IDs on your index.** `pid` uses `process.entity_id`, falling back to `data.ContextProcessId` / `data.TargetProcessId`. Confirm that a scan's connections and lookups share one value.

## Suppression
Suppress by `host.id`, `finding` for 1h. Alerts missing a key field are not suppressed. Aggregating rule: each 5-minute run overlaps the last. Scans are often run several times in a row; those fold into one alert per host and kind of scan.

## Known false positives / exclusions
- Hosts that scan or fan out by design: vulnerability scanners, asset discovery, monitoring, backup and management servers, and the network and security teams. Exclude them by Falcon agent ID (placeholders above), not by user, so a stolen admin account on another host still alerts. In the Palo Alto query, most of these drop out on the unanswered share; exclude vulnerability scanners by address.
- Log collectors and SIEM forwarders that add reverse-DNS names to the events they ship, which looks like a reverse-DNS sweep. Exclude those hosts the same way.
- A management script on a host you didn't expect (an admin's workstation running a PowerShell loop over many servers). That's still worth a look: it's also what an intruder does.

## Blind spot
- In Falcon: a raw-packet scan with name resolution off (`-n`) by a program not on the name list. The Palo Alto query sees it if it crosses the firewall; D04's decoy hosts see any scan that touches them.
- A slow scan spread over more than 10 minutes (`--scan-delay`, `-T1`) stays under each window's thresholds. If that's a concern, run a second copy hourly with a 1-hour lookback and doubled thresholds.

## Triage
- Read `finding` and the process: `process.executable` and `process.command_line` when the start is in the window, otherwise look the process up by `pid`. A shell, a script interpreter, or a binary in `Downloads`, `Temp` or `/tmp` scanning is reconnaissance. So is an IP scanner run on a server by an account that isn't IT.
- Read the shape: `max_ports_one_host` and `port_list` (what it was looking for on one machine), `targets` and `sample_targets` (where it looked). 445, 3389, 22 and 5985 usually come before lateral movement: check B04 on the same host for what followed.
- From the Palo Alto query, find the device behind `source.ip` (DHCP, Falcon, switch port). An address with no Falcon sensor is a device you don't manage.

## Test
From a lab host:
- `nmap -sT -p 1-1000 <lab host>`: "port scan of one host".
- `nmap -sT -p 445 <lab /24>`: "sweep of many hosts".
- `nmap -sS <lab /24>` as admin: "reverse-DNS sweep".
- A PowerShell loop testing port 445 across a lab /24 (`Test-NetConnection` in a `foreach`): "sweep of many hosts", with no scanner involved.
- Advanced IP Scanner on a lab subnet: "known scanner started (by name)", and a reverse-DNS sweep when it resolves names.
