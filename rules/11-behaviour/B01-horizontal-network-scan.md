---
id: B01
name: Internal network or port scan - one process probes many internal host:port endpoints (activity), or a known scanner runs (filename fallback)
category: behaviour
status: todo
severity: high
language: esql
index: logs-yourorg-crowdstrike-data-default*
mitre: [T1046, T1018]
data_source: CrowdStrike FDR network connection events and ProcessRollup2
suppression:
  fields: [host.id, process.name]
  duration: 1h
  missing_fields: do_not_suppress
---
## Why this is behavioural and high fidelity
The rule looks for the shape of scanning first, and the scanner's name second.

**Activity (primary).** One process on one host tries a large number of distinct internal `host:port` endpoints in a short window. Counting endpoints rather than hosts or ports covers every scan shape with one number:
- **Horizontal:** 100 hosts on one port (a sweep for SMB or RDP).
- **Vertical:** 100 ports on one host (nmap's default top 1000 against a server).
- **Mixed:** 20 hosts × 5 ports.

Ordinary clients talk to a handful of server endpoints in ten minutes, not a hundred. All ports count, including the high range, since scanners probe it too. Counting over the whole rule window, not fixed 5-minute buckets, means a scan that crosses a bucket boundary isn't split in two. This works whatever the program is called.

**Filename (fallback).** A known scanner starting: nmap, masscan, rustscan, zmap, naabu, nbtscan, fscan, Advanced IP/Port Scanner, SoftPerfect NetScan or Angry IP Scanner. Ransomware crews and hands-on-keyboard intruders mostly bring these, and outside the network and security teams nobody runs them. The fallback covers what the activity half can't see. Falcon's `NetworkConnectIP4` records programs opening connections, but nmap run as administrator or root does a SYN scan and sends raw packets instead, as do masscan and nmap's ping sweep (`-sn`). Those scans may produce few or no connection events, but starting the scanner is always a process event.

Both halves are grouped on the host and program name, so a known scanner that also probes 100+ endpoints is one alert saying both. This absorbs the former CS12, which matched the scanner names on its own.

## Query
Run every 5 minutes with a 10-minute lookback.
```esql
FROM logs-yourorg-crowdstrike-data-default*
// Activity: connections to internal addresses. Filename fallback: a known scanner starting, which also covers
// raw-packet scans (nmap as admin, masscan, ping sweeps) that Falcon may not record as connections.
| WHERE ((event.action == "networkconnectip4" AND CIDR_MATCH(destination.ip, "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
         OR (event.action IN ("processrollup2", "syntheticprocessrollup2")
             AND TO_LOWER(process.executable) RLIKE """.*[\\/](nmap|masscan|rustscan|zmap|naabu|nbtscan(-[0-9.]+)?|fscan(32|64)?(_[a-z0-9]+)?|advanced_ip_scanner|advanced_port_scanner|netscan|ipscan(-[-_.a-z0-9]+)?)(\.exe)?"""))
  // vulnerability scanners, asset discovery, SCCM, monitoring and the network and security teams (placeholders: Falcon agent IDs)
  AND NOT host.id IN ("<vuln_scanner_aid>", "<sccm_aid>", "<monitoring_aid>", "<network_team_aid>", "<security_team_aid>")
| EVAL process.name = TO_LOWER(COALESCE(process.name, "unknown")),
       endpoint = CASE(event.action == "networkconnectip4", CONCAT(TO_STRING(destination.ip), ":", TO_STRING(destination.port)), NULL),
       scanner_start = event.action != "networkconnectip4"
// One row per host and program: the internal endpoints it probed, and whether a known scanner started under that name.
| STATS endpoints = COUNT_DISTINCT(endpoint), targets = COUNT_DISTINCT(destination.ip), ports = COUNT_DISTINCT(destination.port),
        port_list = VALUES(destination.port), named = MAX(CASE(scanner_start, 1, 0)),
        process.executable = VALUES(process.executable), process.command_line = VALUES(process.command_line),
        first_seen = MIN(@timestamp), host.name = VALUES(host.name)
    BY host.id, process.name
// Activity first: 100+ internal endpoints. Then the filename fallback.
| WHERE endpoints >= 100 OR named == 1
| EVAL finding = CASE(endpoints >= 100 AND named == 1, "known scanner probing the network",
                      endpoints >= 100, "scan by behaviour",
                      "known scanner started (by name)"),
       severity = CASE(endpoints >= 100, "high", "medium")
| KEEP host.id, host.name, process.name, finding, severity, endpoints, targets, ports, port_list, process.executable,
       process.command_line, first_seen
```

**CrowdStrike (Falcon LogScale / Advanced Event Search)**, run over the last 10 minutes:
```logscale
#event_simpleName=/^(NetworkConnectIP4|ProcessRollup2|SyntheticProcessRollup2)$/
// vulnerability scanners, asset discovery, SCCM, monitoring and the network and security teams (placeholders: Falcon agent IDs)
| !in(field="aid", values=["<vuln_scanner_aid>", "<sccm_aid>", "<monitoring_aid>", "<network_team_aid>", "<security_team_aid>"])
| case {
    // Activity: connections to internal addresses.
    #event_simpleName=NetworkConnectIP4
      | cidr(RemoteAddressIP4, subnet=["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"])
      | pname := lower(ContextBaseFileName)
      | endpoint := format("%s:%s", field=[RemoteAddressIP4, RemotePort]);
    // Filename fallback: a known scanner starting, which also covers raw-packet scans.
    ImageFileName=/[\\\/](nmap|masscan|rustscan|zmap|naabu|nbtscan(-[0-9.]+)?|fscan(32|64)?(_[a-z0-9]+)?|advanced_ip_scanner|advanced_port_scanner|netscan|ipscan(-[-_.a-z0-9]+)?)(\.exe)?$/i
      | pname := lower(FileName) | named := 1;
  }
| default(field=pname, value="unknown", replaceEmpty=true)
// One row per host and program: the internal endpoints it probed, and whether a known scanner started under that name.
| groupBy([aid, pname], function=[count(endpoint, distinct=true, as=endpoints), count(RemoteAddressIP4, distinct=true, as=targets),
                                  count(RemotePort, distinct=true, as=ports), count(named, as=named), min(@timestamp, as=first_seen),
                                  collect([ComputerName, ImageFileName, CommandLine])], limit=max)
// Activity first: 100+ internal endpoints. Then the filename fallback.
| test(endpoints >= 100 OR named > 0)
| case {
    test(endpoints >= 100 AND named > 0) | finding := "known scanner probing the network" | severity := "high";
    test(endpoints >= 100) | finding := "scan by behaviour" | severity := "high";
    * | finding := "known scanner started (by name)" | severity := "medium";
  }
```

`targets` and `ports` give the shape: many targets and few ports is a sweep for one service, one target and many ports is a full scan of that host. FDR connection events name the process only on sensors that send `ContextBaseFileName`; otherwise the process reads `unknown`, the row covers every process on the host, and a scanner's start event lands on its own row, still alerting by name.

The scanner pattern matches the last part of the path: `nmap.exe`, `/usr/bin/nmap`, `advanced_ip_scanner.exe` and `fscan.exe` match; `nmapper.exe` doesn't. It also takes the names the tools ship under, which carry a version or architecture: `fscan64.exe`, `fscan_amd64`, `nbtscan-1.0.35.exe`, `ipscan-win64-3.9.1.exe`.

## Suppression
Suppress by `host.id`, `process.name` for 1h. Alerts missing a key field are not suppressed. Aggregating rule: each 5-minute run overlaps the last, and scanners are often run several times in a row with different options. A different host or program still alerts.

## Known false positives / exclusions
- Vulnerability scanners, asset discovery, monitoring, and the network and security teams' hosts. These are few and named; replace the placeholders with their Falcon agent IDs (`aid`). Exclude by host, not by user, so a stolen admin account on another host still alerts.
- Load balancers, proxies, backup servers and management servers that fan out by design. Exclude those hosts the same way. A server whose process name is `unknown` (older sensor) counts every process together, so busy servers are the usual first exclusions.
- `ipscan` is Angry IP Scanner on Windows; `netscan` is SoftPerfect. Another product shipping a binary with one of these names would match; exclude it by full path once seen.

## Blind spot
A renamed scanner sending raw packets: its start doesn't match a known name, and its packets aren't connections. Palo Alto zone protection, if it's on for internal zones, sees scans that cross the firewall.

## Triage
- Read `finding`. Identify the process and user. A browser or system service is likely benign fan-out; a shell, script interpreter or unsigned binary probing 100+ endpoints is reconnaissance. Advanced IP Scanner or NetScan run from `Downloads` or `Temp` on a server, by an account that isn't IT, is an intruder mapping the network.
- Read `targets`, `ports` and `port_list`, or the scanner's command line: a single port across many hosts is a hunt for one service (445 and 3389 usually precede lateral movement); many ports on one host is preparation to attack that host. Check B04 on the same host for what followed.

## Test
From a lab host, run `nmap -sT` against a lab subnet (horizontal) and `nmap -sT -p- <one lab host>` (vertical): both should alert as "known scanner probing the network". Copy nmap to a different name and repeat for "scan by behaviour". Run `nmap -sn <lab subnet>` as admin for "known scanner started (by name)".
