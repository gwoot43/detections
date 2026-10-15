---
id: B01
name: Internal network or port scan - one process probes many internal host:port endpoints
category: behaviour
status: todo
severity: high
language: esql
index: logs-crowdstrike.fdr-*
mitre: [T1046, T1018]
data_source: CrowdStrike FDR network connection events
suppression:
  fields: [host.id, process.name]
  duration: 1h
  missing_fields: do_not_suppress
---
## Why this is behavioural and high fidelity
This does not look for a tool name. It looks for the shape of scanning: one process on one host trying a large number of distinct internal `host:port` endpoints in a short window. Counting endpoints rather than hosts or ports covers every scan shape with one number:
- **Horizontal:** 100 hosts on one port (a sweep for SMB or RDP).
- **Vertical:** 100 ports on one host (nmap's default top 1000 against a server).
- **Mixed:** 20 hosts × 5 ports.

Ordinary clients talk to a handful of server endpoints in ten minutes, not a hundred. All ports count, including the high range, since scanners probe it too. Counting over the whole rule window, not fixed 5-minute buckets, means a scan that crosses a bucket boundary isn't split in two.

This replaces the former B02 (vertical port scan), which the endpoint count now covers.

**Blind spot: raw-packet scans.** Falcon's `NetworkConnectIP4` records programs opening connections. nmap run as administrator or root does a SYN scan by default and sends raw packets instead, as do masscan and nmap's ping sweep (`-sn`). Those scans may produce few or no connection events. Before relying on this rule, run `nmap -sT` and `nmap -sS` (as admin) from a lab host against a lab subnet and compare the event counts. CS12 catches the scanner tools by name, which covers raw-packet scans from hosts with Falcon. Palo Alto zone protection, if it's on for internal zones, sees scans that cross the firewall.

## Query
Run every 5 minutes with a 10-minute lookback.
```esql
FROM logs-crowdstrike.fdr-*
| WHERE event.action == "NetworkConnectIP4"
  AND CIDR_MATCH(destination.ip, "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
  // vulnerability scanners, asset discovery, SCCM and monitoring servers (placeholders: Falcon agent IDs)
  AND NOT host.id IN ("<vuln_scanner_aid>", "<sccm_aid>", "<monitoring_aid>")
| EVAL process.name = TO_LOWER(COALESCE(process.name, "unknown")),
       endpoint = CONCAT(TO_STRING(destination.ip), ":", TO_STRING(destination.port))
| STATS endpoints = COUNT_DISTINCT(endpoint),
        targets = COUNT_DISTINCT(destination.ip),
        ports = COUNT_DISTINCT(destination.port),
        port_list = VALUES(destination.port),
        first_seen = MIN(@timestamp),
        host.name = VALUES(host.name)
    BY host.id, process.name
| WHERE endpoints >= 100
| KEEP host.id, host.name, process.name, endpoints, targets, ports, port_list, first_seen
```

**CrowdStrike (Falcon LogScale / Advanced Event Search)**, run over the last 10 minutes:
```logscale
#event_simpleName=NetworkConnectIP4
| cidr(RemoteAddressIP4, subnet=["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"])
| !in(field="aid", values=["<vuln_scanner_aid>", "<sccm_aid>", "<monitoring_aid>"])
| pname := lower(ContextBaseFileName)
| default(field=pname, value="unknown", replaceEmpty=true)
| endpoint := format("%s:%s", field=[RemoteAddressIP4, RemotePort])
| groupBy([aid, pname], function=[count(endpoint, distinct=true, as=endpoints), count(RemoteAddressIP4, distinct=true, as=targets),
                                  count(RemotePort, distinct=true, as=ports), min(@timestamp, as=first_seen), collect([ComputerName])],
          limit=max)
| test(endpoints >= 100)
```

`targets` and `ports` give the shape: many targets and few ports is a sweep for one service, one target and many ports is a full scan of that host. FDR connection events name the process only on sensors that send `ContextBaseFileName`; otherwise the process reads `unknown` and the row covers every process on the host.

## Suppression
Suppress by `host.id`, `process.name` for 1h. Alerts missing a key field are not suppressed. Aggregating rule: each 5-minute run overlaps the last. A different host or process still alerts. `host.id` is the Falcon agent ID and is always present; `host.name` is filled only when the integration's host metadata enrichment is on, so it is an output column, not a key.

## Known false positives / exclusions
- Vulnerability scanners, asset discovery and monitoring. These are few and named; replace the placeholders with their Falcon agent IDs (`aid`).
- Load balancers, proxies, backup servers and management servers that fan out by design. Exclude those hosts the same way. A server whose process name is `unknown` (older sensor) counts every process together, so busy servers are the usual first exclusions.

## Triage
- Identify the process and user. A browser or system service is likely benign fan-out; a shell, script interpreter or unsigned binary probing 100+ endpoints is reconnaissance.
- Read `targets`, `ports` and `port_list`: a single port across many hosts is a hunt for one service (445 and 3389 usually precede lateral movement); many ports on one host is preparation to attack that host. Pivot to the host for how the process got there.

## Test
From a lab host, run `nmap -sT` against a lab subnet (horizontal) and `nmap -sT -p- <one lab host>` (vertical). Both should fire. Repeat with `nmap -sS` as admin to see how much of a raw-packet scan Falcon records.
