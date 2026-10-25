---
id: PIVOT-01
name: One process bridging the internet and the internal network (ligolo-ng, chisel, gost, a SOCKS proxy in a beacon) - by behaviour
language: cql
index: logs-yourorg-crowdstrike-data-default*
mitre: [T1090.001, T1572, T1021]
data_source: CrowdStrike FDR NetworkConnectIP4/IP6
suppression:
  fields: [host.id, process.name]
  duration: 6h
  missing_fields: do_not_suppress
---
**Catches:** ligolo-ng, chisel, gost, a SOCKS proxy inside a beacon - any tunnel or pivot relay - by what it does, not its name.

A pivot relay has one process do two things at once: it holds an outbound connection to the operator's server **on the internet**, and it originates connections to **many internal hosts** (the traffic the operator relays through it). ligolo-ng's agent is the clearest case - it keeps one control connection out (TLS, default port 11601) and then makes real socket connections to each internal target the operator reaches. No ordinary program behaves this way: a browser or updater talks to the internet but not to a spread of internal hosts; a management agent talks internal but not to an arbitrary internet address. One process doing both is the relay.

This is the name-free cut. CS16 catches the same pivot when it reaches internal **admin ports** and the program is rare; this one is port-agnostic (ligolo relays any port) and keys on the internet-plus-internal shape instead. Browsers are excluded (they legitimately do both, to intranet sites).

Run every 15 minutes over the last 30.
```logscale
#event_simpleName=/^NetworkConnectIP[46]$/ ConnectionDirection=0
//native stacks and browsers legitimately reach both the internet and internal hosts; exclude on the raw field first
| ContextBaseFileName!=/^(system|svchost\.exe|chrome\.exe|msedge\.exe|firefox\.exe|iexplore\.exe|opera\.exe|brave\.exe)$/i
| RemoteAddress := coalesce([RemoteAddressIP4, RemoteAddressIP6])
| proc := lower(ContextBaseFileName)
//split each connection into internal or external by destination
| case {
    cidr(RemoteAddress, subnet=["10.0.0.0/8","172.16.0.0/12","192.168.0.0/16","fc00::/7","127.0.0.0/8","169.254.0.0/16"]) | int_ip := RemoteAddress ;
    * | ext_ip := RemoteAddress ;
  }
//per host and process: how many internal hosts it reached, and whether it also talked to the internet
| groupBy([aid, proc], function=[count(int_ip, distinct=true, as=internal_hosts), count(ext_ip, distinct=true, as=external_hosts),
    collect([ComputerName, ext_ip, int_ip, RemotePort], limit=50), min(@timestamp, as=first_seen), max(@timestamp, as=last_seen)], limit=max)
//one process bridging the internet and 5+ internal hosts is a relay (starting value - baseline below)
| internal_hosts >= 5
| external_hosts >= 1
| match(file="aid_master_main.csv", field=aid, include=[ComputerName], strict=false)
| select([ComputerName, proc, external_hosts, internal_hosts, ext_ip, int_ip, RemotePort, first_seen, last_seen])
```
```esql
FROM logs-yourorg-crowdstrike-data-default*
| WHERE event.action IN ("networkconnectip4", "networkconnectip6") AND data.ConnectionDirection == "0" AND process.name IS NOT NULL
// split each connection into internal or external; fc00::/7 is the internal IPv6 range
| EVAL proc = TO_LOWER(process.name),
       is_internal = CIDR_MATCH(destination.ip, "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7", "127.0.0.0/8", "169.254.0.0/16")
// native stacks and browsers legitimately reach both the internet and internal hosts
| WHERE NOT proc IN ("system", "svchost.exe", "chrome.exe", "msedge.exe", "firefox.exe", "iexplore.exe", "opera.exe", "brave.exe")
| STATS internal_hosts = COUNT_DISTINCT(CASE(is_internal, destination.ip, NULL)),
        external_hosts = COUNT_DISTINCT(CASE(NOT is_internal, destination.ip, NULL)),
        int_sample = MV_SLICE(VALUES(CASE(is_internal, destination.ip, NULL)), 0, 49),
        ext_sample = MV_SLICE(VALUES(CASE(NOT is_internal, destination.ip, NULL)), 0, 9),
        host.name = VALUES(host.name), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
    BY host.id, proc
// one process bridging the internet and 5+ internal hosts is a relay (starting value - baseline below)
| WHERE internal_hosts >= 5 AND external_hosts >= 1
```
Suppress by host and process for 6h.

## Before turning it on
Run it over a week and see which processes normally bridge both sides:
```logscale
#event_simpleName=/^NetworkConnectIP[46]$/ ConnectionDirection=0
//baseline helper: list every named process that reaches both the internet and internal hosts (not a detection threshold)
| ContextBaseFileName=/./
| RemoteAddress := coalesce([RemoteAddressIP4, RemoteAddressIP6])
| proc := lower(ContextBaseFileName)
| case { cidr(RemoteAddress, subnet=["10.0.0.0/8","172.16.0.0/12","192.168.0.0/16","fc00::/7","127.0.0.0/8","169.254.0.0/16"]) | int_ip := RemoteAddress ; * | ext_ip := RemoteAddress ; }
| groupBy([proc], function=[count(int_ip, distinct=true, as=internal_hosts), count(ext_ip, distinct=true, as=external_hosts), count(aid, distinct=true, as=hosts)], limit=max)
| internal_hosts >= 1 | external_hosts >= 1
| sort(field=internal_hosts, order=desc, limit=200)
```
The legitimate bridges in your estate (a proxy, a VPN concentrator, a patch server, a backup appliance, monitoring) show here - exclude them as host + process pairs, and set the `internal_hosts` threshold from the rest. Scope the rule to workstations and ordinary servers if your gateways genuinely relay.

## What it misses
- A relay used only inside the network (no internet leg) - that's just lateral movement; 16 (fan-out) and CS16 (rare program to admin ports) cover it.
- A relay whose internal use stays under the threshold (one or two targets) in the window - lower the threshold or widen the window to trade noise for reach.
- A relay that reuses a browser or `svchost` name/process to inherit the exclusion. The binary's path and parent in its ProcessRollup2 event would still show it.

## When it fires
`proc` is the relay, `ext_sample` the operator's server (the internet leg), `int_sample` what it reached inside. Find the process's ProcessRollup2 event for the path, command line and parent - an unsigned binary in a user-writable folder, or a command line with `-connect`/`-ignore-cert` (ligolo) or `client ... R:socks` (chisel), is the intrusion. Check CS11 (did it also start listening?), 16 and B04 (the internal fan-out), and treat the host as a foothold and pivot point.
