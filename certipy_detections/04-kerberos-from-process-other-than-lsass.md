---
id: CERTIPY-04
name: Kerberos traffic from a Windows process other than LSASS (certipy auth, Rubeus or Impacket through a proxy)
language: esql
index: logs-yourorg-crowdstrike-data-default*
mitre: [T1649, T1558, T1090]
data_source: CrowdStrike FDR NetworkConnectIP4
suppression:
  fields: [host.id]
  duration: 1h
  missing_fields: do_not_suppress
---
On Windows, every program's Kerberos goes through LSASS, so LSASS is the only process that talks to a DC on port 88. Anything else doing it is speaking Kerberos itself: Rubeus, or `certipy auth` and Impacket running on the attacker's machine and tunnelled through a SOCKS proxy on this host. The proxy process makes the connection, and Falcon records it.

Run every 15 minutes over the last 20.

**CrowdStrike (Falcon LogScale)**
```logscale
//Filter for Kerberos connections from Windows hosts
#event_simpleName=NetworkConnectIP4 event_platform=Win RemotePort=88
//Keep anything other than LSASS
| ContextBaseFileName!=/^lsass\.exe$/i
//Add the host name and display results
| match(file="aid_master_main.csv", field=aid, include=[ComputerName], strict=false)
| table([@timestamp, ComputerName, ContextBaseFileName, ContextProcessId, RemoteAddressIP4])
```

**Elastic (ES|QL)**
```esql
FROM logs-yourorg-crowdstrike-data-default* METADATA _id, _index, _version
// Filter for Kerberos connections from Windows hosts
| WHERE event.action == "networkconnectip4" AND data.event_platform == "Win" AND destination.port == 88
// Keep anything other than LSASS; a connection with no process name stays in
| WHERE data.ContextBaseFileName IS NULL OR NOT data.ContextBaseFileName IN ("lsass.exe", "LSASS.EXE", "Lsass.exe")
// Display results
| KEEP @timestamp, host.id, host.name, data.ContextBaseFileName, data.ContextProcessId, destination.ip, _id, _index, _version
```
Suppress by host for an hour.

## Before turning it on
- Check how many port-88 connections arrive without a process name. If LSASS's own connections are often unnamed, they'll all pass; require a name (`ContextBaseFileName=*` / `IS NOT NULL`) and accept that an unnamed attacker process is missed too.
  ```logscale
  #event_simpleName=NetworkConnectIP4 event_platform=Win RemotePort=88
  | groupBy([ContextBaseFileName], function=count(), limit=max)
  ```
- Run it over 7 days. Expect a few Java applications that do their own Kerberos; exclude them as host + process pairs.

## What it misses
- Linux and other non-Windows hosts, where any program may speak Kerberos.
- A proxy running inside LSASS, or tooling that uses Windows' own Kerberos (Certify, Rubeus `/ptt` followed by normal tools).

## When it fires
The process is a tool or a proxy. Open it on that host: its command line, parent and other connections (05 shows whether it also talks to the internet). Check the DC for what followed from that address (AD16, AD15).
