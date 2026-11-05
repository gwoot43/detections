---
id: CERTIPY-05
name: One process talking to the internet and to Kerberos or LDAP on internal hosts (a SOCKS proxy into AD - Certipy, ADExplorer, ldapdomaindump)
language: esql
index: logs-yourorg-crowdstrike-data-default*
mitre: [T1090, T1087.002, T1649]
data_source: CrowdStrike FDR NetworkConnectIP4
suppression:
  fields: [host.id]
  duration: 6h
  missing_fields: do_not_suppress
---
Run through a SOCKS proxy, `certipy find`, `certipy auth`, ADExplorer and ldapdomaindump all reach AD from the pivot host: the proxy process connects to the DC on LDAP (389, 636, 3268, 3269) or Kerberos (88). The same process also talks to the attacker over the internet. Normal Windows LDAP and Kerberos clients (LSASS, Group Policy, `mmc`) don't talk to the internet; a beacon in `rundll32`, chisel or `ssh` acting as the proxy does both.

It doesn't depend on the tool, its name, or how it authenticates.

Run hourly over the last hour.

**CrowdStrike (Falcon LogScale)**
```logscale
//Filter for outbound connections from Windows processes
#event_simpleName=NetworkConnectIP4 event_platform=Win ConnectionDirection=0
//Keep processes that connected both to Kerberos or LDAP inside the network and to the internet
| selfJoinFilter(field=[aid, ContextProcessId], where=[{RemotePort=/^(88|389|636|3268|3269)$/ RemoteAddressIP4=/^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.)/}, {RemoteAddressIP4!=/^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.|127\.|169\.254\.)/}])
//Group by host and process
| groupBy([aid, ContextProcessId], function=[collect([ContextBaseFileName]), collect([RemoteAddressIP4, RemotePort], limit=20), count(as=connections), min(@timestamp, as=first_seen)], limit=max)
//Leave out the agents that sync AD to the cloud by design (placeholders)
| NOT ContextBaseFileName=/^(miiserver|Microsoft\.Tri\.Sensor|<idp_agent>)\.exe$/i
//Add the host name and display results
| match(file="aid_master_main.csv", field=aid, include=[ComputerName], strict=false)
| table([ComputerName, ContextBaseFileName, ContextProcessId, connections, RemoteAddressIP4, RemotePort, first_seen])
```

**Elastic (ES|QL)**
```esql
FROM logs-yourorg-crowdstrike-data-default*
// Filter for outbound connections from Windows processes
| WHERE event.action == "networkconnectip4" AND data.event_platform == "Win" AND data.ConnectionDirection == "0"
  AND data.ContextProcessId IS NOT NULL AND destination.ip IS NOT NULL
// Mark connections that stay inside the network
| EVAL internal = CIDR_MATCH(destination.ip, "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10",
                             "127.0.0.0/8", "169.254.0.0/16")
// Group by process: Kerberos or LDAP connections inside, connections to the internet
| STATS ad_connections = COUNT(*) WHERE internal AND destination.port IN (88, 389, 636, 3268, 3269),
        internet_connections = COUNT(*) WHERE NOT internal,
        process = TOP(data.ContextBaseFileName, 1, "asc"), host.name = VALUES(host.name), first_seen = MIN(@timestamp)
    BY host.id, data.ContextProcessId
// Keep processes that did both
| WHERE ad_connections > 0 AND internet_connections > 0
// Leave out the agents that sync AD to the cloud by design (placeholders)
| WHERE process IS NULL OR NOT process IN ("miiserver.exe", "Microsoft.Tri.Sensor.exe", "<idp_agent>.exe")
```
Suppress by host for 6h.

## Before turning it on
- Run it over 7 days. The expected noise is small and known: Entra Connect (`miiserver.exe`), the Defender for Identity sensor (`Microsoft.Tri.Sensor.exe`), identity-provider agents (Okta's AD agent, Duo's authentication proxy), and possibly Zscaler Client Connector if remote users reach the DCs through ZPA. Exclude them as host + process pairs.
- Run your SOCKS tests and check the pivot shows connections to the DC on 389 or 88, credited to the proxy process.
- The ES|QL version groups every process with a connection in the hour; if that's heavy, run it every 2 hours.

## What it misses
- Peer-to-peer C2, where the pivot's implant reaches the internet through another internal host (an SMB beacon chain): the pivot's process has no internet connection. 04 still sees its Kerberos.
- A proxy split across two processes, one for the C2 and one for the AD traffic.
- Pivots that aren't Windows.

## When it fires
The process is the proxy. Its internet connections are the attacker's infrastructure; its AD connections say what was reached. Check the DCs for logons from this host's address in the same window (01) and the CA for requests (03, AD14).
