---
id: DIRENUM-01
name: Directory enumeration sweep - one process reaching several directory servers over LDAP, Global Catalog or ADWS (9389)
language: cql
index: logs-yourorg-crowdstrike-data-default*
mitre: [T1087.002, T1069.002, T1018, T1046]
data_source: CrowdStrike FDR NetworkConnectIP4/IP6
suppression:
  fields: [host.id, process.name, finding]
  duration: 6h
  missing_fields: do_not_suppress
---
**Catches:** directory collection - SharpHound/BloodHound, ADExplorer, ldapdomaindump, SOAPHound - by the shape it leaves on the network, not the tool name. One consolidated LDAP rule covering every directory port, including the one the LDAP-only rules miss.

A collector reads the directory and then reaches out across it, so one process connects to **several directory servers** in a short time. An estate has a handful of domain controllers, not hundreds, and a normal client (an app, a logged-on user's `Get-ADUser`) queries **one**. One process reaching three or more is enumeration.

It watches every directory port in one place:
- **389 / 636** - LDAP / LDAPS
- **3268 / 3269** - Global Catalog
- **9389 - AD Web Services (ADWS).** The one the LDAP rules miss. ADWS answers the same directory questions over SOAP, so **SOAPHound** (built to dodge LDAP-based detection) and the AD PowerShell module use it instead of 389. A collector that knows your rules watch 389/636/3268 just points at 9389 - so `finding` flags `directory_sweep_adws` when 9389 is in the mix, because a non-admin fanning out over ADWS is the evasion path.

Netlogon's DC locator (inside `lsass.exe`) pings several DCs to find one - that's normal discovery, excluded by process.

Run every 10 minutes over the last 15.
```logscale
#event_simpleName=/^NetworkConnectIP[46]$/ ConnectionDirection=0
| in(field="RemotePort", values=["389", "636", "3268", "3269", "9389"])
| RemoteAddress := coalesce([RemoteAddressIP4, RemoteAddressIP6])
| cidr(RemoteAddress, subnet=["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"])
| proc := lower(ContextBaseFileName)
// Netlogon's DC locator (inside lsass) pings several DCs to find one - normal discovery, not enumeration
| proc!="lsass.exe"
| adws := if(RemotePort=="9389", then=1, else=0)
// per host and process: how many distinct directory servers it reached, and whether any was over ADWS
| groupBy([aid, proc], function=[count(RemoteAddress, distinct=true, as=directory_servers), max(adws, as=over_adws),
    collect([ComputerName, RemoteAddress, RemotePort], limit=50), min(@timestamp, as=first_seen), max(@timestamp, as=last_seen)], limit=max)
// one process reaching 3+ directory servers is enumeration (handful of DCs in an estate; starting value - baseline below)
| directory_servers >= 3
| case {
    over_adws=1 | finding := "directory_sweep_adws" ;
    * | finding := "directory_sweep" ;
  }
| match(file="aid_master_main.csv", field=aid, include=[ComputerName], strict=false)
| select([ComputerName, proc, directory_servers, over_adws, RemoteAddress, RemotePort, finding, first_seen, last_seen])
```
```esql
FROM logs-yourorg-crowdstrike-data-default*
// outbound connections to directory services: LDAP, LDAPS, Global Catalog, ADWS (fc00::/7 is the internal IPv6 range)
| WHERE event.action IN ("networkconnectip4", "networkconnectip6") AND data.ConnectionDirection == "0"
  AND destination.port IN (389, 636, 3268, 3269, 9389)
  AND CIDR_MATCH(destination.ip, "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7")
  AND process.name IS NOT NULL
| EVAL proc = TO_LOWER(process.name), adws = destination.port == 9389
// Netlogon's DC locator (inside lsass) pings several DCs to find one - normal discovery, not enumeration
| WHERE proc != "lsass.exe"
// per host and process: how many distinct directory servers it reached, and whether any was over ADWS
| STATS directory_servers = COUNT_DISTINCT(destination.ip), ports = VALUES(destination.port), over_adws = MAX(CASE(adws, 1, 0)),
        server_sample = MV_SLICE(VALUES(destination.ip), 0, 19), host.name = VALUES(host.name),
        first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
    BY host.id, proc
// one process reaching 3+ directory servers is enumeration (handful of DCs in an estate; starting value - baseline below)
| WHERE directory_servers >= 3
| EVAL finding = CASE(over_adws == 1, "directory_sweep_adws", "directory_sweep")
```
Suppress by host, process and finding for 6h.

## Where this sits
- Supersedes the LDAP-port angle scattered across the library (B04's `ldap_dc_fanout` tier, the directory leg of 05): one process, every directory port, 9389 included.
- **05** (one process proxying into AD) is the companion for a collector run **through a SOCKS pivot** - there the directory connection shows the pivot, not the DC, so the fan-out here won't see it.
- **08** (BloodHound sweep) is the **Kerberos + IPC$** angle (4769 to computer SPNs, 5140 to IPC$). SharpHound trips both - this one from the directory side by process, 08 from the target side by account.
- **04** (Kerberos from a process other than lsass) is the **port-88** leg of the same tradecraft.

## What it misses
- **A single-DC collection.** LDAP and ADWS pull the whole directory down one connection, so a collector pointed at one DC reaches one server and stays under the fan-out threshold. The directory read itself isn't a network-volume signal. If you want the single-DC ADWS case, watch **9389 from a process that isn't your admin tooling** (`powershell.exe`, `mmc.exe`, management servers) - run the baseline below to see who that is, then alert on the rest.
- A collector renamed to `lsass.exe` to inherit the exclusion - its ProcessRollup2 path and parent would still show it.
- Collection through a SOCKS pivot - that's 05.

## Before turning it on
See who talks to directory services, and how far they fan out, so you set the threshold and know your ADWS talkers:
```logscale
#event_simpleName=/^NetworkConnectIP[46]$/ ConnectionDirection=0
| in(field="RemotePort", values=["389", "636", "3268", "3269", "9389"])
| proc := lower(ContextBaseFileName)
| proc!="lsass.exe"
| groupBy([proc, RemotePort], function=[count(aid, distinct=true, as=hosts), count(RemoteAddressIP4, distinct=true, as=servers)], limit=max)
| sort(field=servers, order=desc, limit=200)
```
`powershell.exe` and your management/identity servers (Exchange, Entra Connect, ADFS, monitoring) are the legitimate fan-out and the legitimate ADWS talkers - exclude them as host + process pairs. In an estate with only two DCs per site, drop the threshold to 2; raise it if a tool normally talks to several.

## When it fires
`proc` is the collector, `directory_servers` how many it hit, `ports` which (a mix of 389 and 3268 is SharpHound-style LDAP+GC; **9389 means ADWS - treat `directory_sweep_adws` as the evasion path and higher interest**). Find the process's ProcessRollup2 event for the path, command line and parent - an unsigned binary in a user-writable folder, or a shell under a web worker (13), is the intrusion. Check 04 (Kerberos leg), 08 (IPC$/ticket fan-out) and 16/B04 (lateral movement) on the same host; a directory sweep is reconnaissance for what comes next.
