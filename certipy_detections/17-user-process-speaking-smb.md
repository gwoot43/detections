---
id: LATMOV-04
name: A user-mode process speaks SMB on Windows (Impacket, a renamed SMB tool, smbclient.py) - not the kernel redirector
language: cql
index: logs-yourorg-crowdstrike-data-default*
mitre: [T1021.002, T1570]
data_source: CrowdStrike FDR NetworkConnectIP4/IP6
suppression:
  fields: [host.id, process.name]
  duration: 6h
  missing_fields: do_not_suppress
---
**Catches:** the Impacket suite - and any custom or renamed SMB tool, including `smbclient.py` - run from a Windows host, by the one thing they all do: the tool opens the SMB socket itself.

On Windows, normal SMB (a mapped drive, `net use`, Explorer, a logon script) is spoken by the kernel's SMB redirector, so Falcon attributes the port-445 connection to **`System`**. A *user-mode* process - `python.exe`, a frozen or renamed Impacket binary, `smbclient.py` - that opens an outbound 445 connection is speaking SMB on its own. That is a tool, not Windows. The discriminator is *who* opened the socket, so it doesn't matter what the binary is called.

This is the single-connection, low-volume cut that 16 (the 15+ host sweep) misses: it fires on one connection to one host. No rarity table - just exclude the handful of legitimate user-mode SMB agents in your estate (a backup agent, a sync client) by name.

Run every 10 minutes over the last 15.
```logscale
#event_simpleName=/^NetworkConnectIP[46]$/ event_platform=Win ConnectionDirection=0
| RemotePort=445
| RemoteAddress := coalesce([RemoteAddressIP4, RemoteAddressIP6])
| cidr(RemoteAddress, subnet=["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"])
| proc := lower(ContextBaseFileName)
// native SMB is the kernel redirector (System) or a service host; a user process on 445 is speaking SMB itself
| proc!=/^(system|svchost\.exe)$/
// allowlist the legitimate user-mode SMB agents in your estate (placeholders - fill from the baseline below)
| proc!=/^(<backup_agent>\.exe|<sync_agent>\.exe)$/
| groupBy([aid, proc], function=[count(RemoteAddress, distinct=true, as=hosts), collect([ComputerName, RemoteAddress], limit=50), min(@timestamp, as=first_seen), max(@timestamp, as=last_seen)], limit=max)
| match(file="aid_master_main.csv", field=aid, include=[ComputerName], strict=false)
| select([ComputerName, proc, hosts, RemoteAddress, first_seen, last_seen])
```
```esql
FROM logs-yourorg-crowdstrike-data-default*
// Outbound SMB (445) to an internal host from a Windows host (fc00::/7 is the internal IPv6 range, not a cast)
| WHERE event.action IN ("networkconnectip4", "networkconnectip6") AND host.os.type == "windows"
  AND destination.port == 445 AND data.ConnectionDirection == "0"
  AND CIDR_MATCH(destination.ip, "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7")
  AND process.name IS NOT NULL
| EVAL proc = TO_LOWER(process.name)
// native SMB is the kernel redirector (System) or a service host; a user process on 445 is speaking SMB itself.
// allowlist the legitimate user-mode SMB agents in your estate (placeholders - fill from the baseline below)
| WHERE NOT proc IN ("system", "svchost.exe", "<backup_agent>.exe", "<sync_agent>.exe")
| STATS hosts = COUNT_DISTINCT(destination.ip), target_sample = MV_SLICE(VALUES(destination.ip), 0, 49),
        host.name = VALUES(host.name), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
    BY host.id, proc
```
Suppress by host and process for 6h.

## What it catches and what it doesn't
- **Caught:** Impacket run from a Windows pivot (its Python or frozen process opens 445 itself), `smbclient.py` on Windows, and any renamed/custom SMB tool - because none of them go through the kernel redirector.
- **Not caught here:** Impacket run from the operator's own (usually Linux) box - the source has no Falcon. That lands target-side as the exec artifact (14), remote-exec pipes/service installs (15), share access (10) or Kerberos/IPC$ fan-out (08).
- **Not caught here:** a tool that moves over the *native* Windows SMB stack (`net use` plus a hand-run command, a mapped drive) - that shows as `System`. B04's fan-out and 10's share access catch those by volume.
- **Linux smbclient** is a different shape (Linux has no single kernel-SMB attribution) - that's detection 18.

## Before turning it on
Run it over 30 days with the allowlist empty and see which user-mode processes legitimately speak SMB in your estate:
```logscale
#event_simpleName=/^NetworkConnectIP[46]$/ event_platform=Win ConnectionDirection=0
| RemotePort=445
| proc := lower(ContextBaseFileName)
| proc!=/^(system|svchost\.exe)$/
| groupBy([proc], function=[count(aid, distinct=true, as=hosts), count(as=connections)], limit=max)
| sort(field=hosts, order=desc, limit=200)
```
The processes on many hosts are your legitimate user-mode SMB talkers (a backup or sync agent) - put them in the allowlist. Anything that then opens 445 is speaking SMB where Windows wouldn't.

## When it fires
`proc` is the program that spoke SMB (`python.exe`, a frozen Impacket exe, a renamed binary, `smbclient.py`). Find its ProcessRollup2 event for the path, command line and parent - an unsigned binary or an interpreter in a user-writable folder is the intrusion pattern. Check 14 (did a `$\__` cmd.exe run on the targets?), 15 (service installs, remote-exec pipes there) and 16 (did this process fan out to many hosts?). Treat the account and source host as compromised.
