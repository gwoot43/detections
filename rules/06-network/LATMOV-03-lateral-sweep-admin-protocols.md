---
id: LATMOV-03
name: One host reaching 15+ internal hosts on remote-admin ports in a short window (lateral sweep)
language: esql
index: logs-yourorg-crowdstrike-data-default*
mitre: [T1021, T1570, T1018]
data_source: CrowdStrike FDR NetworkConnectIP4/IP6
suppression:
  fields: [host.id, process.name]
  duration: 2h
  missing_fields: do_not_suppress
---
**Catches:** one program on one host reaching out to many other internal hosts on the remote-execution and remote-admin ports in a short window. That is lateral movement at scale - a NetExec / CrackMapExec run, a PsExec loop, a BloodHound-style reach-to-every-computer - whatever the tool is called.

The signal is the **fan-out**: how many distinct internal hosts one process touched on SMB (445), RPC (135), WinRM (5985/5986) or RDP (3389). A workstation does not WinRM or RDP to fifteen machines in ten minutes. This counts distinct destinations per process, so a renamed binary is caught the same way - no name list, no fleet-wide rarity table. It's a plain threshold on one number.

Run every 10 minutes with a 15-minute lookback.
```esql
FROM logs-yourorg-crowdstrike-data-default*
// Windows connections to internal hosts on remote-exec / remote-admin ports
| WHERE event.action IN ("networkconnectip4", "networkconnectip6") AND host.os.type == "windows"
  AND destination.port IN (445, 135, 5985, 5986, 3389)
  AND CIDR_MATCH(destination.ip, "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7")
| EVAL process.name = TO_LOWER(COALESCE(process.name, "unknown"))
// One row per source host and program: how many distinct internal hosts it reached, and on which ports
| STATS targets = COUNT_DISTINCT(destination.ip), ports = VALUES(destination.port),
        target_sample = MV_SLICE(VALUES(destination.ip), 0, 49), host.name = VALUES(host.name),
        first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
    BY host.id, process.name
// 15+ distinct internal hosts in the window is a sweep (starting value - baseline below)
| WHERE targets >= 15
```

**CrowdStrike (Falcon LogScale)**
```logscale
#event_simpleName=/^NetworkConnectIP[46]$/ event_platform=Win
// Connections to internal hosts on remote-exec / remote-admin ports
| in(field="RemotePort", values=["445", "135", "5985", "5986", "3389"])
| RemoteAddress := coalesce([RemoteAddressIP4, RemoteAddressIP6])
| cidr(RemoteAddress, subnet=["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"])
| pname := lower(ContextBaseFileName)
| default(field=pname, value="unknown", replaceEmpty=true)
// One row per source host and program: how many distinct internal hosts it reached
| groupBy([aid, pname], function=[count(RemoteAddress, distinct=true, as=targets), collect([ComputerName, RemotePort, RemoteAddress], limit=50)], limit=max)
// 15+ distinct internal hosts in the window is a sweep (starting value - baseline below)
| targets >= 15
| match(file="aid_master_main.csv", field=aid, include=[ComputerName], strict=false)
| select([ComputerName, pname, targets, RemotePort, RemoteAddress])
```
Suppress by host and process for 2h.

## Before turning it on
- Run it over a week without the `targets >= 15` line to see how far one process normally fans out, and set the number from that. 15 is a starting value.
- Exclude admin jump hosts, patch/config servers (SCCM) and vulnerability scanners by `host.id` (the Falcon agent ID) - not `host.name`, which can be empty: `| !in(field="aid", values=["<jump01_aid>", "<sccm01_aid>"])`.
- `process.name` on Falcon network events comes from `ContextBaseFileName`; older sensors don't send it, so those events group as `unknown` (every process on the host) and the count is inflated. Check how many arrive without it.

## What it misses
- A slow, low-and-slow sweep under 15 hosts per window, or spread across many windows - raise the lookback or lower the threshold to trade noise for reach.
- LDAP directory fan-out (a collector hitting several domain controllers): that's a different, lower threshold - B04 carries it as a separate tier, and 08 is the BloodHound-specific version.
- The source renamed to a Windows binary with a fleet-wide history doesn't hide here - this counts fan-out per process, so the connections still pile up under that name.

## When it fires
`process.name` is the program, `targets` is how many hosts it hit, `ports` says which protocols. Find its ProcessRollup2 event for the path, command line and parent - an unsigned binary in a user-writable folder is the intrusion pattern. A lateral sweep plus credential access on the source (B08) is hands-on-keyboard movement. On each destination, look for a service install or a `$\__` cmd.exe (14, 15) and logons arriving from this host (4624 type 3).
