---
id: CS16
name: Rare program connects to RDP, SSH, SMB or WinRM on other internal hosts (activity), or a known pivot tool runs on Linux or macOS (filename fallback)
category: crowdstrike-fdr
status: todo
severity: high
language: esql
index: logs-crowdstrike.fdr-*
mitre: [T1090.001, T1572, T1021]
data_source: CrowdStrike FDR NetworkConnectIP4/IP6
suppression:
  fields: [host.id, process.name]
  duration: 24h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
When an attacker pivots through a host with a tunnel or implant (chisel, ligolo-ng, frp, a SOCKS proxy in a beacon), the program on that host opens the connections into the network for them: RDP, SSH, SMB, RPC or WinRM to other internal machines. The programs that normally do that (`mstsc`, `ssh`, PowerShell, Windows itself through `System` and `svchost`) do it on many hosts, every day.

- **Anchor:** a connection to RDP (3389), SSH (22), SMB (445), RPC (135) or WinRM (5985, 5986) on another internal host.
- **Corroborating property:** the program is new to this on this host. Its first such connection in the 7-day lookback was in the last 2 hours.
- **Exclusion by rarity:** the program does this on at most three hosts in the fleet. Admin tools and Windows components have a fleet-wide history and drop out with no list to keep.

It doesn't need the tunnel's internet connection: FDR records a connection when it opens, and an agent's outbound connection is often opened hours before the pivot. Connections to the host's own RDP or SSH (loopback) are CS15's case, from the receiving side. CS10 is the same idea for web server processes, judged per target.

## Query
Run hourly with a 7-day lookback.
```esql
FROM logs-crowdstrike.fdr-*
// Activity: a connection to RDP, SSH, SMB, RPC or WinRM on another internal host. Loopback is CS15.
// Filename fallback: a known pivot tool starting on Linux or macOS (W10 matches these by name on Windows).
| WHERE (event.action IN ("NetworkConnectIP4", "NetworkConnectIP6")
         AND destination.port IN (22, 135, 445, 3389, 5985, 5986)
         AND CIDR_MATCH(destination.ip, "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"))
     OR (event.action IN ("ProcessRollup2", "SyntheticProcessRollup2") AND host.os.type != "windows"
         AND TO_LOWER(process.name) IN ("chisel", "gost", "frpc", "frps", "revsocks", "rathole", "iox"))
| EVAL process.name = TO_LOWER(COALESCE(process.name, "unknown")), tool_start = event.action LIKE "*ProcessRollup2"
// One row per host and program: when it first reached an internal admin service (or started) in the 7 days, and where.
| STATS first_seen = MIN(@timestamp), last_seen = MAX(@timestamp), connections = COUNT(CASE(NOT tool_start, 1, NULL)),
        targets = COUNT_DISTINCT(destination.ip), destination.ip = VALUES(destination.ip), destination.port = VALUES(destination.port),
        named = MAX(CASE(tool_start, 1, 0)), process.command_line = VALUES(process.command_line),
        process.entity_id = VALUES(process.entity_id), host.name = VALUES(host.name)
    BY host.id, process.name
// Rarity: how many hosts had this program reach internal admin services, counted before the newness check.
// Admin tools and Windows itself do this across the fleet and drop out here.
| INLINE STATS hosts = COUNT_DISTINCT(host.id) BY process.name
// New for this program on this host in the last 2 hours (two hourly runs). Activity first: done by it on at most 3 hosts.
// Then the filename fallback: a known pivot tool, however many hosts run it.
| WHERE first_seen >= NOW() - 2 hours AND (hosts <= 3 OR named == 1)
| EVAL finding = CASE(named == 1 AND targets > 0, "known pivot tool reaching internal admin services",
                      named == 1, "known pivot tool started (by name)",
                      "rare program reaching internal admin services")
```

**CrowdStrike (Falcon LogScale / Advanced Event Search)**, run over the last 7 days:
```logscale
#event_simpleName=/^(NetworkConnectIP4|NetworkConnectIP6|ProcessRollup2|SyntheticProcessRollup2)$/
// Activity: a connection to RDP, SSH, SMB, RPC or WinRM on another internal host. Loopback is CS15.
// Filename fallback: a known pivot tool starting on Linux or macOS (W10 matches these by name on Windows).
| case {
    #event_simpleName=/^NetworkConnectIP[46]$/
      | in(field="RemotePort", values=["22", "135", "445", "3389", "5985", "5986"])
      | RemoteAddress := coalesce([RemoteAddressIP4, RemoteAddressIP6])
      | cidr(RemoteAddress, subnet=["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"])
      | pname := lower(ContextBaseFileName);
    event_platform!=Win FileName=/^(chisel|gost|frpc|frps|revsocks|rathole|iox)$/i
      | pname := lower(FileName) | named := 1;
  }
| default(field=pname, value="unknown", replaceEmpty=true)
// One row per host and program: when it first reached an internal admin service (or started) in the 7 days.
| groupBy([pname, aid], function=[min(@timestamp, as=first_seen), count(named, as=named),
                                  collect([ComputerName, RemoteAddress, RemotePort, CommandLine])], limit=max)
// Rarity: one row per program, counting its hosts. Activity first: on at most 3 hosts; then the filename fallback.
// Either way, the newest host started in the last 2 hours.
| groupBy([pname], function=[count(aid, distinct=true, as=hosts), max(first_seen, as=newest_start), sum(named, as=named),
                             collect([ComputerName, RemoteAddress, RemotePort, CommandLine])])
| _now := now()
| test((hosts <= 3 OR named > 0) AND newest_start > _now - 7200000)
```
LogScale has no `INLINE STATS`, so this version rolls up to one row per program, listing the (at most three) hosts it runs on and the targets they reached.

**Check before deploying:** `process.name` on network events comes from `ContextBaseFileName`, which older sensors don't send. Events without it group as `unknown`, which runs on every host and never alerts.

## Suppression
Suppress by `host.id`, `process.name` for 24h. Alerts missing a key field are not suppressed. Aggregating rule: the 7-day lookback overlaps every run, and a pivot that keeps reaching new targets folds into the open alert.

## Known false positives / exclusions
- An admin tool used on only a few workstations (PuTTY, WinSCP, MobaXterm, mRemoteNG) that hasn't been used for 7 days. It alerts when it's used again; if that's noisy, exclude those admin workstations by `host.id`.
- New software on a few servers that reaches file shares or other servers (a backup or vendor agent). It alerts once, then has a history.

## Blind spot
A tunnel tool renamed to a common admin or Windows binary (`powershell.exe`, `svchost.exe`) inherits that binary's fleet-wide history and blends in. The binary's path and hash in its ProcessRollup2 event would show it, but network events carry only the name.

## Triage
- Find the program: its ProcessRollup2 event (same `process.entity_id`) gives the path, command line and parent. An unsigned binary in a user-writable folder is the intrusion pattern.
- Find the tunnel: what this program, or anything else on the host, connected out to on the internet before `first_seen` (CS14, W10, B06).
- On each target in `destination.ip`, look for logons arriving from this host's address (4624 logon type 3 or 10).

## Test
On a lab Windows host, run a chisel client in reverse SOCKS mode to a lab server (`chisel client <server>:8080 R:socks`), then RDP through the SOCKS proxy to a second lab host. The chisel process on the lab host should alert for its connection to port 3389.
