---
id: CS11
name: Program starts accepting connections from other internal hosts, new on this host and rare in the fleet (implant listener or pivot)
category: crowdstrike-fdr
status: todo
severity: medium
language: esql
index: logs-crowdstrike.fdr-*
mitre: [T1090.001, T1572, T1571]
data_source: CrowdStrike FDR NetworkReceiveAcceptIP4
suppression:
  fields: [host.id, pname]
  duration: 24h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
When an attacker turns a compromised host into a relay, something on that host starts accepting connections from other internal machines: a SOCKS proxy from an implant, a `chisel` or `ligolo` server, a bind-TCP beacon, or a tool listening for the next hop. Falcon records each accepted inbound connection with the program that accepted it.

The rule asks one question: did a program start accepting TCP connections from other internal hosts on a host where it never did in the last 7 days, and is it a program almost no other host does this with? Software that legitimately takes inbound connections (SQL Server, IIS, monitoring and backup agents, Windows services) does it every day and on many hosts, so it is in the history and drops out without a list.

Well-known service ports (DNS, Kerberos, LDAP, SMB, RPC endpoint mapper, HTTP/S, SQL Server, global catalog) are left out. They carry most inbound volume on servers and domain controllers, and a tool listening for a pivot can't take them because the real service already holds them.

Port forwarding with `netsh portproxy` is CS09: the forward is accepted by a Windows service that runs everywhere, so this rule won't see it.

## Query
Run hourly with a 7-day lookback.
```esql
FROM logs-crowdstrike.fdr-*
| WHERE event.action == "NetworkReceiveAcceptIP4" AND network.transport == "tcp"
  AND CIDR_MATCH(source.ip, "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
  AND NOT destination.port IN (53, 80, 88, 135, 389, 443, 445, 636, 1433, 3268, 3269)
| EVAL pname = TO_LOWER(COALESCE(process.name, "unknown"))
| STATS first_seen = MIN(@timestamp),
        last_seen = MAX(@timestamp),
        accepts = COUNT(*),
        peers = COUNT_DISTINCT(source.ip),
        peer_ips = VALUES(source.ip),
        ports = VALUES(destination.port),
        host.name = VALUES(host.name)
    BY host.id, pname
| INLINE STATS hosts = COUNT_DISTINCT(host.id) BY pname
| WHERE first_seen >= NOW() - 2 hours AND hosts <= 3
| KEEP host.id, host.name, pname, ports, peers, peer_ips, accepts, first_seen, last_seen, hosts
```

**CrowdStrike (Falcon LogScale / Advanced Event Search)**, run over the last 7 days:
```logscale
#event_simpleName=NetworkReceiveAcceptIP4 Protocol=6
| cidr(RemoteAddressIP4, subnet=["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"])
| !in(field="LocalPort", values=["53", "80", "88", "135", "389", "443", "445", "636", "1433", "3268", "3269"])
| pname := lower(ContextBaseFileName)
| default(field=pname, value="unknown", replaceEmpty=true)
| groupBy([pname, aid], function=[min(@timestamp, as=first_seen), collect([ComputerName, RemoteAddressIP4, LocalPort])], limit=max)
| groupBy([pname], function=[count(aid, distinct=true, as=hosts), max(first_seen, as=newest_start),
                             collect([ComputerName, RemoteAddressIP4, LocalPort])])
| _now := now()
| test(hosts <= 3 AND newest_start > _now - 7200000)
| newest_start := formatTime(format="%F %T", field=newest_start, timezone="Australia/Sydney")
```
LogScale has no `INLINE STATS`, so this version rolls up to one row per program, listing the (at most three) hosts it runs on. It alerts when the newest of those hosts started accepting connections in the last 2 hours.

- **`first_seen`** is when this program first accepted an internal connection on this host in the 7 days. Only programs that started in the last 2 hours (two hourly runs) alert, so a long-running listener alerts once, not every hour.
- **`hosts`** is how many hosts in the fleet had the same program accept internal connections in the 7 days. Three or fewer means it isn't normal software.
- **`peer_ips`** are the machines that connected in: the attacker's previous hop.

**Check before deploying:** `process.name` on these events comes from `ContextBaseFileName`, which older sensors don't send. Run `FROM logs-crowdstrike.fdr-* | WHERE event.action == "NetworkReceiveAcceptIP4" | STATS COUNT(*) BY has_name = process.name IS NOT NULL` over a day. If most events have no name they all group as `unknown`, which runs on every host and never alerts, so the rule would be blind.

## Suppression
Suppress by `host.id`, `pname` for 24h. Alerts missing a key field are not suppressed. Aggregating rule: the 7-day lookback overlaps every run. A different host or program still alerts.

## Known false positives / exclusions
- Software newly installed on one or two servers that takes inbound connections (a vendor agent, a licence server). It alerts once; if it's expected, exclude it by `pname` and host.
- Developer machines running a local web server or debugger that a colleague connects to. Expect a few; confirm with the user.

## Triage
- Look at `pname` and where it runs from (its ProcessRollup2 event on the same host). An unsigned binary in a user-writable folder, or a renamed system tool, is the listener of an implant or tunnel.
- `peer_ips` are the hosts that connected in. Check each for the same activity: the attacker usually came from there.
- Check what this host connected out to after the inbound connections started; a pivot relays traffic onward.

## Test
On a lab Windows host, run `ncat -lk 8443` (or a test SOCKS proxy) and connect to it from another lab host.
