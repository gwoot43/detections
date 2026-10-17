---
id: L14
name: Program started from a temp folder or memory opens a listening port (tunneller, proxy or bind shell)
category: endpoint-linux
status: todo
severity: high
language: esql
index: logs-crowdstrike.fdr-*
mitre: [T1090.001, T1572]
data_source: CrowdStrike FDR ProcessRollup2 and NetworkListenIP4/IP6 (Linux)
suppression:
  fields: [host.id, process.executable]
  duration: 24h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
Tunnellers, SOCKS proxies and bind shells dropped onto a Linux server have to listen for connections, and attackers drop them where any account can write: `/tmp`, `/var/tmp`, `/dev/shm`, or straight into memory. Real services are installed by packages into `/usr`, `/opt` or `/srv` and listen from there. In ARMORY CASTLE's BeyondTrust intrusion (Google Threat Intelligence, October 2026) the actor ran the BARECLAW SOCKS5-over-WebSocket tunneller as `/tmp/ingredi_ws --listen 19800`. They then pointed the appliance's reverse proxy at it on `127.0.0.1`, so it was reachable from the internet but invisible to an external scan.

- **Anchor:** a process that opened a listening socket.
- **Corroborating property:** the process started from a temp folder or from memory (`memfd`). Falcon records the path on the process start, not on the listen event, so the two are joined on the process ID.
- **Exclusion:** Go's own build and test binaries, which run from `/tmp/go-build*` and often listen on localhost.

It doesn't matter who connects, so it covers what CS11 can't see: a listener reached only through a reverse proxy on the same host, as BARECLAW was. CS11 covers listeners that other internal hosts connect to, wherever they're installed.

## Query
Run every 15 minutes with a 1-hour lookback.
```esql
FROM logs-crowdstrike.fdr-*
// Two event types, joined on the process below: Linux programs started from a temp folder or memory, and listening sockets.
| WHERE host.os.type == "linux"
  AND ((event.action == "ProcessRollup2"
        AND (process.executable LIKE "/tmp/*" OR process.executable LIKE "/var/tmp/*" OR process.executable LIKE "/dev/shm/*"
             OR process.executable LIKE "/memfd:*")
        // Go builds and runs its test binaries from /tmp/go-build*, and tests often listen on localhost.
        AND NOT process.executable LIKE "/tmp/go-build*")
       OR event.action IN ("NetworkListenIP4", "NetworkListenIP6"))
// The start event gives the path, the listen event the port (a listen event's own port is in source.port).
| EVAL started_from = CASE(event.action == "ProcessRollup2", process.executable, NULL),
       listen_port = CASE(event.action != "ProcessRollup2", source.port, NULL)
// One row per process: where it started from and the ports it listened on.
| STATS process.executable = VALUES(started_from), source.port = VALUES(listen_port), first_seen = MIN(@timestamp),
        process.command_line = VALUES(process.command_line), process.parent.name = VALUES(process.parent.name),
        user.id = VALUES(user.id), host.name = VALUES(host.name)
    BY host.id, process.entity_id
// Alert on a process that did both.
| WHERE process.executable IS NOT NULL AND source.port IS NOT NULL
```

**CrowdStrike (Falcon LogScale / Advanced Event Search)**, run over the last hour:
```logscale
(#event_simpleName=ProcessRollup2 event_platform=Lin ImageFileName=/^(\/tmp\/|\/var\/tmp\/|\/dev\/shm\/|\/memfd:)/ ImageFileName!=/^\/tmp\/go-build/)
  or (#event_simpleName=/^NetworkListenIP[46]$/ event_platform=Lin)
// Join the start and the listen on the process: TargetProcessId on the start, ContextProcessId on the listen.
| falcon_pid := coalesce([TargetProcessId, ContextProcessId])
| case {
    #event_simpleName=ProcessRollup2 | kind := "start";
    * | kind := "listen";
  }
// One row per process. Alert when it has both a temp-folder start and a listen.
| groupBy([aid, falcon_pid], function=[count(kind, distinct=true, as=kinds), collect([ComputerName, ImageFileName, CommandLine, ParentBaseFileName, UID, LocalPort])],
          limit=max)
| test(kinds == 2)
```

**Check before deploying:** the path Falcon records for a program run from memory isn't confirmed for every sensor version. Run a `memfd` loader in the lab (Test below) and adjust the `/memfd:` pattern to what appears in `process.executable`.

## Suppression
Suppress by `host.id`, `process.executable` for 24h. Alerts missing a key field are not suppressed. The lookback overlaps the last run, and a tool that restarts folds into the open alert.

## Known false positives / exclusions
- An installer or vendor support tool unpacked to `/tmp` that runs a short-lived local web server. Rare on servers. Exclude by exact `process.executable` once it's identified.
- AppImage applications on Linux desktops run from `/tmp/.mount_*` and some listen on localhost. If you manage Linux desktops, exclude that prefix.

## Triage
- Find the tool: the command line and the port. A `--listen`, `--token` or `socks` argument names a tunneller. Hash the file (`process.entity_id` leads to the start event), and capture it before the attacker deletes it.
- Find who reaches it. On a server with a reverse proxy (HAProxy, nginx, Apache), look for a new backend or route that sends a path to `127.0.0.1:<port>`; BARECLAW was exposed through an HAProxy `use_backend` rule on one path. Without one, look for connections arriving at the port (CS11).
- Find how it got there: the parent process (a web server or its shell, L03) and the download before it (L02).

## Test
On a lab Linux host, copy `nc` to `/tmp/lab-listener` and run `/tmp/lab-listener -l 19800`. It should alert within 15 minutes. For the memory case, start a listener from a `memfd` loader (for example a short Python script using `os.memfd_create` and `os.execv`) and note the path Falcon records.
