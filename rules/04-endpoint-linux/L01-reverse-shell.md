---
id: L01
name: Reverse shell launched
category: endpoint-linux
status: todo
severity: critical
language: esql
index: logs-crowdstrike.fdr-*
mitre: [T1059.004, T1071]
data_source: CrowdStrike FDR ProcessRollup2 (Linux)
suppression:
  fields: [host.name]
  duration: 1h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
The one-liner shapes are fixed by tooling (GTFOBins, webshell payloads) and there is no administrative reason to redirect a shell's stdio to a socket.

## Query
```esql
FROM logs-crowdstrike.fdr-* METADATA _id, _index, _version
| WHERE event.action == "ProcessRollup2" AND host.os.type == "linux"
| EVAL cmd = TO_LOWER(process.command_line), pname = TO_LOWER(process.name)
| WHERE cmd LIKE "*/dev/tcp/*" OR cmd LIKE "*/dev/udp/*"
   OR (pname IN ("nc", "ncat", "netcat", "nc.traditional", "nc.openbsd") AND (cmd LIKE "* -e *" OR cmd LIKE "* -c *" OR cmd LIKE "*--exec*" OR cmd LIKE "*--sh-exec*"))
   OR (cmd LIKE "*mkfifo*" AND (cmd LIKE "*nc *" OR cmd LIKE "*ncat*"))
   OR (cmd LIKE "*socat*" AND cmd LIKE "*exec:*" AND (cmd LIKE "*tcp:*" OR cmd LIKE "*tcp4:*" OR cmd LIKE "*openssl:*"))
   OR (pname LIKE "python*" AND cmd LIKE "*socket*" AND (cmd LIKE "*dup2*" OR cmd LIKE "*pty.spawn*") AND cmd LIKE "*connect*")
   OR (pname LIKE "perl*" AND cmd LIKE "*socket*" AND cmd LIKE "*exec*")
   OR (pname LIKE "php*" AND cmd LIKE "*fsockopen*" AND cmd LIKE "*/bin/sh*")
   OR (pname LIKE "ruby*" AND cmd LIKE "*tcpsocket*" AND cmd LIKE "*exec*")
   OR (cmd LIKE "*bash -i*" AND cmd LIKE "*>&*")
   OR (cmd LIKE "*sh -i*" AND (cmd LIKE "*<&*" OR cmd LIKE "*>&*"))
   OR (pname == "openssl" AND cmd LIKE "*s_client*" AND (cmd LIKE "*| /bin/sh*" OR cmd LIKE "*| bash*"))
| KEEP @timestamp, host.name, user.name, process.parent.name, pname, process.command_line, process.parent.command_line
```

## Suppression
Suppress by `host.name` for 1h. Alerts missing a key field are not suppressed. Reverse shells reconnect repeatedly.

## Known false positives / exclusions
- Health checks using `/dev/tcp` to test a port. Exclude the exact command line from the monitoring agent.

## Triage
- Isolate in Falcon. Identify the parent chain: a web server parent means L03, a cron parent means L04.

## Test
Use a lab host with a local listener and Atomic Red Team T1059.004.
