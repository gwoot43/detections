---
id: L01
name: Reverse shell launched
category: endpoint-linux
status: todo
severity: critical
language: esql
index: logs-yourorg-crowdstrike-data-default*
mitre: [T1059.004, T1071]
data_source: CrowdStrike FDR ProcessRollup2 (Linux)
suppression:
  fields: [host.id]
  duration: 1h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
The one-liner shapes are fixed by tooling (GTFOBins, webshell payloads) and there is no administrative reason to redirect a shell's stdio to a socket.

`sh -i` is matched only as its own word (after a space, slash, quote, pipe or `;`), because `ssh -i keyfile host 2>&1` contains the same letters and is ordinary SSH with a key.

`/dev/tcp` on its own is common in health checks and `wait-for-it` scripts (`cat < /dev/null > /dev/tcp/host/port`), so it only counts together with an interactive shell, a file-descriptor duplication onto stdin (`0>&1`, `0<&`) or a read loop. Netcat flags are matched on the original-case command line, because lowercasing turns the harmless `nc -C` (send CRLF) into `-c`.

This rule matches command shapes rather than counting a behaviour: FDR doesn't record what a process's input and output are connected to, so the command is the evidence. It uses no rarity, because there's no legitimate population to measure against.

## Query
```esql
FROM logs-yourorg-crowdstrike-data-default* METADATA _id, _index, _version
| WHERE event.action == "processrollup2" AND host.os.type == "linux"
| EVAL cmd = TO_LOWER(process.command_line), pname = TO_LOWER(process.name),
       // an interactive shell (sh, bash, zsh, dash, ksh -i) as its own word, so "ssh -i keyfile" doesn't count
       shell_i = cmd RLIKE """(.*[ /\"'\|;])?(ba|z|da|k)?sh -i.*"""
// Each branch is a way of wiring a shell's input and output to a network socket. The label says which one matched.
| EVAL finding = CASE(
    // /dev/tcp alone is a common port check: it counts only with a shell, stdin duplication or a read loop
    (cmd LIKE "*/dev/tcp/*" OR cmd LIKE "*/dev/udp/*") AND (cmd LIKE "*0>&1*" OR cmd LIKE "*0<&*" OR shell_i OR cmd LIKE "*while read*"),
      "/dev/tcp or /dev/udp with shell or stdin duplication",
    // netcat flags on the original case: lowercasing turns the harmless -C (send CRLF) into -c
    pname IN ("nc", "ncat", "netcat", "nc.traditional", "nc.openbsd")
      AND (process.command_line LIKE "* -e *" OR process.command_line LIKE "* -c *" OR cmd LIKE "*--exec*" OR cmd LIKE "*--sh-exec*"),
      "netcat with exec",
    // a named pipe feeding netcat, or socat joining a program to a socket
    cmd LIKE "*mkfifo*" AND (cmd LIKE "*nc *" OR cmd LIKE "*ncat*"), "mkfifo netcat relay",
    cmd LIKE "*socat*" AND cmd LIKE "*exec:*" AND (cmd LIKE "*tcp:*" OR cmd LIKE "*tcp4:*" OR cmd LIKE "*openssl:*"), "socat exec to socket",
    // interpreter one-liners: open a socket, then hand it to a shell
    pname LIKE "python*" AND cmd LIKE "*socket*" AND (cmd LIKE "*dup2*" OR cmd LIKE "*pty.spawn*") AND cmd LIKE "*connect*", "python socket shell",
    pname LIKE "perl*" AND cmd LIKE "*socket*" AND cmd LIKE "*exec*", "perl socket shell",
    pname LIKE "php*" AND cmd LIKE "*fsockopen*" AND cmd LIKE "*/bin/sh*", "php fsockopen shell",
    pname LIKE "ruby*" AND cmd LIKE "*tcpsocket*" AND cmd LIKE "*exec*", "ruby socket shell",
    // an interactive shell with its input or output redirected to a descriptor
    (cmd LIKE "*bash -i*" AND cmd LIKE "*>&*") OR (shell_i AND (cmd LIKE "*<&*" OR cmd LIKE "*>&*")), "interactive shell redirected",
    pname == "openssl" AND cmd LIKE "*s_client*" AND (cmd LIKE "*| /bin/sh*" OR cmd LIKE "*| bash*"), "openssl s_client piped to shell",
    NULL)
| WHERE finding IS NOT NULL
| KEEP @timestamp, host.id, host.name, user.name, finding, process.parent.name, pname, process.command_line,
       process.parent.entity_id, _id, _version, _index
```

**CrowdStrike (Falcon LogScale / Advanced Event Search)**
```logscale
#event_simpleName=/^(ProcessRollup2|SyntheticProcessRollup2)$/ event_platform=Lin
// Each branch is a way of wiring a shell's input and output to a network socket. The label says which one matched.
| case {
    // /dev/tcp alone is a common port check: it counts only with a shell, stdin duplication or a read loop
    CommandLine=/\/dev\/(tcp|udp)\//i CommandLine=/0>&1|0<&|(^|[\s\/"'|;])(ba|z|da|k)?sh -i|while read/i
      | finding := "/dev/tcp or /dev/udp with shell or stdin duplication";
    // netcat flags on the original case: lowercasing turns the harmless -C (send CRLF) into -c
    in(field="FileName", ignoreCase=true, values=["nc", "ncat", "netcat", "nc.traditional", "nc.openbsd"])
      | (CommandLine=/ -(e|c) / OR CommandLine=/--(sh-)?exec/i)
      | finding := "netcat with exec";
    // a named pipe feeding netcat, or socat joining a program to a socket
    CommandLine=/mkfifo/i CommandLine=/nc |ncat/i
      | finding := "mkfifo netcat relay";
    CommandLine=/socat/i CommandLine=/exec:/i CommandLine=/tcp4?:|openssl:/i
      | finding := "socat exec to socket";
    // interpreter one-liners: open a socket, then hand it to a shell
    FileName=/^python/i CommandLine=/socket/i CommandLine=/dup2|pty\.spawn/i CommandLine=/connect/i
      | finding := "python socket shell";
    FileName=/^perl/i CommandLine=/socket/i CommandLine=/exec/i
      | finding := "perl socket shell";
    FileName=/^php/i CommandLine=/fsockopen/i CommandLine=/\/bin\/sh/i
      | finding := "php fsockopen shell";
    FileName=/^ruby/i CommandLine=/tcpsocket/i CommandLine=/exec/i
      | finding := "ruby socket shell";
    // an interactive shell with its input or output redirected to a descriptor
    CommandLine=/bash -i/i CommandLine=/>&/
      | finding := "interactive shell redirected";
    CommandLine=/(^|[\s\/"'|;])(ba|z|da|k)?sh -i/i CommandLine=/[<>]&/
      | finding := "interactive shell redirected";
    FileName=/^openssl$/i CommandLine=/s_client/i CommandLine=/\| (\/bin\/sh|bash)/i
      | finding := "openssl s_client piped to shell";
  }
| table([@timestamp, aid, ComputerName, UserName, finding, ParentBaseFileName, FileName, CommandLine, ParentProcessId])
```

## Suppression
Suppress by `host.id` for 1h. Alerts missing a key field are not suppressed. Reverse shells reconnect repeatedly. `host.id` is the Falcon agent ID and is always present; `host.name` is filled only when the integration's host metadata enrichment is on.

## Known false positives / exclusions
- Health checks that use `/dev/tcp` to test a port no longer match unless they also start an interactive shell or duplicate a descriptor onto stdin. If one still does, exclude its exact command line.

## Triage
- Isolate in Falcon. Identify the parent chain (FDR has no parent command line; find the parent's own ProcessRollup2 by `process.parent.entity_id`): a web server parent means L03, a cron parent means L04.

## Test
Run the Atomic Red Team T1059.004 reverse-shell test against a local listener on a lab host.
