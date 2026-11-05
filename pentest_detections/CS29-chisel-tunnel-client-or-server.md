---
id: CS29
name: chisel tunnel client or server - verbs, R:socks spec and tunnel flags
category: crowdstrike-fdr
status: todo
language: esql
index: logs-yourorg-crowdstrike-data-default*
mitre: [T1572, T1090.001]
data_source: CrowdStrike FDR ProcessRollup2
suppression:
  fields: [host.id, user.name]
  duration: 24h
  missing_fields: do_not_suppress
---

## Why this is high fidelity

chisel is the tunnel of choice in most engagements right now: one Go binary, no install, works over a single
outbound HTTPS connection, and it exposes a SOCKS proxy so every subsequent tool rides the same channel. `CS14`
catches the hosted tunnel *services* by their ports; a chisel binary compiled by the tester has no such port.

What it does have is its argument grammar. It is a `client` or a `server`, it takes a `host:port` spec, and when it
is exposing a SOCKS proxy the spec is **`R:socks`** - a string that appears in no normal command line on any
operating system. The flags (`--auth`, `--fingerprint`, `--tls-ca`, `--proxy`) are equally distinctive.

This is a name-and-shape rule rather than a behaviour rule, so it fails against a renamed binary. `CS30` and `CS11`
are the behavioural net underneath it: a pivot has to accept connections and carry them out, whatever it is called.

## Query

```esql
FROM logs-yourorg-crowdstrike-data-default*
| WHERE @timestamp >= NOW() - 1 hour
  AND event.action IN ("processrollup2", "syntheticprocessrollup2")
| EVAL cmd = TO_LOWER(COALESCE(process.command_line, "")),
       proc = TO_LOWER(COALESCE(process.name, "")),
       parent = TO_LOWER(COALESCE(process.parent.name, ""))
// the verbs and the tunnel spec. R:socks is chisel's remote-SOCKS syntax; the flags below have no benign use
// outside chisel itself.
| WHERE cmd LIKE "*chisel client*" OR cmd LIKE "*chisel server*"
     OR cmd LIKE "*chisel.exe client*" OR cmd LIKE "*chisel.exe server*"
     OR cmd LIKE "*r:socks*"
     OR (proc LIKE "chisel*" AND (cmd LIKE "*--auth*" OR cmd LIKE "*--fingerprint*"
                                  OR cmd LIKE "*--tls-ca*" OR cmd LIKE "*--proxy*"))
| STATS launches = COUNT(*),
        first_seen = MIN(@timestamp), last_seen = MAX(@timestamp),
        commands = MV_SLICE(VALUES(process.command_line), 0, 3),
        parents = MV_SLICE(VALUES(process.parent.name), 0, 3),
        users = MV_SLICE(VALUES(user.name), 0, 3)
    BY host.id, host.name, proc
// Baseline: zero. chisel has no legitimate role in this estate - if red team tooling is allowed, allowlist by
// hash or by the engagement's own hosts rather than raising this threshold.
| WHERE launches >= 1
| SORT first_seen DESC
| LIMIT 50
```

## Reading the alert

- **`server` is the more interesting half.** A chisel server on an internal host means an inbound pivot: the
  attacker connects in and the host becomes the entry point to that segment. Read it with `CS11` for what it
  accepted.
- **`R:socks`** means the binary is proxying, not just port-forwarding - everything that follows rides it.
- **The parent is the story.** `cmd.exe` or `powershell.exe` from an Office or browser process is a full intrusion;
  a shell from a developer's terminal is a tester with authorisation.

## Nearest benign twins

- **A pentest in progress**, which is a known, scheduled exception - allowlist by the engagement's source hosts.
- **A developer reproducing the tool** from GitHub. Rare, and the parent process usually gives it away.

## What it misses

- **A renamed binary with a rewritten command line.** `chisel` renamed to `svc.exe` and run with
  `client 10.0.0.5:8080 R:socks` is still caught by the `r:socks` test, but a plain port-forward
  (`client host:8080 3389:127.0.0.1:3389`) is not.
- **chisel compiled into another binary** as a library - no command line at all.
- **The traffic itself.** That is `CS30`: many internal peers in, one external peer out.

## Test

```esql
FROM logs-yourorg-crowdstrike-data-default*
| WHERE @timestamp >= NOW() - 30 days
  AND event.action IN ("processrollup2", "syntheticprocessrollup2")
  AND process.command_line IS NOT NULL
| EVAL cmd = TO_LOWER(process.command_line)
| WHERE cmd LIKE "*chisel*" OR cmd LIKE "*r:socks*" OR cmd LIKE "*ligolo*" OR cmd LIKE "*socat*"
| STATS launches = COUNT(*) BY host.name, process.name
| SORT launches DESC
| LIMIT 20
```

This is also your false-positive check: anything already running these tools in the estate shows up here before the
rule is enabled.
