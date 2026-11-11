---
id: L17
name: Linux recon tooling - linpeas, pspy and the fetch-then-run pattern
category: endpoint-linux
status: todo
language: esql
index: logs-yourorg-crowdstrike-data-default*
mitre: [T1082, T1087.001, T1548.003]
data_source: CrowdStrike FDR ProcessRollup2 on Linux
suppression:
  fields: [host.id, user.name]
  duration: 24h
  missing_fields: do_not_suppress
---

## Why this is high fidelity

`linpeas` is the first thing run on a Linux host that has just been landed on: it enumerates sudo rules, SUID
binaries, capabilities, cron jobs, writable paths and credentials, and prints a ranked escalation list. `pspy` does
the same for running processes. Neither has any legitimate use in a managed estate, so **the name is a zero-baseline
signal** - the cheapest high-fidelity rule you can write.

The name alone is also easy to defeat: rename the file, or never write it to disk at all. So the rule has three
branches, in descending order of durability:

1. **The tool by name** - `linpeas.sh`, `linpeas`, `pspy64`, `pspy32`, `LinEnum`, `unix-privesc-check`,
   `linux-exploit-suggester`, `traitor`.
2. **Fetch then run** - `curl … | sh`, `wget … -O /tmp/x && chmod +x /tmp/x && /tmp/x`, or a script executed from
   `/tmp`, `/dev/shm`, `/var/tmp` or `/home`. This catches a renamed tool and a memory-only one.
3. **The vocabulary** - `sudo -l`, `find / -perm -4000`, `getcap -r /`, `cat /etc/shadow`. Any one of these is an
   admin doing something; **two or more on the same host in the same hour, plus an execution from a writable path,
   is enumeration.**

`L16` is the escalation that follows this; this rule is the step before it.

## Query

Run every 15 minutes with a 1-hour lookback.

```esql
FROM logs-yourorg-crowdstrike-data-default*
| WHERE @timestamp >= NOW() - 1 hour
  AND host.os.type == "linux"
  AND event.action == "processrollup2"
| EVAL proc = TO_LOWER(COALESCE(process.name, "")),
       cmd = TO_LOWER(COALESCE(process.command_line, "")),
       path = TO_LOWER(COALESCE(process.executable, ""))
| EVAL is_named = proc LIKE "linpeas*" OR proc LIKE "pspy*" OR proc LIKE "linenum*"
                 OR proc LIKE "unix-privesc-check*" OR proc LIKE "linux-exploit-suggester*"
                 OR proc LIKE "traitor*"
                 OR cmd LIKE "*linpeas.sh*" OR cmd LIKE "*pspy64*" OR cmd LIKE "*pspy32*",
       // a download piped straight into a shell, or a script run out of a writable path
       is_fetch_run = (cmd LIKE "*curl *" AND cmd LIKE "*| sh*") OR (cmd LIKE "*wget *" AND cmd LIKE "*| sh*"),
       writable = path LIKE "/tmp/*" OR path LIKE "/dev/shm/*" OR path LIKE "/var/tmp/*" OR path LIKE "/home/*",
       is_recon_cmd = cmd LIKE "*sudo -l*" OR cmd LIKE "*find / -perm -4000*" OR cmd LIKE "*getcap -r /*"
                      OR cmd LIKE "*cat /etc/shadow*" OR cmd LIKE "*ls -la /etc/*"
| STATS events = COUNT(*),
        named = COUNT(*) WHERE is_named,
        fetch_run = COUNT(*) WHERE is_fetch_run,
        recon_cmds = COUNT(*) WHERE is_recon_cmd,
        writable_runs = COUNT(*) WHERE writable,
        first_seen = MIN(@timestamp), last_seen = MAX(@timestamp),
        commands = MV_SLICE(VALUES(process.command_line), 0, 5),
        parents = MV_SLICE(VALUES(process.parent.name), 0, 3),
        users = MV_SLICE(VALUES(user.name), 0, 3)
    BY host.id, host.name
// (1) a named recon tool: baseline zero, nothing legitimate runs these
// (2) fetch-then-run: a download piped to a shell is how a renamed tool arrives without ever touching disk
// (3) enumeration by volume: three or more of the vocabulary commands in an hour, with something executing from a
//     writable path. Baseline: an admin runs one of these occasionally; three plus a /tmp execution is a sweep.
| WHERE named >= 1
     OR fetch_run >= 1
     OR (recon_cmds >= 3 AND writable_runs >= 1)
| SORT first_seen DESC
| LIMIT 50
```

## Reading the alert

- **`named >= 1`** is the easy case: read `users` and `parents`. A named tool run from a `sudo` shell is already an
  escalation attempt.
- **`fetch_run`** is the one to look at closely - the `commands` field shows the URL. A raw IP, a gist, or a
  shortened link is the case; a distribution mirror is a build script.
- **`recon_cmds >= 3`** means someone is looking for a way up. `commands` in time order tells you what they found
  before they stopped.

## Nearest benign twins

- **Configuration management and CIS hardening** running `find / -perm -4000` or `getcap -r /` - it comes from
  `ansible`, `puppet`, `salt` or a scanner, on every host, at the same minute. Allowlist by parent.
- **A build or install script** doing `curl … | sh` (Homebrew, rustup, NodeSource). The URL is the tell, and the
  parent is a build agent rather than a shell.
- **An administrator's own audit script** in `/home` - it repeats weekly from the same account.

## What it misses

- **A tool uploaded over an existing session and run from memory** - no process name, no download, no writable path.
  Nothing in process data sees that.
- **Enumeration done by hand**, one command at a time over hours. The volume branch needs three in an hour; a patient
  operator stays under it, and that is the correct trade - the alternative is alerting on every `sudo -l`.
- **Windows-side recon** (PowerView, SharpHound) - that is `WE16` and `CS21`.

## Test

```esql
FROM logs-yourorg-crowdstrike-data-default*
| WHERE @timestamp >= NOW() - 30 days
  AND host.os.type == "linux"
  AND event.action == "processrollup2"
| EVAL proc = TO_LOWER(COALESCE(process.name, "")),
       cmd = TO_LOWER(COALESCE(process.command_line, ""))
| WHERE proc LIKE "linpeas*" OR proc LIKE "pspy*" OR cmd LIKE "*linpeas.sh*" OR cmd LIKE "*pspy64*"
| STATS events = COUNT(*) BY host.name, user.name
| SORT events DESC
| LIMIT 20
```

Empty is the expected answer, and it means branch (1) needs no tuning. Run the same shape over the vocabulary
commands to size branch (3) against your own admins before enabling:

```esql
FROM logs-yourorg-crowdstrike-data-default*
| WHERE @timestamp >= NOW() - 30 days
  AND host.os.type == "linux"
  AND event.action == "processrollup2"
| EVAL cmd = TO_LOWER(COALESCE(process.command_line, ""))
| WHERE cmd LIKE "*sudo -l*" OR cmd LIKE "*find / -perm -4000*" OR cmd LIKE "*getcap -r /*"
| STATS events = COUNT(*) BY host.name, user.name, process.parent.name
| SORT events DESC
| LIMIT 30
```
