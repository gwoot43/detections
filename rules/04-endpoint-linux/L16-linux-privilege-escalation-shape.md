---
id: L16
name: Linux privilege escalation shape - recon then a root shell that fetches a payload
category: endpoint-linux
status: todo
language: esql
index: logs-yourorg-crowdstrike-data-default*
mitre: [T1548.003, T1068, T1059.004]
data_source: CrowdStrike FDR ProcessRollup2 on Linux
suppression:
  fields: [host.id, user.name]
  duration: 24h
  missing_fields: do_not_suppress
---

## Why this is high fidelity

Linux escalation has three halves - enumerate, escalate, exploit - and you collect only the process half, because
Linux file events are not in the index. That rules out anything anchored on "a write to `/etc/sudoers`", which is
the anchor most published rules use.

What is left is still enough, if the rule is built on **behaviour rather than on the escalation mechanism**:

1. **The recon** - `linpeas`, `pspy`, `linux-exploit-suggester`, `sudo -l`, `find / -perm -4000`, `getcap -r /`. A
   normal host produces none of these, ever.
2. **The privilege transition** - a shell whose parent is `sudo`, `su`, `pkexec` or `doas`. Common for admins, so on
   its own it is noise.
3. **The payload fetch from a root shell** - `curl`/`wget`/`nc` started from that shell. A root shell that
   downloads something is the pair that separates an escalation from routine administration.

Requiring either (1) alone, or (2) **and** (3) together, keeps the rule quiet on admin habits and loud on the actual
chain.

## Query

Run every 15 minutes with a 1-hour lookback.

```esql
FROM logs-yourorg-crowdstrike-data-default*
| WHERE @timestamp >= NOW() - 1 hour
  AND host.os.type == "linux"
  AND event.action == "processrollup2"
| EVAL proc = TO_LOWER(COALESCE(process.name, "")),
       cmd = TO_LOWER(COALESCE(process.command_line, "")),
       parent = TO_LOWER(COALESCE(process.parent.name, "")),
       path = TO_LOWER(COALESCE(process.executable, ""))
| EVAL is_recon = proc LIKE "linpeas*" OR proc LIKE "pspy*" OR proc LIKE "linux-exploit-suggester*"
                 OR proc LIKE "linuxprivchecker*" OR cmd LIKE "*sudo -l*" OR cmd LIKE "*find / -perm -4000*"
                 OR cmd LIKE "*getcap -r /*",
       // a shell started by an escalator, or any process running from a writable path
       is_root_shell = proc IN ("sh", "bash", "dash", "zsh") AND parent IN ("sudo", "su", "pkexec", "doas"),
       is_fetch = proc IN ("curl", "wget", "nc", "ncat", "socat") OR cmd LIKE "*base64 -d*",
       is_writable_path = path LIKE "/tmp/*" OR path LIKE "/dev/shm/*" OR path LIKE "/var/tmp/*"
                          OR path LIKE "/home/*"
| STATS events = COUNT(*),
        recon = COUNT(*) WHERE is_recon,
        root_shells = COUNT(*) WHERE is_root_shell,
        fetches = COUNT(*) WHERE is_fetch,
        writable_path_runs = COUNT(*) WHERE is_writable_path,
        first_seen = MIN(@timestamp), last_seen = MAX(@timestamp),
        commands = MV_SLICE(VALUES(process.command_line), 0, 5),
        parents = MV_SLICE(VALUES(process.parent.name), 0, 5)
    BY host.id, host.name, user.name
// recon alone is an alert (nothing legitimate runs linpeas); a root shell alone is not, but a root shell that
// fetches a payload is. Baseline: recon = 0 in a normal estate, so there is nothing to tune on that branch.
| WHERE recon >= 1
     OR (root_shells >= 1 AND fetches >= 1)
     OR (root_shells >= 1 AND writable_path_runs >= 1)
| SORT first_seen DESC
| LIMIT 50
```

## Reading the alert

- **`commands`** shows the chain: a recon tool, then `sudo -i`, then `curl`. Read it in time order - `first_seen`
  and `last_seen` bound the whole sequence.
- **`recon >= 1` with no root shell** is a tester enumerating and not yet succeeding, which is still worth a call.
- **`parents`** containing `sudo` on a host where that user has never run it is the single strongest signal the
  process data can give you.

## Nearest benign twins

- **Configuration management** running `find / -perm -4000` as part of a hardening check - it comes from `ansible`,
  `puppet` or `salt`, on every host, at the same time. Allowlist by parent.
- **An administrator** running `sudo -i` then `curl` to fetch a package. The `commands` field distinguishes a
  package URL from a raw IP.
- **`/home` binaries** run by their owner (a user's own script) - the writable-path branch needs the root shell to
  make it meaningful, which is why it is paired above.

## What it misses

- **A silent escalation** with no recon and no download - a `sudo` rule abused to read a file, or a capability on a
  binary that spawns a shell quietly. Nothing in process data separates that from an admin doing their job.
- **Kernel exploits** whose only visible artefact is a crash or a new process in `/tmp` - the writable-path branch
  catches the second, not the first.
- **Writes to `/etc/sudoers`, `cron.d`, `authorized_keys`** - the file events that would catch these are not
  collected. State that in the rule; do not imply coverage.

## Test

```esql
FROM logs-yourorg-crowdstrike-data-default*
| WHERE @timestamp >= NOW() - 30 days
  AND host.os.type == "linux"
  AND event.action == "processrollup2"
| EVAL proc = TO_LOWER(COALESCE(process.name, ""))
| WHERE proc LIKE "linpeas*" OR proc LIKE "pspy*"
| STATS events = COUNT(*) BY host.name, user.name
| SORT events DESC
| LIMIT 20
```

Empty is the expected answer, and it means the recon branch has a zero baseline. The root-shell branch needs the
30-day parent distribution below it, so run this too before enabling:

```esql
FROM logs-yourorg-crowdstrike-data-default*
| WHERE @timestamp >= NOW() - 30 days
  AND host.os.type == "linux"
  AND event.action == "processrollup2"
| EVAL parent = TO_LOWER(COALESCE(process.parent.name, ""))
| WHERE parent IN ("sudo", "su", "pkexec", "doas")
| STATS events = COUNT(*) BY host.name, user.name
| SORT events DESC
| LIMIT 30
```
