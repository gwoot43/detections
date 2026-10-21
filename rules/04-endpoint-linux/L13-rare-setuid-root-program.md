---
id: L13
name: Rare program runs setuid root (SUID backdoor such as a copied shell)
category: endpoint-linux
status: todo
language: esql
index: logs-yourorg-crowdstrike-data-default*
mitre: [T1548.001]
data_source: CrowdStrike FDR ProcessRollup2 (Linux)
suppression:
  fields: [host.id]
  duration: 24h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
An attacker who gets root once leaves a way back: a copy of a shell, owned by root, with the setuid bit set, so any account can become root again. In ARMORY CASTLE's BeyondTrust intrusion (Google Threat Intelligence, October 2026) the actor copied `/bin/sh` to `/usr/bin/dbus-authd`, a name chosen to blend in, and made it setuid root.

Whatever the file is called, it starts the same way: as root (effective user 0) for an account that isn't root. Falcon records both users on every Linux process start. Only a setuid-root file starts like that, and the setuid-root programs a fleet really uses (`sudo`, `su`, `passwd`, `mount`, `ping`) run on every host.

- **Anchor:** a process that started with effective user 0 and a real user that isn't 0.
- **Corroborating property:** the program is new to this on this host. Its first setuid run in the 7-day lookback was in the last 2 hours.
- **Exclusion by rarity:** the program runs setuid on at most three hosts in the fleet. System setuid programs drop out with no list to keep.

L06 catches `chmod u+s` on files in temp and home folders. This rule doesn't care where the file is or how its bit was set, so it also catches a backdoor placed in `/usr/bin` under a system-looking name. What the backdoor runs keeps the root effective user, so its child processes show up in the same alert.

## Query
Run hourly with a 7-day lookback.
```esql
FROM logs-yourorg-crowdstrike-data-default*
// Anchor: a Linux program that started as root for an account that isn't root: only a setuid-root file starts like that.
// user.id is the effective user (UID), process.real_user.id the account that ran it (RUID).
| WHERE event.action == "processrollup2" AND host.os.type == "linux"
  AND user.id == "0" AND process.real_user.id != "0"
// One row per host and program: when it first ran setuid in the 7 days, and for whom.
| STATS first_seen = MIN(@timestamp), last_seen = MAX(@timestamp), runs = COUNT(*),
        process.real_user.id = VALUES(process.real_user.id), process.parent.name = VALUES(process.parent.name),
        process.command_line = VALUES(process.command_line), process.hash.sha256 = VALUES(process.hash.sha256), host.name = VALUES(host.name)
    BY host.id, process.executable
// Rarity: how many hosts ran this program setuid, counted before the newness check.
// sudo, su, passwd, mount and ping do it on every host and drop out here.
| INLINE STATS hosts = COUNT_DISTINCT(host.id) BY process.executable
// New on this host in the last 2 hours (two hourly runs), and on at most 3 hosts.
| WHERE first_seen >= NOW() - 2 hours AND hosts <= 3
// One alert per host: the backdoor and whatever ran through it (children keep the root effective user).
| STATS first_seen = MIN(first_seen), last_seen = MAX(last_seen), runs = SUM(runs), process.executable = VALUES(process.executable),
        process.real_user.id = VALUES(process.real_user.id), process.parent.name = VALUES(process.parent.name),
        process.command_line = VALUES(process.command_line), process.hash.sha256 = VALUES(process.hash.sha256), host.name = VALUES(host.name)
    BY host.id
```

**CrowdStrike (Falcon LogScale / Advanced Event Search)**, run over the last 7 days:
```logscale
#event_simpleName=ProcessRollup2 event_platform=Lin
// Anchor: started as root (UID 0) for an account that isn't root (RUID): a setuid-root file.
| UID=0 RUID=* RUID!=0
// One row per host and program: when it first ran setuid in the 7 days.
| groupBy([ImageFileName, aid], function=[min(@timestamp, as=first_seen), collect([ComputerName, RUID, ParentBaseFileName, CommandLine, SHA256HashData])],
          limit=max)
// Rarity: one row per program, counting its hosts. Alert when it's on at most 3 and the newest started in the last 2 hours.
| groupBy([ImageFileName], function=[count(aid, distinct=true, as=hosts), max(first_seen, as=newest_start),
                                     collect([aid, ComputerName, RUID, ParentBaseFileName, CommandLine, SHA256HashData])], limit=max)
| _now := now()
| test(hosts <= 3 AND newest_start > _now - 7200000)
```
LogScale has no `INLINE STATS`, so this version rolls up to one row per program, listing the (at most three) hosts it runs on.

**Check before deploying:** run `FROM logs-yourorg-crowdstrike-data-default* | WHERE event.action == "processrollup2" AND process.name == "sudo" | STATS COUNT(*) BY user.id, process.real_user.id` over a day. You should see `user.id` 0 with your admins' user IDs as `process.real_user.id`. If `process.real_user.id` is empty, the sensor isn't sending `RUID` and this rule can't work.

## Suppression
Suppress by `host.id` for 24h. Alerts missing a key field are not suppressed. Aggregating rule: the 7-day lookback overlaps every run, and the backdoor alerts the first time it's used on a host.

## Known false positives / exclusions
- A setuid helper from software installed on only a few hosts (Chrome's `chrome-sandbox` on Linux desktops, `nvidia-modprobe` on GPU servers, Oracle's `oradism` and `extjob`). They run regularly, so they have a history and alert only when first used on a host after a quiet week. Exclude a noisy one by `process.executable` only after checking its hash against the vendor's.

## Blind spot
A backdoor on several hosts that the attacker uses at least weekly on each becomes part of the history after the first week. The first use still alerts on every host.

## Triage
- Check the file: `process.hash.sha256` against the host's own `/bin/bash` or `/bin/dash` (a matching hash means a copied shell), its owner and mode (`ls -l`), and whether a package owns it (`rpm -qf` or `dpkg -S`). A file no package owns is the backdoor.
- `process.real_user.id` is the account that used it, often a web or service account. Look for how that account got a shell (L03), and for the earlier command that created the file (`cp`, `chown`, `chmod`).
- Remove the file, then look for the other persistence the actor left (sudoers, L15; boot scripts and cron, L04).

## Test
On a lab Linux host, as root: `cp /bin/bash /usr/local/bin/lab-authd && chmod 4755 /usr/local/bin/lab-authd`. Then, as an ordinary user, run `lab-authd -p -c id`. The host should alert, listing `/usr/local/bin/lab-authd` and `/usr/bin/id`.
