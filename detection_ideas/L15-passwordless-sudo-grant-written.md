---
id: L15
name: Passwordless sudo grant written to a sudoers file from the command line
category: endpoint-linux
status: todo
language: esql
index: logs-yourorg-crowdstrike-data-default*
mitre: [T1548.003]
data_source: CrowdStrike FDR ProcessRollup2 (Linux)
suppression:
  fields: [host.id]
  duration: 24h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
A `NOPASSWD` sudo rule for an account the attacker controls turns any foothold on that account into root, and it survives a password change. Admins add sudo rules through configuration management or `visudo`, which don't put the rule on a command line. Attackers write it with one shell command. In ARMORY CASTLE's BeyondTrust intrusion (Google Threat Intelligence, October 2026), a boot script ran `grep -qF '<account> ALL=(ALL) NOPASSWD: ALL' /ns/config/sudoers.template || echo '<account> ALL=(ALL) NOPASSWD: ALL' >> /ns/config/sudoers.template`. Writing to the template that `/etc/sudoers` is rebuilt from meant the grant survived configuration resets.

- **Anchor:** a command line containing `NOPASSWD`. Sudo only accepts the tag in capitals, so the match is case-sensitive.
- **Corroborating property:** the same command names a sudoers file (`/etc/sudoers`, `/etc/sudoers.d/…`, or a template like the one above). Programs that only read (`grep`, `cat`) are excluded by name; a shell that checks and then writes still counts.
- **Exclusion by rarity and newness:** the command (with digits blanked) is new on this host in the last 2 hours and has run on at most 3 hosts in 7 days. A build script that runs across the fleet, or a compliance check that runs daily, drops out.

## Query
Run hourly with a 7-day lookback.
```esql
FROM logs-yourorg-crowdstrike-data-default*
// Anchor: a Linux command holding a passwordless sudo grant (case-sensitive, as sudo is) and naming a sudoers file.
| WHERE event.action == "processrollup2" AND host.os.type == "linux"
  AND process.command_line LIKE "*NOPASSWD*" AND process.command_line LIKE "*sudoers*"
  // Readers only check for a grant. A shell that checks and then writes (grep … || echo … >>) still counts.
  AND NOT process.name IN ("grep", "egrep", "fgrep", "cat", "less", "awk")
// The command with digits blanked, so a script that runs with a new date or PID each time counts as one command.
| EVAL command_shape = REPLACE(process.command_line, "[0-9]+", "0")
// One row per host and command: when it first ran in the 7 days.
| STATS first_seen = MIN(@timestamp), last_seen = MAX(@timestamp), runs = COUNT(*), process.command_line = VALUES(process.command_line),
        process.parent.name = VALUES(process.parent.name), user.id = VALUES(user.id), host.name = VALUES(host.name)
    BY host.id, command_shape
// Rarity: how many hosts ran this command, counted before the newness check, so fleet-wide build scripts drop out.
| INLINE STATS hosts = COUNT_DISTINCT(host.id) BY command_shape
// New on this host in the last 2 hours (two hourly runs), and run on at most 3 hosts.
| WHERE first_seen >= NOW() - 2 hours AND hosts <= 3
```

**CrowdStrike (Falcon LogScale / Advanced Event Search)**, run over the last 7 days:
```logscale
#event_simpleName=ProcessRollup2 event_platform=Lin CommandLine=/NOPASSWD/ CommandLine=/sudoers/
// Readers only check for a grant. A shell that checks and then writes still counts.
| !in(field="FileName", values=["grep", "egrep", "fgrep", "cat", "less", "awk"])
// The command with digits blanked, so a script that runs with a new date or PID each time counts as one command.
| replace(regex="[0-9]+", with="0", field=CommandLine, as=command_shape)
// One row per host and command: when it first ran in the 7 days.
| groupBy([command_shape, aid], function=[min(@timestamp, as=first_seen), collect([ComputerName, CommandLine, ParentBaseFileName, UID])], limit=max)
// Rarity: one row per command, counting its hosts. Alert when it's on at most 3 and the newest started in the last 2 hours.
| groupBy([command_shape], function=[count(aid, distinct=true, as=hosts), max(first_seen, as=newest_start),
                                     collect([aid, ComputerName, CommandLine, ParentBaseFileName, UID])], limit=max)
| _now := now()
| test(hosts <= 3 AND newest_start > _now - 7200000)
```
LogScale has no `INLINE STATS`, so this version rolls up to one row per command, listing the (at most three) hosts that ran it.

## Suppression
Suppress by `host.id` for 24h. Alerts missing a key field are not suppressed. Aggregating rule: the 7-day lookback overlaps every run. A grant written again at every boot, as in the intrusion above, alerts the first time and then has a history.

## Known false positives / exclusions
- A host built this week by a provisioning script (cloud-init, Packer, kickstart) that writes a sudo rule with `echo`, if at most three hosts were built with it. It alerts once per host, at build time. If that's routine, exclude the provisioning parent (`cloud-init`) by name.

## Blind spot
A grant written by a program that takes the rule from a file or from standard input (`tee -a /etc/sudoers` typed in an interactive shell, `cp` of a prepared file) doesn't put `NOPASSWD` on any command line. Falcon file integrity monitoring on `/etc/sudoers*`, where it's licensed, covers that.

## Triage
- Read the grant in `process.command_line`: which account it's for, and which file. A web or service account getting `ALL` is an intrusion.
- Look at the parent. A web server or its shell (L03), or a boot or cron script nobody recognises (L04), is the attacker's.
- Remove the line, and check other files that rebuild `/etc/sudoers` (templates, configuration management sources) for the same line.

## Test
On a lab Linux host: `sudo sh -c "echo 'labuser ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers.d/lab-test"`. It should alert within the hour. Delete the file afterwards.
