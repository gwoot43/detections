---
id: L07
name: Linux anti-forensics - logs, login records or shell history deleted or emptied, logging stopped, or system files re-dated
category: endpoint-linux
status: todo
language: esql
index: logs-yourorg-crowdstrike-data-default*
mitre: [T1685.006, T1070.003, T1685.004, T1070.006]
data_source: CrowdStrike FDR ProcessRollup2 (Linux)
suppression:
  fields: [host.id]
  duration: 24h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
Every Linux anti-forensic step pairs an action with a record: it deletes, empties or stops something that records activity, or re-dates a file so a planted one looks old. One rule covers them all by matching the pair, not each command:

- **Anchor:** a process start by a program that deletes, empties, stops or re-dates files (`rm`, `shred`, `truncate`, `systemctl`, `touch` …), or by a shell, where redirects and history settings show up.
- **Corroborating property:** it acts on a live record. That's a file in a log folder whose name ends in `.log` or `.journal` or is a classic log (`messages`, `secure`, `wtmp`, `btmp`, `lastlog`), shell history, `utmp`, the audit or syslog service, or a system file being re-dated. The `technique` column names which.
- **Exclusion by rarity and newness:** the command (with digits blanked) is new on this host in the last 2 hours and has run on at most 3 hosts in 7 days. Housekeeping runs on a schedule or across the fleet, so it drops out with no list of jobs to keep.

The record is matched by shape, not by a list of file names, so application logs in non-standard places count. In ARMORY CASTLE's BeyondTrust intrusion (Google Threat Intelligence, October 2026) the actor deleted `/home/bomgar/log/bt-secrets.log` and a dozen logs under `/ns/log/` alongside `/var/log/messages`. Rotated copies (`auth.log.1`, `secure-20261017`, `.gz`) don't match, because clearing old logs is housekeeping.

Shell built-ins (`history -c`, `unset HISTFILE`) typed in an interactive shell don't start a process. They're seen here only when they run inside `sh -c`, which is how a webshell runs every command, or inside a script.

## Query
Run hourly with a 7-day lookback.
```esql
FROM logs-yourorg-crowdstrike-data-default*
// Anchor: Linux starts of the programs that delete, empty, stop or re-date files, and of shells (redirects, history settings).
// Filtering on the name first keeps the 7-day scan cheap.
| WHERE event.action == "processrollup2" AND host.os.type == "linux"
  AND process.name IN ("rm", "unlink", "shred", "truncate", "cp", "ln", "journalctl", "systemctl", "service", "auditctl",
                       "pkill", "killall", "touch", "sh", "bash", "dash", "zsh", "ksh")
| EVAL cmd = TO_LOWER(process.command_line)
// A live record: a file in a log folder named *.log, *.journal or a classic log (messages, secure, wtmp …), shell history or utmp.
// Rotated copies (auth.log.1, secure-20261017) don't match: the name has to end there.
| EVAL live_record = cmd RLIKE """.*(/logs?/([^ '\"]*/)?(messages|secure|syslog|wtmp|btmp|lastlog|[^ '\"/]*\.(log|journal))|_history|/utmp)([ '\";].*)?"""
// The action on it. The label goes in the alert.
| EVAL technique = CASE(
    // Deleted: rm, unlink or shred on a live record, or the systemd journal vacuumed.
    process.name IN ("rm", "unlink", "shred") AND live_record, "deleted",
    process.name == "journalctl" AND cmd LIKE "*--vacuum*", "deleted",
    // Emptied in place: truncated, /dev/null copied or linked over it, or nothing redirected into it (": >", "echo >", "cat /dev/null >").
    process.name == "truncate" AND live_record, "emptied",
    process.name IN ("cp", "ln") AND live_record AND cmd LIKE "*/dev/null*", "emptied",
    cmd RLIKE """.*(:|echo|\"\"|''|/dev/null) *\> *[^ ;\&|\>]*(/logs?/|_history|/utmp).*""", "emptied",
    // Shell history switched off for the session.
    cmd RLIKE """.*(unset histfile|histfile=/dev/null|histsize=0|history -c|set \+o history).*""", "history disabled",
    // The recorder stopped: auditd or syslog stopped, disabled or killed, or kernel auditing switched off.
    process.name IN ("pkill", "killall") AND cmd RLIKE ".*(auditd|syslog|journald).*", "logging stopped",
    process.name IN ("systemctl", "service") AND cmd RLIKE ".*(auditd|syslog|journald).*" AND cmd RLIKE ".* (stop|disable|mask)( .*)?", "logging stopped",
    process.name == "auditctl" AND cmd LIKE "*-e 0*", "logging stopped",
    // Re-dated: touch copying another file's time (-r) or setting one (-t, -d) on a system file, so a planted file looks old.
    process.name == "touch" AND cmd RLIKE ".* -(r|t|d|-reference|-date)[ =].*" AND cmd RLIKE ".* /(usr|bin|sbin|lib|lib64|etc)/.*", "re-dated",
    NULL)
| WHERE technique IS NOT NULL
// The command with digits blanked, so a job that runs with a new date or PID each time counts as one command.
| EVAL command_shape = REPLACE(cmd, "[0-9]+", "0")
// One row per host and command: when it first ran in the 7 days.
| STATS first_seen = MIN(@timestamp), last_seen = MAX(@timestamp), technique = VALUES(technique),
        process.command_line = VALUES(process.command_line), process.parent.name = VALUES(process.parent.name),
        user.id = VALUES(user.id), user.name = VALUES(user.name), process.entity_id = VALUES(process.entity_id), host.name = VALUES(host.name)
    BY host.id, command_shape
// Rarity: how many hosts ran this command, counted before the newness check, so fleet-wide housekeeping drops out.
| INLINE STATS hosts = COUNT_DISTINCT(host.id) BY command_shape
// New on this host in the last 2 hours (two hourly runs), and run on at most 3 hosts.
| WHERE first_seen >= NOW() - 2 hours AND hosts <= 3
// One alert per host, listing every new command.
| STATS first_seen = MIN(first_seen), last_seen = MAX(last_seen), commands = COUNT(*), technique = VALUES(technique),
        process.command_line = VALUES(process.command_line), process.parent.name = VALUES(process.parent.name),
        user.id = VALUES(user.id), user.name = VALUES(user.name), process.entity_id = VALUES(process.entity_id), host.name = VALUES(host.name)
    BY host.id
| KEEP host.id, host.name, technique, commands, first_seen, last_seen, user.id, user.name, process.parent.name, process.command_line, process.entity_id
```

**CrowdStrike (Falcon LogScale / Advanced Event Search)**, run over the last 7 days:
```logscale
#event_simpleName=ProcessRollup2 event_platform=Lin
// Anchor: the programs that delete, empty, stop or re-date files, and shells (redirects, history settings).
| in(field="FileName", values=["rm", "unlink", "shred", "truncate", "cp", "ln", "journalctl", "systemctl", "service", "auditctl",
                               "pkill", "killall", "touch", "sh", "bash", "dash", "zsh", "ksh"])
| cmd := lower(CommandLine)
// A live record (a log named *.log, *.journal or a classic log, shell history or utmp), kept as "record" for the alert.
| regex("(?<record>/logs?/([^ '\"]*/)?(messages|secure|syslog|wtmp|btmp|lastlog|[^ '\"/]*[.](log|journal))|_history|/utmp)([ '\";]|$)", field=cmd, strict=false)
// The action on it.
| case {
    in(field="FileName", values=["rm", "unlink", "shred"]) record=* | technique := "deleted";
    FileName=journalctl cmd=/--vacuum/ | technique := "deleted";
    FileName=truncate record=* | technique := "emptied";
    in(field="FileName", values=["cp", "ln"]) record=* cmd=/\/dev\/null/ | technique := "emptied";
    cmd=/(:|echo|""|''|\/dev\/null) *> *[^ ;&|>]*(\/logs?\/|_history|\/utmp)/ | technique := "emptied";
    cmd=/unset histfile|histfile=\/dev\/null|histsize=0|history -c|set \+o history/ | technique := "history disabled";
    in(field="FileName", values=["pkill", "killall"]) cmd=/auditd|syslog|journald/ | technique := "logging stopped";
    in(field="FileName", values=["systemctl", "service"]) cmd=/auditd|syslog|journald/ cmd=/ (stop|disable|mask)( |$)/ | technique := "logging stopped";
    FileName=auditctl cmd=/-e 0/ | technique := "logging stopped";
    FileName=touch cmd=/ -(r|t|d|-reference|-date)[ =]/ cmd=/ \/(usr|bin|sbin|lib|lib64|etc)\// | technique := "re-dated";
  }
// The command with digits blanked, so a job that runs with a new date or PID each time counts as one command.
| replace(regex="[0-9]+", with="0", field=cmd, as=command_shape)
// One row per host and command: when it first ran in the 7 days.
| groupBy([command_shape, aid], function=[min(@timestamp, as=first_seen), collect([ComputerName, technique, CommandLine, ParentBaseFileName, UID])],
          limit=max)
// Rarity: one row per command, counting its hosts. Alert when it's on at most 3 and the newest started in the last 2 hours.
| groupBy([command_shape], function=[count(aid, distinct=true, as=hosts), max(first_seen, as=newest_start),
                                     collect([aid, ComputerName, technique, CommandLine, ParentBaseFileName, UID])], limit=max)
| _now := now()
| test(hosts <= 3) | test(newest_start > _now - 7200000)
```
LogScale has no `INLINE STATS`, so this version rolls up to one row per command, listing the (at most three) hosts that ran it.

## Suppression
Suppress by `host.id` for 24h. Alerts missing a key field are not suppressed. Aggregating rule: the 7-day lookback overlaps every run, and a host alerts once, when the wiping starts. Later wiping on the same host folds into the open alert.

## Known false positives / exclusions
- A one-off clean-up of a live log by an admin (`truncate -s 0` on a log that filled the disk). It alerts once; the triage below separates it quickly.
- A new application whose start script deletes its own log, on at most three hosts. It alerts at its first start, then has a history (if it restarts at least weekly).
- A package removal that purges its logs on one or two hosts. Fleet-wide removals drop out on rarity.

## Blind spot
- A wiper that runs as one program (a compiled tool, or `python -c` calling `os.remove`) never starts `rm`. Its command line names the record only if the attacker passes it as an argument.
- A command typed into an interactive shell, rather than run through `sh -c`, isn't a process when it's a built-in. `rm` and `truncate` still are.

## Triage
- Read `technique` and `process.command_line`: what was destroyed, and was it the live log or the login records.
- Look at the parent. A web server, `php-fpm` or a shell under it (L03), or a `sudo` from the web server's account, is an intrusion. An admin's SSH session with a ticket is housekeeping.
- Rebuild the timeline from Falcon telemetry, which the attacker can't clear on the host, and from the copies your syslog forwarding already sent. A gap in forwarding that starts and ends with one session is a strong sign of tampering.

## Test
On a lab Linux host, run `sudo rm -f /var/log/lab-test.log`, then `sudo sh -c ': > /var/log/lab-test2.log'`, then `sh -c 'unset HISTFILE'`. The host should alert once, within the hour, with `deleted`, `emptied` and `history disabled`.
