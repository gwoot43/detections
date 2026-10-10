---
id: L07
name: Log clearing, shell history tamper or timestomping
category: endpoint-linux
status: todo
severity: high
language: esql
index: logs-crowdstrike.fdr-*
mitre: [T1070.002, T1070.003, T1070.006, T1562.001, T1222.002]
data_source: CrowdStrike FDR ProcessRollup2 (Linux)
suppression:
  fields: [host.name]
  duration: 1h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
Deleting or truncating login records, auth and audit logs or shell history, unsetting `HISTFILE`, backdating system binaries with `touch -r` and stopping auditd are things attackers do to cover tracks and admins almost never do interactively.

General clean-up of application logs under `/var/log` (old `.gz` files, `truncate -s 0` on a full disk) is routine, so only the security-relevant files count: `auth.log`, `secure`, `messages`, `syslog`, `audit.log`, `wtmp`, `btmp`, `lastlog` and shell history. Timestomping counts only on system directories; build tools set timestamps in `/tmp` for reproducible builds.

Shell built-ins such as `history -c` typed in an interactive shell do not start a process, so that branch only sees them inside `bash -c` or a script.

## Query
```esql
FROM logs-crowdstrike.fdr-* METADATA _id, _index, _version
| WHERE event.action == "ProcessRollup2" AND host.os.type == "linux"
| EVAL cmd = TO_LOWER(process.command_line), pname = TO_LOWER(process.name)
| EVAL sec_log = cmd LIKE "*/var/log/auth.log*" OR cmd LIKE "*/var/log/secure*" OR cmd LIKE "*/var/log/messages*" OR cmd LIKE "*/var/log/syslog*"
                 OR cmd LIKE "*/var/log/audit/*" OR cmd LIKE "*wtmp*" OR cmd LIKE "*btmp*" OR cmd LIKE "*lastlog*"
                 OR cmd LIKE "*.bash_history*" OR cmd LIKE "*.zsh_history*" OR cmd LIKE "*/root/.*history*"
| WHERE (pname IN ("rm", "unlink", "shred", "truncate") AND sec_log)
   // overwrite, not append: scripts append status lines to /var/log/messages
   OR (sec_log AND (cmd LIKE "*: >*" OR cmd LIKE "*echo*>*" OR cmd LIKE "*cat /dev/null*>*") AND NOT cmd LIKE "*>>*")
   OR (cmd LIKE "*history -c*" OR cmd LIKE "*unset histfile*" OR cmd LIKE "*export histfile=/dev/null*" OR cmd LIKE "*set +o history*" OR cmd LIKE "*histsize=0*")
   OR (cmd LIKE "*ln -sf /dev/null*" AND cmd LIKE "*history*")
   OR (pname == "touch" AND (cmd LIKE "*-r *" OR cmd LIKE "*-t *" OR cmd LIKE "*-d *") AND (cmd LIKE "*/usr/*" OR cmd LIKE "*/bin/*" OR cmd LIKE "*/sbin/*" OR cmd LIKE "*/lib*" OR cmd LIKE "*/etc/*"))
   // systemctl puts the verb first ("stop auditd"), service puts it last ("auditd stop")
   OR (pname IN ("systemctl", "service") AND (cmd LIKE "*stop*" OR cmd LIKE "*disable*" OR cmd LIKE "*mask*") AND (cmd LIKE "*auditd*" OR cmd LIKE "*syslog*"))
   OR (pname == "auditctl" AND cmd LIKE "*-e 0*")
   OR (cmd LIKE "*chattr*" AND (cmd LIKE "*+i*" OR cmd LIKE "*-a*") AND (cmd LIKE "*/var/log*" OR cmd LIKE "*history*"))
| KEEP @timestamp, host.name, user.name, process.parent.name, pname, process.command_line
```

## Suppression
Suppress by `host.name` for 1h. Alerts missing a key field are not suppressed. Log wiping runs as a burst of commands.

## Known false positives / exclusions
- Log rotation runs as `logrotate`, not `rm`, and is not matched. Custom clean-up jobs that delete rotated auth logs (`/var/log/secure-2026…`) should be excluded by exact command line.
- `history -c` by tidy admins. Low volume; keep it, it correlates well with other activity on the same host.
- Planned auditd or rsyslog maintenance. Ticket-gated.

## Triage
- Any log tamper is a cover-up; expand the timeline on that host before the logs were touched, using Falcon telemetry which the attacker cannot clear.

## Test
`truncate -s 0 /var/log/test.log` on a lab host.
