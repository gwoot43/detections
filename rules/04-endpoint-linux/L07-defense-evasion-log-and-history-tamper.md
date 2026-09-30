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
Truncating `/var/log`, unsetting `HISTFILE`, deleting `.bash_history` and running `touch -r` to backdate files are things attackers do to cover tracks and admins almost never do interactively.

## Query
```esql
FROM logs-crowdstrike.fdr-* METADATA _id, _index, _version
| WHERE event.action == "ProcessRollup2" AND host.os.type == "linux"
| EVAL cmd = TO_LOWER(process.command_line), pname = TO_LOWER(process.name)
| WHERE (cmd LIKE "*rm *" AND (cmd LIKE "*/var/log/*" OR cmd LIKE "*.bash_history*" OR cmd LIKE "*/root/.*history*" OR cmd LIKE "*wtmp*" OR cmd LIKE "*btmp*" OR cmd LIKE "*lastlog*" OR cmd LIKE "*auth.log*" OR cmd LIKE "*secure*" OR cmd LIKE "*audit/audit.log*"))
   OR (pname IN ("truncate", "shred") AND (cmd LIKE "*/var/log/*" OR cmd LIKE "*wtmp*" OR cmd LIKE "*history*"))
   OR (cmd LIKE "*>*/var/log/*" AND (cmd LIKE "*: >*" OR cmd LIKE "*echo*>*" OR cmd LIKE "*cat /dev/null*"))
   OR (cmd LIKE "*history -c*" OR cmd LIKE "*unset histfile*" OR cmd LIKE "*export histfile=/dev/null*" OR cmd LIKE "*set +o history*" OR cmd LIKE "*histsize=0*")
   OR (cmd LIKE "*ln -sf /dev/null*" AND cmd LIKE "*history*")
   OR (pname == "touch" AND (cmd LIKE "*-r *" OR cmd LIKE "*-t *" OR cmd LIKE "*-d *") AND (cmd LIKE "*/tmp/*" OR cmd LIKE "*/dev/shm/*" OR cmd LIKE "*/usr/*" OR cmd LIKE "*/bin/*"))
   OR (pname IN ("auditctl", "systemctl", "service") AND (cmd LIKE "*auditd*stop*" OR cmd LIKE "*rsyslog*stop*" OR cmd LIKE "*-e 0*" OR cmd LIKE "*syslog*stop*"))
   OR (cmd LIKE "*chattr*" AND (cmd LIKE "*+i*" OR cmd LIKE "*-a*") AND (cmd LIKE "*/var/log*" OR cmd LIKE "*history*"))
| KEEP @timestamp, host.name, user.name, process.parent.name, pname, process.command_line
```

## Suppression
Suppress by `host.name` for 1h. Alerts missing a key field are not suppressed. Log wiping runs as a burst of commands.

## Known false positives / exclusions
- Log rotation runs as `logrotate`, not `rm`. Exclude the `logrotate` parent if it appears.
- `history -c` by tidy admins. Low volume; keep it, it correlates well with other activity on the same host.

## Triage
- Any log tamper is a cover-up; expand the timeline on that host before the logs were touched, using Falcon telemetry which the attacker cannot clear.

## Test
`truncate -s 0 /var/log/test.log` on a lab host.
