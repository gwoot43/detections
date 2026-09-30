---
id: L03
name: Web or application server process spawning a shell or interpreter
category: endpoint-linux
status: todo
severity: critical
language: esql
index: logs-crowdstrike.fdr-*
mitre: [T1505.003, T1190, T1059.004]
data_source: CrowdStrike FDR ProcessRollup2 (Linux)
suppression:
  fields: [host.name, parent]
  duration: 1h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
This is the universal post-exploitation signal for web app RCE and webshells. Application servers fork shells only when the code is designed to, which you enumerate once and exclude.

## Query
```esql
FROM logs-crowdstrike.fdr-* METADATA _id, _index, _version
| WHERE event.action == "ProcessRollup2" AND host.os.type == "linux"
| EVAL parent = TO_LOWER(process.parent.name), child = TO_LOWER(process.name), cmd = TO_LOWER(process.command_line)
| WHERE parent IN ("nginx", "apache2", "httpd", "php-fpm", "php-fpm7.4", "php-fpm8.1", "php-fpm8.2", "php", "java", "tomcat", "node", "nodejs", "python", "python3", "gunicorn", "uwsgi", "ruby", "puma", "dotnet", "confluence", "jira", "lighttpd", "caddy", "envoy", "traefik")
  AND child IN ("sh", "bash", "dash", "zsh", "ash", "ksh", "nc", "ncat", "netcat", "perl", "python", "python3", "php", "ruby", "curl", "wget", "whoami", "id", "uname", "chmod", "base64", "socat", "crontab", "useradd", "passwd")
| WHERE NOT (cmd IN ("sh -c ls", "sh -c /usr/bin/whoami"))
| KEEP @timestamp, host.name, user.name, parent, child, process.command_line, process.parent.command_line
```

## Suppression
Suppress by `host.name`, `parent` for 1h. Alerts missing a key field are not suppressed. Each webshell command is a new process. One alert per compromised service, with the count showing activity.

## Known false positives / exclusions
- Apps that call `sh -c` for image conversion or git. Baseline for two weeks and exclude by exact command line. A `java` parent spawning `sh -c` with `curl` or `/dev/tcp` is never legitimate.

## Triage
- Treat as confirmed RCE until proven otherwise. Pull the web access log for the same second (Imperva N05/N06), isolate, snapshot.

## Test
Deploy a lab page that calls `system('id')` and request it.
