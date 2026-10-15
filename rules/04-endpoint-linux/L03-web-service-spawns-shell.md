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
  fields: [host.id, parent]
  duration: 1h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
This is the universal post-exploitation signal for web app RCE and webshells. Application servers fork shells only when the code is designed to, which you enumerate once and exclude.

Two parent groups are treated differently:
- **Web servers and app-server workers** (nginx, Apache, php-fpm, gunicorn, uwsgi and similar) spawning any shell, interpreter, downloader or recon tool.
- **Generic runtimes** (`java`, `node`, `python`, `ruby`, `php`, `dotnet`) also run build jobs, Jenkins agents, Ansible and cron scripts, which spawn shells all day. For these the child must be a recon or socket tool (`whoami`, `nc`, `socat`), or a shell whose command line reaches for `/dev/tcp`, `whoami`, a Base64 decode or a pipe into a shell.

Confluence, Jira and Tomcat run as `java` in FDR, so they fall in the second group.

## Query
```esql
FROM logs-crowdstrike.fdr-* METADATA _id, _index, _version
| WHERE event.action == "ProcessRollup2" AND host.os.type == "linux"
| EVAL parent = TO_LOWER(process.parent.name), child = TO_LOWER(process.name), cmd = TO_LOWER(COALESCE(process.command_line, ""))
| EVAL web_parent = parent IN ("nginx", "apache2", "httpd", "lighttpd", "caddy", "envoy", "traefik", "php-cgi", "gunicorn", "uwsgi", "puma", "unicorn")
                    OR parent LIKE "php-fpm*",
       runtime_parent = parent IN ("java", "node", "nodejs", "python", "python3", "ruby", "php", "dotnet"),
       shell_child = child IN ("sh", "bash", "dash", "zsh", "ash", "ksh")
| WHERE (web_parent
         AND (shell_child OR child IN ("nc", "ncat", "netcat", "perl", "python", "python3", "php", "ruby", "curl", "wget", "whoami", "id", "uname", "chmod", "base64", "socat", "crontab", "useradd", "passwd")))
   OR (runtime_parent
       AND (child IN ("whoami", "nc", "ncat", "netcat", "socat")
            OR (shell_child AND (cmd LIKE "*/dev/tcp/*" OR cmd LIKE "*whoami*" OR cmd LIKE "*base64 -d*"
                                 OR cmd RLIKE """.*\| ?(sh|bash)([ ;].*)?"""))))
// add exact benign command lines found while baselining, e.g. | WHERE NOT (cmd IN ("sh -c /usr/bin/convert ..."))
| KEEP @timestamp, host.id, host.name, user.name, parent, child, process.command_line, process.parent.entity_id
```

**CrowdStrike (Falcon LogScale / Advanced Event Search)**
```logscale
#event_simpleName=/^(ProcessRollup2|SyntheticProcessRollup2)$/ event_platform=Lin
| case {
    ParentBaseFileName=/^(nginx|apache2|httpd|lighttpd|caddy|envoy|traefik|php-cgi|gunicorn|uwsgi|puma|unicorn|php-fpm.*)$/i
      | in(field="FileName", ignoreCase=true, values=["sh", "bash", "dash", "zsh", "ash", "ksh", "nc", "ncat", "netcat", "perl", "python",
                                                     "python3", "php", "ruby", "curl", "wget", "whoami", "id", "uname", "chmod", "base64",
                                                     "socat", "crontab", "useradd", "passwd"])
      | finding := "web server spawned shell or tool";
    in(field="ParentBaseFileName", ignoreCase=true, values=["java", "node", "nodejs", "python", "python3", "ruby", "php", "dotnet"])
      | in(field="FileName", ignoreCase=true, values=["whoami", "nc", "ncat", "netcat", "socat"])
      | finding := "runtime spawned recon or socket tool";
    in(field="ParentBaseFileName", ignoreCase=true, values=["java", "node", "nodejs", "python", "python3", "ruby", "php", "dotnet"])
      | in(field="FileName", ignoreCase=true, values=["sh", "bash", "dash", "zsh", "ash", "ksh"])
      | CommandLine=/\/dev\/tcp\/|whoami|base64 -d|\| ?(sh|bash)([ ;]|$)/i
      | finding := "runtime spawned shell with reverse-shell or recon command";
  }
// add exact benign command lines found while baselining, e.g. | !in(field="CommandLine", ignoreCase=true, values=["sh -c /usr/bin/convert ..."])
| table([@timestamp, aid, ComputerName, UserName, finding, ParentBaseFileName, FileName, CommandLine, ParentProcessId])
```

## Suppression
Suppress by `host.id`, `parent` for 1h. Alerts missing a key field are not suppressed. Each webshell command is a new process. One alert per compromised service, with the count showing activity. `host.id` is the Falcon agent ID and is always present; `host.name` is filled only when the integration's host metadata enrichment is on.

## Known false positives / exclusions
- Web apps that call `sh -c` for image conversion or git. Baseline for two weeks and exclude by exact command line. A web server spawning `sh -c` with `curl` or `/dev/tcp` is never legitimate.
- Build agents and scripts under a generic runtime only alert on recon or reverse-shell shapes. If a build job runs `whoami`, exclude that job's exact command line.

## Triage
- Treat as confirmed RCE until proven otherwise. Pull the web access log for the same second (Imperva N05/N06), isolate, snapshot.

## Test
Deploy a lab page that calls `system('id')` and request it.
