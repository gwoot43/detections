---
id: W21
name: Java, Tomcat, CrushFTP or another application server on Windows spawning a shell or recon command
category: endpoint-windows
status: todo
language: esql
index: logs-yourorg-crowdstrike-data-default*
mitre: [T1190, T1505.003, T1059]
data_source: CrowdStrike FDR ProcessRollup2
suppression:
  fields: [host.id, process.parent.name]
  duration: 6h
  missing_fields: do_not_suppress
---

An exploited internet-facing application runs the attacker's first command as a child of the application's own
process. The catalogue already covers two of the three families: IIS and SQL Server on Windows (`AD11`), and every
Linux web and app server (`L03`). This rule is the missing one: **Java application servers and file-transfer
products on Windows.** That means Tomcat, CrushFTP, WebLogic, JBoss, and anything run through a service wrapper, which
is where most 2024 to 2026 edge exploitation landed.

The difficulty is `java.exe`. It starts `cmd.exe` all day on developer machines, because Gradle, Maven and IDEs do
exactly that. So the rule treats two parents differently:

- A **named app-server process** (`tomcat*.exe`, `crushftp*.exe`, `beasvc.exe`, `wrapper.exe` and so on) starting
  **any** shell or LOLBin is the case.
- A **bare JVM** (`java.exe`, `javaw.exe`) counts only when the child is hands-on: recon (`whoami`, `net`,
  `nltest`, `systeminfo`), a download (`certutil`, `bitsadmin`, `curl`, `Invoke-WebRequest`), or an encoded or
  invoked PowerShell command. A build tool never runs `whoami`.

## Query

Run every 5 minutes with a 10-minute lookback.

```esql
FROM logs-yourorg-crowdstrike-data-default* METADATA _id, _index, _version
| WHERE event.action IN ("processrollup2", "syntheticprocessrollup2")
  AND data.event_platform == "Win"
| EVAL parent = TO_LOWER(COALESCE(process.parent.name, "")),
       child = TO_LOWER(COALESCE(process.name, "")),
       cmd = TO_LOWER(COALESCE(process.command_line, ""))
| EVAL app_server = parent LIKE "tomcat*" OR parent LIKE "crushftp*"
                    OR parent IN ("beasvc.exe", "wrapper.exe", "jbosssvc.exe", "php-cgi.exe", "httpd.exe", "nginx.exe"),
       jvm = parent IN ("java.exe", "javaw.exe"),
       shell = child IN ("cmd.exe", "powershell.exe", "pwsh.exe", "mshta.exe", "wscript.exe", "cscript.exe",
                         "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe", "whoami.exe", "net.exe",
                         "net1.exe", "nltest.exe", "systeminfo.exe", "curl.exe"),
       hands_on = child IN ("whoami.exe", "net.exe", "net1.exe", "nltest.exe", "systeminfo.exe", "certutil.exe",
                            "bitsadmin.exe", "curl.exe", "mshta.exe")
                  OR cmd LIKE "*whoami*" OR cmd LIKE "*-enc *" OR cmd LIKE "*-encodedcommand*"
                  OR cmd LIKE "*downloadstring*" OR cmd LIKE "*invoke-webrequest*" OR cmd LIKE "*invoke-expression*"
                  OR cmd LIKE "*iex(*" OR cmd LIKE "*iex (*" OR cmd LIKE "*ipconfig*" OR cmd LIKE "*net user*"
                  OR cmd LIKE "*net group*" OR cmd LIKE "*certutil*" OR cmd LIKE "*bitsadmin*"
// a named app-server process starting any shell is the case; a bare JVM only with a hands-on child
| WHERE shell AND (app_server OR (jvm AND hands_on))
| EVAL finding = CASE(app_server, "app_server_spawned_shell", "jvm_spawned_hands_on_command")
| KEEP @timestamp, host.id, host.name, user.name, finding, process.parent.name, process.name, process.command_line,
       process.entity_id, _id, _version, _index
```

```logscale
#event_simpleName=/^(ProcessRollup2|SyntheticProcessRollup2)$/ event_platform=Win
| FileName=/^(cmd|powershell|pwsh|mshta|wscript|cscript|rundll32|regsvr32|certutil|bitsadmin|whoami|net|net1|nltest|systeminfo|curl)\.exe$/i
// no * branch: a parent that is neither an app server nor a JVM is dropped on purpose
| case {
    ParentBaseFileName=/^(tomcat.*|crushftp.*|beasvc|wrapper|jbosssvc|php-cgi|httpd|nginx)\.exe$/i
      | finding := "app_server_spawned_shell";
    ParentBaseFileName=/^(java|javaw)\.exe$/i
      | (FileName=/^(whoami|net|net1|nltest|systeminfo|certutil|bitsadmin|curl|mshta)\.exe$/i
         OR CommandLine=/whoami|-enc(odedcommand)?\s|downloadstring|invoke-webrequest|invoke-expression|iex\s?\(|ipconfig|net\s+(user|group)/i)
      | finding := "jvm_spawned_hands_on_command";
  }
| select([@timestamp, aid, ComputerName, UserName, finding, ParentBaseFileName, FileName, CommandLine])
```

## Before turning it on

Run the ES|QL over 30 days. The `app_server_spawned_shell` rows that remain are your applications' own maintenance
scripts, for example Tomcat's `catalina.bat` run through a wrapper. Exclude each as a pair of the parent and the
child command it runs, never the host.

## What it misses

- **An application server with an unlisted process name.** Add your estate's own (Confluence, Jira, ManageEngine,
  MOVEit, GoAnywhere) to `app_server` once you know them. Many run as `tomcat9.exe` or `java.exe`, which are already
  covered.
- **Exploitation that stays inside the JVM.** A Java webshell or in-memory implant runs no child process. `CS22`
  (webshell write and execute) and `X04` (WAF hit then callback) are the neighbours.
- **The Linux and IIS cases**, which are `L03` and `AD11`.

## When it fires

Treat the host as compromised from outside. Check the application's access log for the request that preceded the
process start, and isolate the host before the child process's own children run.
