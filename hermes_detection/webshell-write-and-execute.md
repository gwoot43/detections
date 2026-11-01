# Web-shell write and execute

A web shell is the step that turns an exploited application into a command channel, and it is the one ARTEX-class frameworks leave behind deliberately: the reported tradecraft staged custom Python, C# and PowerShell through Kudu administrative APIs, and the accompanying indicators call out `*.aspx` and `*.jsp` files appearing on the target.

Two moments are observable, and either one is enough:

**The execution.** A web server process spawning a shell or a loader. IIS (`w3wp.exe`), Apache and nginx with PHP (`httpd.exe`, `php-fpm`), Tomcat (`java`), or a Node process does not fork `cmd.exe`, `powershell.exe` or `certutil.exe` unless an application told it to - and when it does, the request that told it is a web shell.

**The write.** A server-side script extension appearing under a web root, opened by something that is *not* the web server and *not* a deployment tool. IIS opens `.aspx` files constantly while compiling them, so the writer matters: the web server touching its own files is noise, and `curl.exe`, `powershell.exe` or `python` creating one is not.

```esql
FROM logs-yourorg-crowdstrike-data-default*
// 15 minutes, stated in the query: the write and the first execution are usually seconds apart.
| WHERE @timestamp >= NOW() - 15 minutes
  AND event.action IN ("processrollup2", "syntheticprocessrollup2", "fileopeninfo", "fspostopen")
| EVAL is_proc = event.action LIKE "%processrollup2",
       parent = TO_LOWER(COALESCE(process.parent.name, "")),
       child = TO_LOWER(COALESCE(process.name, "")),
       cl = TO_LOWER(COALESCE(process.command_line, "")),
       path = TO_LOWER(TO_STRING(COALESCE(file.path, ""))),
       user = TO_LOWER(COALESCE(user.name, ""))
// The processes that serve web requests, on both operating systems in this estate.
| EVAL web_server = child IN ("w3wp.exe", "httpd.exe", "nginx.exe", "apache2", "httpd", "nginx",
                             "php-fpm", "php-cgi", "php", "java", "tomcat", "node", "dotnet"),
// What a web shell actually needs to run: a shell, a fetch, or a discovery binary.
       shell_child = child IN ("cmd.exe", "powershell.exe", "pwsh.exe", "pwsh", "bash", "sh", "dash", "ksh",
                               "cscript.exe", "wscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe",
                               "certutil.exe", "bitsadmin.exe", "curl", "curl.exe", "wget", "python", "python3",
                               "perl", "net.exe", "net1.exe", "whoami.exe", "systeminfo.exe", "nltest.exe",
                               "ipconfig.exe", "tasklist.exe", "hostname.exe", "quser.exe"),
// The worker identity, not an administrator. Maintenance is done by a human as SYSTEM or admin; a web shell
// inherits the app-pool or www-data context it was uploaded into.
       worker_identity = user LIKE "%iis apppool%\\%" OR user LIKE "%nt authority\\network service%"
                         OR user IN ("www-data", "apache", "nginx", "nobody", "tomcat", "httpd", "php-fpm"),
// Payload shape in the spawned command line: fetch it, encode it, or look around.
       payload = cl LIKE "%http://%" OR cl LIKE "%https://%" OR cl LIKE "% -enc%" OR cl LIKE "%frombase64%"
                 OR cl LIKE "%certutil%" OR cl LIKE "%bitsadmin%" OR cl LIKE "%whoami%" OR cl LIKE "%net user%"
                 OR cl LIKE "%net group%" OR cl LIKE "%nltest%" OR cl LIKE "%systeminfo%" OR cl LIKE "%/dev/tcp/%"
                 OR cl LIKE "%invoke-%" OR cl LIKE "%downloadstring%",
// Server-side extensions a web server will execute, as opposed to static files it will only serve.
       webshell_ext = path LIKE "%.aspx" OR path LIKE "%.ashx" OR path LIKE "%.asmx" OR path LIKE "%.ascx"
                      OR path LIKE "%.jsp" OR path LIKE "%.jspx" OR path LIKE "%.php" OR path LIKE "%.phtml"
                      OR path LIKE "%.cer" OR path LIKE "%.war",
       deploy_tool = child IN ("msiexec.exe", "setup.exe", "installutil.exe", "devenv.exe", "robocopy.exe",
                               "xcopy.exe", "7z.exe", "winrar.exe", "tar", "unzip", "git", "svn", "dotnet.exe")
// Execution: a web server forking a shell, with the worker identity or a fetch/discovery payload to confirm it.
// Write: a server-side script written by anything that is neither the web server nor a deployment tool.
| WHERE (is_proc AND parent IN ("w3wp.exe", "httpd.exe", "nginx.exe", "apache2", "httpd", "nginx",
                               "php-fpm", "php-cgi", "php", "java", "tomcat", "node", "dotnet")
         AND shell_child AND (worker_identity OR payload))
     OR (NOT is_proc AND webshell_ext AND NOT web_server AND NOT deploy_tool)
| EVAL finding = CASE(is_proc, "web_server_spawned_shell", "server_side_script_written")
// One row per host and shape: a web shell runs again and again, and the alert should say how often.
| STATS events = COUNT(*),
        first_seen = MIN(@timestamp), last_seen = MAX(@timestamp),
        commands = MV_SLICE(VALUES(process.command_line), 0, 4),
        paths = MV_SLICE(VALUES(file.path), 0, 4),
        writers = MV_SLICE(VALUES(process.name), 0, 4),
        users = MV_SLICE(VALUES(user.name), 0, 3)
    BY host.id, host.name, finding
| SORT events DESC
| LIMIT 100
```

Deploy every 5 minutes over the last 15. Suppress by `host.id` + `finding` for 24h.

## Reading the alert
- **`commands`** on a `web_server_spawned_shell` row is the executed request. `whoami`, `net user`, `certutil -urlcache -f http://...` and `powershell -enc` are the first four commands of nearly every web shell.
- **`paths`** on a `server_side_script_written` row is the file itself. A name under a web root ending `.aspx`/`.jsp` that nobody deployed is the shell; read the timestamp against your deployment calendar.
- **`writers`** is the differentiator on the write side: `w3wp.exe` compiling its own pages is why this branch excludes the web server, and `curl.exe` or `python` writing a `.aspx` is not a build.
- **`users`** should be the app-pool or `www-data` identity. A shell running as `NT AUTHORITY\SYSTEM` from a web server is worse, not better - it means the app pool is privileged.

## Nearest benign twins
- **Legitimate .NET or PHP applications calling out to system tools** - report generators invoking `cmd.exe /c`, PDF converters invoking a binary. They run as the app-pool identity too, so the payload test is what separates them: a fixed argument list with no URL, no `-enc`, no discovery command.
- **Deployment pipelines** writing files into a web root. Excluded by `deploy_tool`, and the remaining case is a pipeline using a custom uploader - an entity pair once it is confirmed.
- **Health checks and agents** that shell out from `w3wp.exe` for monitoring. Rare, and usually a fixed command line.
- **`java` and `node` parents are broad.** Application servers legitimately fork subprocesses, so those rows lean on `payload`; if your estate has heavy `node` usage, drop `node` from the parent list and let the write branch carry it.

## What it misses
- **A web shell running inside the application itself** - `System.Diagnostics.Process` in an ASPX page is a `w3wp.exe` child, which is covered; a shell that stays inside `w3wp` with no child process is not.
- **In-memory web shells** (a filter or module loaded into the worker process), which never touch disk and never spawn.
- **File writes on hosts where `fileopeninfo`/`fspostopen` are not collected** - the write branch then silently matches nothing while the execution branch still works, which is the reason both shapes are in one rule.
- **Linux file writes** if the sensor's file events are not deployed for that platform; the process branch covers execution on both.
- **A shell dropped with a non-executable extension** (`.jpg`, `.txt`) and invoked by an already-present loader - that is a different rule.

## Probe before enabling
Two fields carry this rule, and either can be absent without the query failing:
```esql
FROM logs-yourorg-crowdstrike-data-default*
| WHERE @timestamp >= NOW() - 24 hours
  AND event.action IN ("processrollup2", "fileopeninfo", "fspostopen")
| STATS events = COUNT(*), with_path = COUNT(*) WHERE file.path IS NOT NULL,
        with_parent = COUNT(*) WHERE process.parent.name IS NOT NULL
    BY event.action, host.os.type
| SORT events DESC
```
`with_path` at zero on `fileopeninfo` means the write branch is dead - keep the execution branch and say so in the rule description, rather than shipping a branch that never fires.

## References
- Zscaler ThreatLabz, ARTEX campaign analysis (October 2026) - Kudu API abuse to stage custom Python/C#/PowerShell, and `*.aspx`/`*.jsp` as an indicator: `zscaler.com/blogs/security-research/threat-actor-abuses-agentic-ai-pentesting-framework-target-south-korean`
- MITRE T1505.003 (web shell), T1059 (command and scripting interpreter), T1105 (ingress tool transfer)
- `rules/03-endpoint-windows/W02-office-browser-spawns-script-host.md` - the same parent/child logic for the browser path; this is its server-side mirror
