---
id: CS19
name: PHP worker (or Apache running mod_php) does something new - starts a program, writes a web script, looks up a name or connects on a port it hasn't before (PHP2Shell and web shell follow-up)
category: crowdstrike-fdr
status: todo
language: esql
index: logs-yourorg-crowdstrike-data-default*
mitre: [T1190, T1505.003, T1059]
data_source: CrowdStrike FDR ProcessRollup2, NetworkConnectIP4/6, DnsRequest and file-written events
suppression:
  fields: [host.id, event.action]
  duration: 24h
  missing_fields: do_not_suppress
---
PHP2Shell (CVE-2026-109618 and CVE-2026-109619) gets code running inside PHP before the application sees the request, so the exploit itself leaves nothing on the host. What the attacker does next does: the PHP process starts a shell, drops a web shell, looks up a C2 domain or connects out on a port it never uses. The same is true of any other PHP remote code execution or web shell. So this watches everything PHP processes do, and alerts on the first time a host's PHP does each thing in 14 days:

- **starts a program** it hasn't started before (keyed on the program, not the full command line);
- **writes a web script** or a file that makes PHP load one: `.php`, `.php5`/`.php7`, `.phtml`, `.phar`, `.inc`, `.htaccess`, `.user.ini`;
- **looks up a domain** it hasn't before;
- **connects on a port** it hasn't before, internal and external counted apart. Keyed on the port, not the address, because PHP apps call cloud APIs whose addresses change daily.

PHP means the PHP binaries (`php`, `php-cgi`, `php-fpm` and its versioned names, `lsphp`, `frankenphp`), plus Apache on the servers that run mod_php, where PHP lives inside `httpd`/`apache2`. That's the setup PHP2Shell hits hardest.

Run daily over the last 14 days.

**CrowdStrike (Falcon LogScale / Advanced Event Search).** This is the stronger version: it links activity to the PHP process by process ID, so connections and lookups that carry no process name still count.
```logscale
// PHP processes seen in the last 30 days, since workers can live for weeks. Apache only on the mod_php servers.
defineTable(name="php_procs", start=30d, include=[aid, TargetProcessId, init_name, init_cmd, init_parent], query={
    #event_simpleName=/^(ProcessRollup2|SyntheticProcessRollup2)$/
    // A filter: deliberately no * branch, so any other process is dropped.
    | case {
        FileName=/^(php(-cgi|-fpm|-win)?[0-9.]*|php[0-9.]+-fpm|lsphp[0-9]*|frankenphp)(\.exe)?$/i;
        FileName=/^(httpd|apache2)(\.exe)?$/i | in(field="aid", values=["<mod_php_server_aid>"]);
      }
    | init_name := FileName
    | init_cmd := CommandLine
    | init_parent := ParentBaseFileName
})
| #event_simpleName=/^(ProcessRollup2|SyntheticProcessRollup2|NetworkConnectIP[46]|DnsRequest|[A-Za-z]*Written)$/
// The process that did it: the parent of a new process, the context process for everything else.
| case {
    #event_simpleName=/ProcessRollup2$/ | init_pid := ParentProcessId | path := ImageFileName;
    * | init_pid := ContextProcessId | path := TargetFileName;
  }
// Keep only what a PHP process did, matched by process ID.
| match(table="php_procs", field=[aid, init_pid], column=[aid, TargetProcessId], strict=true)
| regex("(?<fname>[^\\\\/]+)$", field=path, strict=false)
// File writes: only web scripts and the files that make PHP load one. Loopback connections and the console host
// Windows starts for every exec() don't count.
| NOT (#event_simpleName=/Written$/ AND fname!=/\.(php[0-9]?|phtml|phar|inc)$|^\.htaccess$|^\.user\.ini$/i)
| NOT RemoteAddressIP4=/^127\./
| NOT RemoteAddressIP6="::1"
| NOT CommandLine=/conhost\.exe\s+0xffffffff\s+-ForceV1$/i
// What "new" is measured on, per kind of activity.
| case {
    #event_simpleName=/ProcessRollup2$/ | what := fname;
    #event_simpleName=/Written$/ | what := path;
    #event_simpleName=DnsRequest | what := DomainName;
    #event_simpleName=/^NetworkConnectIP/ | cidr(RemoteAddressIP4, subnet=["10.0.0.0/8", "100.64.0.0/10", "172.16.0.0/12", "192.168.0.0/16"])
      | what := format("internal port %s", field=[RemotePort]);
    #event_simpleName=/^NetworkConnectIP/ | what := format("external port %s", field=[RemotePort]);
    * | what := "-";
  }
| default(field=[CommandLine, RemoteAddressIP4, init_cmd, init_parent], value="-")
| groupBy([aid, #event_simpleName, what], function=[min(@timestamp, as=FirstSeen), count(as=events),
          selectFromMin(field=@timestamp, include=[init_name, init_cmd, init_parent, CommandLine, path, RemoteAddressIP4])],
          limit=max)
// New for this host's PHP in the last 24 hours.
| _now := now()
| test(FirstSeen >= _now - 86400000)
| match(file="aid_master_main.csv", field=aid, include=[ComputerName], strict=false)
| FirstSeen := formatTime("%Y-%m-%d %H:%M:%S", field=FirstSeen, timezone="Australia/Sydney")
| select([FirstSeen, aid, ComputerName, #event_simpleName, what, events, init_name, init_cmd, init_parent, CommandLine, path,
          RemoteAddressIP4])
```

**Same idea in ES|QL.** ES|QL can't look up a process by ID, so it matches the initiating process by name: the parent's name on a new process, the context process's name on everything else. Connections and lookups without a process name (common on older sensors) are missed, so prefer the LogScale version where you can.
```esql
FROM logs-yourorg-crowdstrike-data-default*
// What a PHP process did: started a program (PHP is the parent), or wrote a file, looked up a name or connected (PHP
// is the context process). The write events are named "...written"; the leading wildcard is on event.action, which
// has only a few values.
| WHERE (event.action IN ("processrollup2", "syntheticprocessrollup2")
         AND (data.ParentBaseFileName IN ("php.exe", "php-cgi.exe", "php-win.exe", "php", "php-cgi", "php-fpm", "lsphp", "frankenphp")
              OR data.ParentBaseFileName LIKE "php-fpm*" OR data.ParentBaseFileName LIKE "php7*" OR data.ParentBaseFileName LIKE "php8*"
              OR (data.ParentBaseFileName IN ("httpd", "httpd.exe", "apache2") AND host.id IN ("<mod_php_server_aid>"))))
     OR ((event.action IN ("networkconnectip4", "networkconnectip6", "dnsrequest") OR event.action LIKE "*written")
         AND (data.ContextBaseFileName IN ("php.exe", "php-cgi.exe", "php-win.exe", "php", "php-cgi", "php-fpm", "lsphp", "frankenphp")
              OR data.ContextBaseFileName LIKE "php-fpm*" OR data.ContextBaseFileName LIKE "php7*" OR data.ContextBaseFileName LIKE "php8*"
              OR (data.ContextBaseFileName IN ("httpd", "httpd.exe", "apache2") AND host.id IN ("<mod_php_server_aid>"))))
// What "new" is measured on: the program started, the file written, the name looked up, or the port (internal and
// external apart). The file name and conhost checks only run on the rows above.
| EVAL file = MV_LAST(SPLIT(REPLACE(COALESCE(data.TargetFileName, ""), "\\\\", "/"), "/")),
       what = CASE(event.action LIKE "*processrollup2", COALESCE(process.name, data.FileName),
                   event.action LIKE "*written", data.TargetFileName,
                   event.action == "dnsrequest", data.DomainName,
                   CIDR_MATCH(destination.ip, "10.0.0.0/8", "100.64.0.0/10", "172.16.0.0/12", "192.168.0.0/16"),
                     CONCAT("internal port ", TO_STRING(destination.port)),
                   CONCAT("external port ", TO_STRING(destination.port)))
| WHERE what IS NOT NULL
  AND NOT (event.action LIKE "*written" AND NOT TO_LOWER(file) RLIKE ".*\\.(php[0-9]?|phtml|phar|inc)|\\.htaccess|\\.user\\.ini")
  AND NOT (destination.ip IS NOT NULL AND CIDR_MATCH(destination.ip, "127.0.0.0/8", "::1/128"))
  AND NOT (process.command_line IS NOT NULL AND process.command_line RLIKE ".*conhost\\.exe +0xffffffff +-ForceV1")
// First time this host's PHP did each thing in the 14 days, with one command line for context.
| STATS first_seen = MIN(@timestamp), events = COUNT(*), command_line = TOP(process.command_line, 1, "asc"),
        initiated_by = VALUES(COALESCE(data.ParentBaseFileName, data.ContextBaseFileName)), host.name = VALUES(host.name)
    BY host.id, event.action, what
// New in the last 24 hours.
| WHERE first_seen >= NOW() - 24 hours
| KEEP first_seen, host.id, host.name, event.action, what, events, initiated_by, command_line
```

Suppress by host and kind of activity (`aid` and `#event_simpleName` in LogScale) for 24h, so a burst of new things from one exploited server is a handful of alerts, not dozens.

## Before turning it on
- **List your mod_php servers** in the two placeholders. Leave them out and Apache's own children (CGI scripts, log rotation) would flood it; leave them empty and mod_php isn't covered at all.
- **Check that a `.php` write is recorded.** FDR doesn't log every file write. In a lab, have PHP write a `.php` file (a `file_put_contents` in a test page) and check that a `...Written` event arrives with PHP as the context process. If it doesn't, web shell drops are invisible here and only the process and network parts work.
- **The first run is noisy.** Everything is new to a 14-day history only once. Let the first daily run's alerts through to a report rather than a queue, then judge the second.
- **Cost.** It reads 14 days of process, connection, DNS and write events. In LogScale, the PHP match drops almost everything straight after the event-type filter. In ES|QL, the name filter is answered by the index.

## What it can miss
- An attacker who stays inside PHP: memory-only payloads, `eval` of code that never starts a process, writes a file or connects anywhere new. CVE-2026-109618's memory disclosure (Heartbleed-style) also leaves no trace here. N12 sees the attempt at the edge.
- A reverse shell to a new address on a port the app already uses (443 out to a new IP). Ports, not addresses, are what's tracked.
- PHP processes older than 30 days in LogScale; older than 14 days or unnamed in ES|QL.
- A new PHP release or a renamed worker that the name pattern doesn't cover.

## When it fires
- **A new program** under PHP: a shell, `curl`, `wget`, `certutil`, `whoami` or a script interpreter is the classic web shell or exploit follow-up (L03 and AD11 overlap here). Read `init_cmd` for which worker or site it was, and `CommandLine` for what ran.
- **A new script file:** open it. A short file with `eval`, `assert`, `system`, `base64_decode` or `$_POST` in it is a web shell; check the web server's access log for requests to it.
- **A new domain or external port:** look the destination up, and see whether anything else on the host followed it.
- Check the PHP version on that host (PHP2Shell is fixed in 8.5.12, 8.4.27, 8.3.36 and 8.2.35) and N12 for attempts against the site at the edge.
