---
id: CS20
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
CS19 reads the PHP code. This watches what PHP does, for the code CS19 can't read: a payload that runs in memory (PHP2Shell's does), or a call built at runtime. It alerts the first time in 14 days a host's PHP:

- **starts a program** (keyed on the program, not the command line);
- **writes a web script**, or a file that makes PHP load one: `.php`, `.php5`/`.php7`, `.phtml`, `.phar`, `.inc`, `.htaccess`, `.user.ini`;
- **looks up a domain**;
- **connects on a port**, internal and external apart. The port, not the address, because PHP apps call cloud APIs whose addresses change daily.

PHP is `php`, `php-cgi`, `php-fpm` and its versioned names, `lsphp` and `frankenphp`, plus `httpd`/`apache2` on the servers that run mod_php, the setup PHP2Shell hits hardest.

This one has to be longer than CS19: "new" means comparing against two weeks of the same host's PHP. Run daily over the last 14 days.

**CrowdStrike (Falcon LogScale / Advanced Event Search).** The stronger version: it ties activity to the PHP process by process ID, so connections and lookups with no process name still count.
```logscale
// PHP processes from the last 30 days (workers live for weeks). Apache only on the mod_php servers.
defineTable(name="php_procs", start=30d, include=[aid, TargetProcessId, init_name, init_cmd, init_parent], query={
    #event_simpleName=/^(ProcessRollup2|SyntheticProcessRollup2)$/
    // Deliberately no * branch: any other process is dropped.
    | case {
        FileName=/^(php(-cgi|-fpm|-win)?[0-9.]*|php[0-9.]+-fpm|lsphp[0-9]*|frankenphp)(\.exe)?$/i;
        FileName=/^(httpd|apache2)(\.exe)?$/i | in(field="aid", values=["<mod_php_server_aid>"]);
      }
    | init_name := FileName
    | init_cmd := CommandLine
    | init_parent := ParentBaseFileName
})
| #event_simpleName=/^(ProcessRollup2|SyntheticProcessRollup2|NetworkConnectIP[46]|DnsRequest|[A-Za-z]*Written)$/
| case {
    #event_simpleName=/ProcessRollup2$/ | init_pid := ParentProcessId | path := ImageFileName;
    * | init_pid := ContextProcessId | path := TargetFileName;
  }
| match(table="php_procs", field=[aid, init_pid], column=[aid, TargetProcessId], strict=true)
| regex("(?<fname>[^\\\\/]+)$", field=path, strict=false)
// Writes count only for web scripts; loopback and the console host Windows starts for every exec() don't count.
| NOT (#event_simpleName=/Written$/ AND fname!=/\.(php[0-9]?|phtml|phar|inc)$|^\.htaccess$|^\.user\.ini$/i)
| NOT RemoteAddressIP4=/^127\./
| NOT RemoteAddressIP6="::1"
| NOT CommandLine=/conhost\.exe\s+0xffffffff\s+-ForceV1$/i
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
// First seen in the last 24 hours.
| _now := now()
| test(FirstSeen >= _now - 86400000)
| match(file="aid_master_main.csv", field=aid, include=[ComputerName], strict=false)
| FirstSeen := formatTime("%Y-%m-%d %H:%M:%S", field=FirstSeen, timezone="Australia/Sydney")
| select([FirstSeen, aid, ComputerName, #event_simpleName, what, events, init_name, init_cmd, init_parent, CommandLine, path,
          RemoteAddressIP4])
```

**Elastic (ES|QL).** ES|QL can't look a process up by ID, so it goes by name: the parent's on a new process, the context process's on everything else. Connections and lookups with no process name are missed.
```esql
FROM logs-yourorg-crowdstrike-data-default*
// A program PHP started, or a write, lookup or connection PHP made. The leading wildcard is on event.action, which
// has only a few values.
| WHERE (event.action IN ("processrollup2", "syntheticprocessrollup2")
         AND (data.ParentBaseFileName IN ("php.exe", "php-cgi.exe", "php-win.exe", "php", "php-cgi", "php-fpm", "lsphp", "frankenphp")
              OR data.ParentBaseFileName LIKE "php-fpm*" OR data.ParentBaseFileName LIKE "php7*" OR data.ParentBaseFileName LIKE "php8*"
              OR (data.ParentBaseFileName IN ("httpd", "httpd.exe", "apache2") AND host.id IN ("<mod_php_server_aid>"))))
     OR ((event.action IN ("networkconnectip4", "networkconnectip6", "dnsrequest") OR event.action LIKE "*written")
         AND (data.ContextBaseFileName IN ("php.exe", "php-cgi.exe", "php-win.exe", "php", "php-cgi", "php-fpm", "lsphp", "frankenphp")
              OR data.ContextBaseFileName LIKE "php-fpm*" OR data.ContextBaseFileName LIKE "php7*" OR data.ContextBaseFileName LIKE "php8*"
              OR (data.ContextBaseFileName IN ("httpd", "httpd.exe", "apache2") AND host.id IN ("<mod_php_server_aid>"))))
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
| STATS first_seen = MIN(@timestamp), events = COUNT(*), command_line = TOP(process.command_line, 1, "asc"),
        initiated_by = VALUES(COALESCE(data.ParentBaseFileName, data.ContextBaseFileName)), host.name = VALUES(host.name)
    BY host.id, event.action, what
// First seen in the last 24 hours.
| WHERE first_seen >= NOW() - 24 hours
| KEEP first_seen, host.id, host.name, event.action, what, events, initiated_by, command_line
```
Suppress by host and kind of activity for 24h, so one exploited server is a handful of alerts, not dozens.

## Before turning it on
- **List your mod_php servers** in the two placeholders. Without them, mod_php isn't covered at all.
- **Check a `.php` write is recorded.** FDR doesn't log every write. In a lab, have PHP write a `.php` file and check a `...Written` event arrives with PHP as the context process. If not, only the process and network parts work.
- **The first run is noisy:** everything is new once. Send the first day to a report, then judge the second.

## What it misses
- An attacker who stays inside PHP: no new process, file, domain or port. CVE-2026-109618's memory disclosure leaves nothing here either; N12 sees it at the edge.
- A reverse shell on a port the app already uses (443 to a new address).
- PHP processes older than 30 days in LogScale; older than 14 days or unnamed in ES|QL.

## When it fires
- **A new program:** a shell, `curl`, `wget`, `whoami` or an interpreter under PHP is the classic web shell follow-up. `init_cmd` says which worker or site, `CommandLine` what ran.
- **A new script file:** open it, and run CS19's script query over that host.
- **A new domain or external port:** look the destination up and see what followed on the host.
- Check the PHP version (fixed in 8.5.12, 8.4.27, 8.3.36 and 8.2.35) and N12 for attempts at the edge.
