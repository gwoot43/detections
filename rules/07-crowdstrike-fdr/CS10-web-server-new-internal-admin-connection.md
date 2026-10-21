---
id: CS10
name: Web server process connects to internal RDP, SMB, SSH, WinRM or RPC on a host it has never contacted (webshell tunnel or pivot)
category: crowdstrike-fdr
status: todo
language: esql
index: logs-yourorg-crowdstrike-data-default*
mitre: [T1090.001, T1572, T1505.003, T1021]
data_source: CrowdStrike FDR NetworkConnectIP4
suppression:
  fields: [host.id, process.name]
  duration: 24h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
Webshell tunnels (reGeorg, Neo-reGeorg, Suo5 and similar) turn a compromised web server into a SOCKS proxy: the attacker sends traffic over HTTPS to the webshell, and the web server process opens the real connections to internal hosts. The web server process then talks to RDP, SMB, SSH, WinRM or RPC on machines it has no business with. Commands run through a webshell to move laterally look the same on the network.

A web server's own back-end connections are stable: the same database, the same file share, the same API, every day. So the rule doesn't list allowed targets. It asks one question: did a web server process connect to an admin port on an internal host it hasn't connected to in the last 7 days? Everything the application does routinely is in that history and never alerts.

Database (1433, 3306, 5432) and directory (88, 389, 636) ports are left out because web apps use them legitimately. Process spawns from a web server are AD11, and the web exploit itself is X04.

## Query
Run hourly with a 7-day lookback.
```esql
FROM logs-yourorg-crowdstrike-data-default*
// Anchor: a web server process connecting to SSH, RPC, SMB, RDP or WinRM on an internal address.
| WHERE event.action == "networkconnectip4"
  AND process.name IN ("w3wp.exe", "php-cgi.exe", "php-fpm", "httpd", "httpd.exe", "apache2", "nginx", "nginx.exe",
                       "tomcat8.exe", "tomcat9.exe", "tomcat10.exe")
  AND destination.port IN (22, 135, 445, 3389, 5985, 5986)
  AND CIDR_MATCH(destination.ip, "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
// One row per server, process and target: when it first made this connection in the 7 days.
| STATS first_seen = MIN(@timestamp), host.name = VALUES(host.name)
    BY host.id, process.name, destination.ip, destination.port
// New in the last 2 hours (two hourly runs). Everything the application does routinely is in the history.
| WHERE first_seen >= NOW() - 2 hours
// One row per server and process, listing every new target.
| STATS new_targets = COUNT_DISTINCT(destination.ip),
        targets = VALUES(destination.ip),
        ports = VALUES(destination.port),
        first_seen = MIN(first_seen),
        host.name = VALUES(host.name)
    BY host.id, process.name
| KEEP host.id, host.name, process.name, new_targets, targets, ports, first_seen
```

**CrowdStrike (Falcon LogScale / Advanced Event Search)**, run over the last 7 days:
```logscale
#event_simpleName=NetworkConnectIP4
// Anchor: a web server process connecting to SSH, RPC, SMB, RDP or WinRM on an internal address.
| in(field="ContextBaseFileName", ignoreCase=true, values=["w3wp.exe", "php-cgi.exe", "php-fpm", "httpd", "httpd.exe", "apache2",
                                                          "nginx", "nginx.exe", "tomcat8.exe", "tomcat9.exe", "tomcat10.exe"])
| in(field="RemotePort", values=["22", "135", "445", "3389", "5985", "5986"])
| cidr(RemoteAddressIP4, subnet=["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"])
// One row per server, process and target: when it first made this connection in the 7 days.
| groupBy([aid, ContextBaseFileName, RemoteAddressIP4, RemotePort], function=[min(@timestamp, as=first_seen), collect([ComputerName])],
          limit=max)
// New in the last 2 hours (two hourly runs), then one row per server and process listing every new target.
| _now := now()
| test(first_seen > _now - 7200000)
| groupBy([aid, ContextBaseFileName], function=[count(RemoteAddressIP4, distinct=true, as=new_targets),
                                              collect([ComputerName, RemoteAddressIP4, RemotePort]), min(first_seen, as=first_seen)], limit=max)
| first_seen := formatTime(format="%F %T", field=first_seen, timezone="Australia/Sydney")
```

The first `STATS` finds when each web server first reached each internal admin port in the 7 days. The second keeps the ones that are new in the last 2 hours (two hourly runs, so a late event isn't missed) and rolls them up to one row per server and process, with every new target listed.

The process filter compares `process.name` unchanged so Elasticsearch can apply it in the index; FDR writes these names in lower case. `process.name` on network events comes from `ContextBaseFileName`, which older sensors don't send.

**Java web apps** (Confluence, Jira, JBoss, Tomcat on Linux) run as `java` or `java.exe`. Add them if your web apps are Java. Java desktop tools also run under that name, so expect a few more alerts on developer machines.

## Suppression
Suppress by `host.id`, `process.name` for 24h. Alerts missing a key field are not suppressed. Aggregating rule: a tunnel used through the day keeps finding new targets, and those fold into the open alert with a rising count. A different web server still alerts.

## Known false positives / exclusions
- An application change that points the site at a new file share or server. It alerts once and then becomes part of the history.
- A new web server in its first 7 days has no history, so all its back-end connections look new. Expect alerts during the first week after a build.

## Triage
- `targets` and `ports` show where the web server reached. RDP or WinRM to a workstation or domain controller from a web server is not application traffic.
- Check the web server for a recently written script file in the web root (FDR file-written events under `inetpub`, `htdocs` or `webapps`) and for shells spawned by the web server process (AD11).
- On each target, look for logons arriving from the web server's IP.

## Test
On a lab IIS server, drop a test ASPX page that opens a TCP connection to port 3389 on another lab host, and load the page.
