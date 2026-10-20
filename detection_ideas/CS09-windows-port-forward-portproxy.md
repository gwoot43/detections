---
id: CS09
name: Windows port forward created with netsh portproxy (traffic relayed through this host)
category: crowdstrike-fdr
status: todo
severity: high
language: esql
index: logs-yourorg-crowdstrike-data-default*
mitre: [T1090.001, T1572]
data_source: CrowdStrike FDR ProcessRollup2 and registry value updates
suppression:
  fields: [host.id]
  duration: 1h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
`netsh interface portproxy` is Windows' built-in port forwarder. One command makes the host listen on a port and relay everything to another host and port, with no tool to drop and nothing listening that looks unusual. Attackers use it to reach internal systems through a machine they control (RDP to a server the VPN can't reach, for example) and to put RDP behind an innocent-looking port. It's a signature technique of Volt Typhoon and other hands-on-keyboard groups.

The rule watches both ends: the `netsh` command that adds or changes a forward, and the registry key the forward is stored in (`HKLM\SYSTEM\CurrentControlSet\Services\PortProxy`), which catches forwards written directly to the registry.

There's nothing to count and no rarity to apply: one forward is the event, and forwards are rare on every host.

## Query
```esql
FROM logs-yourorg-crowdstrike-data-default* METADATA _id, _index, _version
// Anchor: Windows process starts and registry writes, the two places a port forward shows up.
| WHERE host.os.type == "windows"
  AND event.action IN ("processrollup2", "reggenericvalueupdate", "regsystemconfigvalueupdate", "asepvalueupdate")
| EVAL cmd = TO_LOWER(COALESCE(process.command_line, "")),
       key = TO_LOWER(COALESCE(registry.path, ""))
// A netsh command that adds or changes a forward (show and delete don't match),
// or any write to the key forwards are stored in, which catches forwards written straight to the registry.
| WHERE (cmd LIKE "*portproxy*" AND (cmd LIKE "* add *" OR cmd LIKE "* set *"))
     OR key LIKE """*\\services\\portproxy\\*"""
| KEEP @timestamp, host.id, host.name, user.name, event.action, process.parent.name, process.command_line,
       registry.path, registry.data.strings, _id, _version, _index
```

**CrowdStrike (Falcon LogScale / Advanced Event Search)**
```logscale
#event_simpleName=/^(ProcessRollup2|SyntheticProcessRollup2|RegGenericValueUpdate|RegSystemConfigValueUpdate|AsepValueUpdate)$/ event_platform=Win
| case {
    // a netsh command that adds or changes a forward (show and delete don't match)
    #event_simpleName=/ProcessRollup2$/ CommandLine=/portproxy/i CommandLine=/\s(add|set)\s/i
      | finding := "netsh portproxy command";
    // any write to the key forwards are stored in, including forwards written straight to the registry
    RegObjectName=/\\Services\\PortProxy\\/i
      | finding := "PortProxy registry write";
  }
| select([@timestamp, aid, ComputerName, UserName, finding, ParentBaseFileName, CommandLine, RegObjectName, RegValueName, RegStringValue])
```

The `netsh` command line holds the whole forward (`listenport=`, `connectaddress=`, `connectport=`). In the registry the value name is the listen address and port, and the data is the target. Whether the registry branch fires depends on your sensor reporting writes to that key; the process branch doesn't depend on it.

## Suppression
Suppress by `host.id` for 1h. Alerts missing a key field are not suppressed. One `netsh` command writes a process event and a registry event; they fold into one alert. A forward on another host still alerts.

## Known false positives / exclusions
- Developers forwarding ports into WSL2 or a local VM (`connectaddress` is a `172.x` WSL address or `127.0.0.1`). Exclude those hosts' group once confirmed, not the command.
- Admins publishing a legacy service on a different port. Rare and worth a ticket.
- `netsh interface portproxy show` and `delete` don't match.

## Triage
- Read the forward: which port this host now listens on and where it sends traffic. A forward to port 3389, 22 or 445 on another internal host is a pivot.
- Look at the parent process and user that ran `netsh`, then check the target host for logons arriving from this host's IP (4624 logon type 3 or 10).
- Remove it with `netsh interface portproxy delete v4tov4 listenport=<port> listenaddress=<address>`, then contain the host.

## Test
On a lab host, run `netsh interface portproxy add v4tov4 listenport=8888 connectaddress=127.0.0.1 connectport=3389`, then `netsh interface portproxy reset`.
