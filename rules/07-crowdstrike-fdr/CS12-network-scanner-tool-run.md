---
id: CS12
name: Network scanner run (nmap, masscan, rustscan, zmap, Advanced IP Scanner, SoftPerfect NetScan, Angry IP Scanner, nbtscan, fscan)
category: crowdstrike-fdr
status: todo
severity: medium
language: esql
index: logs-crowdstrike.fdr-*
mitre: [T1046, T1018]
data_source: CrowdStrike FDR ProcessRollup2
suppression:
  fields: [host.id, process.executable]
  duration: 1h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
Ransomware crews and hands-on-keyboard intruders scan the internal network early, and they mostly bring the same tools: Advanced IP Scanner and SoftPerfect NetScan show up in a large share of ransomware incident reports, nmap and masscan everywhere else, and `fscan` and `nbtscan` in recent state-sponsored intrusions. Outside the network and security teams, nobody in the business runs them.

This is the companion to B01. B01 catches any scan by its shape but relies on Falcon recording connections, which raw-packet scans (nmap as admin, masscan, ping sweeps) may not produce. Starting the scanner is always a process event, so this rule sees those scans whatever packets they send. It matches the file name of the program, so a copy run from Downloads or Temp matches, but a renamed binary doesn't (B01 covers renamed tools that use normal connections).

## Query
```esql
FROM logs-crowdstrike.fdr-* METADATA _id, _index, _version
| WHERE event.action == "ProcessRollup2"
| EVAL exe = TO_LOWER(COALESCE(process.executable, ""))
| WHERE exe RLIKE """.*[\\/](nmap|masscan|rustscan|zmap|nbtscan|fscan|advanced_ip_scanner|netscan|ipscan)(\.exe)?"""
  // network and security team hosts that scan by design (placeholders: Falcon agent IDs)
  AND NOT host.id IN ("<network_team_aid>", "<security_team_aid>")
| KEEP @timestamp, host.id, host.name, user.name, process.executable, process.command_line, process.parent.name,
       process.hash.sha256, _id, _version, _index
```

**CrowdStrike (Falcon LogScale / Advanced Event Search)**
```logscale
#event_simpleName=/^(ProcessRollup2|SyntheticProcessRollup2)$/
| ImageFileName=/[\\\/](nmap|masscan|rustscan|zmap|nbtscan|fscan|advanced_ip_scanner|netscan|ipscan)(\.exe)?$/i
| !in(field="aid", values=["<network_team_aid>", "<security_team_aid>"])
| table([@timestamp, aid, ComputerName, UserName, ImageFileName, CommandLine, ParentBaseFileName, SHA256HashData])
```

The pattern matches the last part of the path: `nmap.exe`, `/usr/bin/nmap`, `advanced_ip_scanner.exe` and `fscan.exe` match; `nmapper.exe` doesn't.

## Suppression
Suppress by `host.id`, `process.executable` for 1h. Alerts missing a key field are not suppressed. Scanners are often run several times in a row with different options. A different host or tool still alerts.

## Known false positives / exclusions
- The network and security teams. Replace the placeholders with their hosts' Falcon agent IDs; exclude by host, not by user, so a stolen admin account on another host still alerts.
- `ipscan` is Angry IP Scanner on Windows; `netscan` is SoftPerfect. Another product shipping a binary with one of these names would match; exclude it by full path once seen.

## Triage
- Who ran it and from where it was launched (`process.parent.name`, the command line). Advanced IP Scanner or NetScan run from `Downloads` or `Temp` on a server, by an account that isn't IT, is an intruder mapping the network.
- Read the command line for the targets and ports, then check B01 and B04 on the same host for what followed.

## Test
Run `nmap -sn <lab subnet>` on a lab host.
