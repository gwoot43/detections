---
id: CS18
name: Common attacker tool started, by file name (scanners, credential and secret stealers, lateral movement, tunnels, privilege escalation, exfiltration, EDR killers)
category: crowdstrike-fdr
status: todo
language: esql
index: logs-yourorg-crowdstrike-data-default*
mitre: [T1046, T1003, T1555, T1552.001, T1021, T1110, T1572, T1090, T1068, T1567.002, T1685]
data_source: CrowdStrike FDR ProcessRollup2
suppression:
  fields: [host.id, process.name]
  duration: 24h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
**One question:** did a tool that intruders commonly use start on this host, under the name it ships with? Intruders often don't bother renaming their tools, so the name alone finds them. This is the one place known tools are matched by name. The behaviour rules (B01 scanning, B04 lateral movement, B07 file staging, B08 credential stores, CS03 DNS tunnels, CS16 pivoting, CS17 key testing) catch renamed and recompiled copies by what they do. This rule catches the tool when its behaviour isn't visible: a raw-packet scan, a scan with key checking switched off, a run below a threshold.

| Family | Tools (as they ship) |
|---|---|
| Network scanning | nmap, masscan, RustScan, ZMap, naabu, fscan, nbtscan, Advanced IP and Port Scanner, SoftPerfect NetScan, Angry IP Scanner |
| Credential theft | LaZagne, HackBrowserData, SharpChrome, SharpDPAPI, SharpKatz, SafetyKatz, pypykatz, nanodump |
| Secret scanning | TruffleHog, gitleaks, Nosey Parker |
| Lateral movement and spraying | CrackMapExec, NetExec, Kerbrute |
| Tunnels and proxies | chisel, gost, frp, revsocks, rathole, iox, ligolo on Linux (W10 matches them on Windows); iodine, dnscat2, dns2tcp |
| Privilege escalation | PrintSpoofer, the Potato family (Juicy, God, Sweet, Rogue, Efs), winPEAS and linPEAS builds, pspy |
| Exfiltration | rclone |
| Disabling security tools | EDRSandBlast, Backstab, PCHunter |

Not repeated here: W09 matches AD attack tools by name (AdFind, Rubeus, Mimikatz, SharpHound, Certify, Whisker, Seatbelt, SharpView, Snaffler), and W10 matches remote-access tools and tunnels on Windows.

- **Anchor:** a process start whose file name is one of these.
- **Corroborating property:** none. The name is the evidence, which is why this is a fallback, not the main line of detection.
- **Exclusion:** a host and the tool it runs by design (the network team's scanner, AppSec's secret scanner, IT's rclone), never the whole host.

## Query
Run every 5 minutes with a 10-minute lookback. It's a non-aggregating rule: one alert per process start.
```esql
FROM logs-yourorg-crowdstrike-data-default* METADATA _id, _index, _version
// 1 GATE: a process starting under the name an attacker tool ships with. Exact names, plus prefixes for versioned or
// architecture-suffixed builds; the index answers both, so no other process start is read. LIKE and IN are
// case-sensitive, so names are listed in the case each tool ships in.
| WHERE event.action IN ("processrollup2", "syntheticprocessrollup2")
  AND (process.name IN (
         "nmap.exe", "nmap", "masscan.exe", "masscan", "rustscan.exe", "rustscan", "zmap", "naabu.exe", "naabu",
         "advanced_ip_scanner.exe", "advanced_port_scanner.exe", "netscan.exe", "ipscan.exe",
         "LaZagne.exe", "lazagne.exe", "laZagne", "hack-browser-data.exe", "hack-browser-data", "SharpChrome.exe",
         "SharpDPAPI.exe", "SharpKatz.exe", "SafetyKatz.exe", "pypykatz.exe",
         "trufflehog.exe", "trufflehog", "gitleaks.exe", "gitleaks", "noseyparker.exe", "noseyparker",
         "crackmapexec.exe", "cme.exe", "nxc.exe", "netexec.exe",
         "chisel", "gost", "frpc", "frps", "revsocks", "rathole", "iox", "iodine", "iodine.exe", "dnscat", "dnscat2",
         "dnscat2.exe", "dns2tcpc",
         "rclone.exe", "rclone")
       OR process.name LIKE "nbtscan*" OR process.name LIKE "fscan*" OR process.name LIKE "kerbrute*"
       OR process.name LIKE "nanodump*" OR process.name LIKE "ligolo*"
       OR process.name LIKE "PrintSpoofer*" OR process.name LIKE "JuicyPotato*" OR process.name LIKE "GodPotato*"
       OR process.name LIKE "SweetPotato*" OR process.name LIKE "RoguePotato*" OR process.name LIKE "EfsPotato*"
       OR process.name LIKE "winPEAS*" OR process.name LIKE "linpeas*" OR process.name LIKE "pspy*"
       OR process.name LIKE "EDRSandBlast*" OR process.name LIKE "Backstab*" OR process.name LIKE "PCHunter*")
  // A host and the tool it runs by design, never the whole host (placeholders).
  AND NOT ((host.id == "<network_team_aid>" AND process.name IN ("nmap.exe", "advanced_ip_scanner.exe"))
           OR (host.id == "<appsec_aid>" AND process.name IN ("trufflehog", "gitleaks"))
           OR (host.id == "<file_server_aid>" AND process.name == "rclone"))
// 6 OUTPUT: who ran it, from where and how. The process ID links to everything it did afterwards.
| KEEP @timestamp, host.id, host.name, user.name, process.name, process.executable, process.command_line, process.parent.name,
       data.TargetProcessId, _id, _version, _index
```

**CrowdStrike (Falcon LogScale / Advanced Event Search)**, run every 5 minutes over the last 10 minutes:
```logscale
#event_simpleName=/^(ProcessRollup2|SyntheticProcessRollup2)$/
// 1 GATE: the same names, any case, with wildcards for versioned or architecture-suffixed builds: scanning, credential
// theft, secret scanning, lateral movement, tunnels, privilege escalation, exfiltration, disabling security tools.
| in(field="FileName", ignoreCase=true, values=[
    "nmap.exe", "nmap", "masscan.exe", "masscan", "rustscan.exe", "rustscan", "zmap", "naabu.exe", "naabu",
    "advanced_ip_scanner.exe", "advanced_port_scanner.exe", "netscan.exe", "ipscan.exe", "nbtscan*", "fscan*", "kerbrute*",
    "lazagne.exe", "lazagne", "hack-browser-data.exe", "hack-browser-data", "sharpchrome.exe", "sharpdpapi.exe",
    "sharpkatz.exe", "safetykatz.exe", "pypykatz.exe", "nanodump*",
    "trufflehog.exe", "trufflehog", "gitleaks.exe", "gitleaks", "noseyparker.exe", "noseyparker",
    "crackmapexec.exe", "cme.exe", "nxc.exe", "netexec.exe",
    "chisel", "gost", "frpc", "frps", "revsocks", "rathole", "iox", "ligolo*", "iodine", "iodine.exe", "dnscat", "dnscat2",
    "dnscat2.exe", "dns2tcpc",
    "printspoofer*", "juicypotato*", "godpotato*", "sweetpotato*", "roguepotato*", "efspotato*", "winpeas*", "linpeas*", "pspy*",
    "rclone.exe", "rclone",
    "edrsandblast*", "backstab*", "pchunter*"])
// A host and the tool it runs by design, never the whole host (one line per pair; placeholders).
| NOT (aid="<network_team_aid>" AND FileName=/^(nmap|advanced_ip_scanner)\.exe$/i)
| NOT (aid="<appsec_aid>" AND FileName=/^(trufflehog|gitleaks)$/i)
| NOT (aid="<file_server_aid>" AND FileName=/^rclone$/i)
// 6 OUTPUT
| select([@timestamp, aid, ComputerName, UserName, FileName, ImageFileName, CommandLine, ParentBaseFileName, TargetProcessId])
```

## Rule settings
| | |
|---|---|
| Interval / lookback | 5 minutes / 10 minutes. Non-aggregating, so the overlap is deduplicated by `_id`. |
| Suppression | `host.id`, `process.name` for 24h: a tool run many times on one host is one alert a day |

## Telemetry assumptions
- `processrollup2` events with `process.name` (the file name), `process.executable`, `process.command_line` and `data.TargetProcessId`. If your pipeline leaves `process.name` empty on process starts, gate on the raw `data.FileName` instead.

Confirm it over the last hour:
```esql
FROM logs-yourorg-crowdstrike-data-default*
| WHERE event.action == "processrollup2"
| STATS starts = COUNT(*), with_name = COUNT(process.name), with_raw_name = COUNT(data.FileName),
        with_pid = COUNT(data.TargetProcessId)
    BY data.event_platform
```
```logscale
#event_simpleName=ProcessRollup2
| groupBy([event_platform], function=[count(as=starts), count(FileName, as=with_name), count(TargetProcessId, as=with_pid)], limit=max)
```

## Before enabling: who already runs these
There's no threshold to baseline, but there is a population to know. Run the gate without the exclusions over the last 30 days to see which tools already run where. The ones your IT, network and security teams run become host + tool exclusions; anything else is worth asking about now.
```esql
FROM logs-yourorg-crowdstrike-data-default*
| WHERE event.action IN ("processrollup2", "syntheticprocessrollup2")
  AND (process.name IN ("nmap.exe", "nmap", "advanced_ip_scanner.exe", "advanced_port_scanner.exe", "netscan.exe", "ipscan.exe",
                        "trufflehog.exe", "trufflehog", "gitleaks.exe", "gitleaks", "rclone.exe", "rclone")
       OR process.name LIKE "nbtscan*" OR process.name LIKE "pspy*")
| STATS starts = COUNT(*), hosts = COUNT_DISTINCT(host.id), last_seen = MAX(@timestamp) BY process.name
| SORT hosts DESC
```
```logscale
#event_simpleName=/^(ProcessRollup2|SyntheticProcessRollup2)$/
| in(field="FileName", ignoreCase=true, values=["nmap.exe", "nmap", "advanced_ip_scanner.exe", "advanced_port_scanner.exe", "netscan.exe",
                                                "ipscan.exe", "trufflehog.exe", "trufflehog", "gitleaks.exe", "gitleaks", "rclone.exe",
                                                "rclone", "nbtscan*", "pspy*"])
| tool := lower(FileName)
| groupBy([tool], function=[count(as=starts), count(aid, distinct=true, as=hosts), max(@timestamp, as=last_seen)], limit=max)
```
These are the dual-use tools on the list, the ones IT staff run too; the rest have no business on a managed host. Run it with the full list if you want the complete picture.

## Suppression
Suppress by `host.id`, `process.name` for 24h. Alerts missing a key field are not suppressed. A different tool on the same host is a separate alert: a scanner followed by a credential stealer is the start of an intrusion, not noise.

## Known false positives / exclusions
- Network and IT staff running scanners (nmap, Advanced IP Scanner, Angry IP Scanner) from their own machines. Exclude the host and the tool. A scanner on a server, or run by an account that isn't IT, still alerts.
- AppSec and CI hosts running TruffleHog or gitleaks by design: the host and the scanner.
- rclone used for legitimate backup or migration on a file server: the host and rclone. rclone anywhere else is the most common ransomware exfiltration tool.
- Security testing (red team, penetration tests). Agree the hosts and dates in advance and close those alerts against them, rather than excluding the tools.

## Blind spots
- **Renamed or recompiled tools.** A name is the easiest thing to change; the behaviour rules listed above are the main line of detection.
- **Tools run by an interpreter.** Impacket, Certipy, NetExec installed with `pip`, evil-winrm, PowerView and `linpeas.sh` start as `python`, `ruby`, `powershell` or `bash`, so their own names never appear as the process name. Their command lines do; that's for rules that read command lines (W09 for AD tools).
- **Tools run in memory** (execute-assembly, beacon object files, reflective loading), which never start as a process of their own.
- In ES|QL, names in a case other than the one listed (`NMAP.EXE`). The LogScale version ignores case.

## Triage
- Read who ran it, from where and from what: `user.name`, `process.executable` (a `Downloads`, `Temp`, `/tmp` or `/dev/shm` path is a bad sign), `process.parent.name` (a shell under a web server or an Office application is worse) and `process.command_line` (the targets and options).
- Check the same host for the behaviour rule that matches the tool's family (B01 for a scanner, B04 for CrackMapExec, B08 for LaZagne, CS16 for chisel, CS17 for TruffleHog). Behaviour on the same process means it ran, not just started.
- Pivot on the process ID for everything it did, from its start to the alert:
```esql
FROM logs-yourorg-crowdstrike-data-default*
| WHERE host.id == "<host.id>"
  AND (data.TargetProcessId == "<data.TargetProcessId>" OR data.ContextProcessId == "<data.TargetProcessId>"
       OR data.ParentProcessId == "<data.TargetProcessId>")
| KEEP @timestamp, event.action, process.name, process.command_line, destination.ip, destination.port, data.DomainName,
       data.TargetFileName
| SORT @timestamp ASC
```
```logscale
#event_simpleName=/^(ProcessRollup2|SyntheticProcessRollup2|NetworkConnectIP4|DnsRequest|.*Written)$/ aid="<aid>"
| TargetProcessId="<TargetProcessId>" or ContextProcessId="<TargetProcessId>" or ParentProcessId="<TargetProcessId>"
| select([@timestamp, #event_simpleName, FileName, CommandLine, RemoteAddressIP4, RemotePort, DomainName, TargetFileName])
```
This returns its start, its connections, lookups and file writes, and the processes it started.

## Test
On a lab host, run `nmap --version` and `rclone version`: both alert. Copy one to a new name and run it again: no alert, by design (see Blind spots). Run one on an excluded host + tool pair: no alert; run a different tool on that host: an alert.
