---
id: TOOLS-01
name: Common red/purple-team tool started, by file name (fallback to the behaviour rules)
language: esql
index: logs-yourorg-crowdstrike-data-default*
mitre: [T1046, T1003, T1021, T1087.002, T1558.003, T1550, T1069.002]
data_source: CrowdStrike FDR ProcessRollup2
suppression:
  fields: [host.id, process.name]
  duration: 24h
  missing_fields: do_not_suppress
---
**Catches:** a well-known offensive tool by the name it ships with, on a process start. This is a **fallback** - the name is the whole evidence, so a renamed copy slips past it. The behaviour rules catch those: 14/15 (Impacket exec), 16/B04 (lateral sweep), 17 (SMB from a user process), 18 (smbclient), 20 (pivot relay), 08/10 (BloodHound/share sweep), 01-05 (the Certipy chain), CS16/CS17.

It matches `FileName` (the process basename) on a process start, not the command line - one event per start, no command-line noise. The same names can be matched on `ContextBaseFileName` if you want the tool seen on a network event when the sensor missed the start (see below).

Covers the tools you named and their families, matched as the binary they run as:

| Family | Names matched |
|---|---|
| AD CS | certipy, certipy.exe |
| Directory / BloodHound | adexplorer.exe, adexplorer64.exe, sharphound.exe, azurehound.exe, adfind.exe, snaffler.exe |
| SMB | smbclient, smbclient.exe, smbmap, smbmap.exe |
| Lateral / spray | crackmapexec.exe, cme.exe, nxc.exe, netexec.exe, kerbrute, evil-winrm.exe |
| Scanning | nmap, nmap.exe, masscan, rustscan, enum4linux, nbtscan |
| Credential / Kerberos | mimikatz.exe, rubeus.exe, certify.exe, seatbelt.exe, lazagne.exe, pypykatz |

It overlaps the library's CS18 (compiled-tool names) and W09 (.NET AD tools) by design - this is the one place to keep the name list for this folder's estate. The net-new names over those are the ones you asked for: certipy, ADExplorer, smbclient, smbmap.

Run every 5 minutes over the last 10. Non-aggregating: one alert per process start, deduplicated on `_id`.
```esql
FROM logs-yourorg-crowdstrike-data-default* METADATA _id, _index, _version
// a process starting under the name an offensive tool ships with. Exact names plus prefixes for versioned builds;
// IN and LIKE are case-sensitive, so names are listed in the case each tool ships in.
| WHERE event.action IN ("processrollup2", "syntheticprocessrollup2")
  AND (process.name IN (
         "certipy", "certipy.exe", "Certipy.exe",
         "adexplorer.exe", "ADExplorer.exe", "adexplorer64.exe", "ADExplorer64.exe", "adfind.exe", "AdFind.exe",
         "smbclient", "smbclient.exe", "smbmap", "smbmap.exe",
         "cme.exe", "nxc.exe", "netexec.exe", "evil-winrm.exe",
         "nmap", "nmap.exe", "masscan", "masscan.exe", "rustscan", "enum4linux", "nbtscan",
         "mimikatz.exe", "lazagne.exe", "LaZagne.exe", "pypykatz", "pypykatz.exe")
       OR process.name LIKE "crackmapexec*" OR process.name LIKE "kerbrute*"
       OR process.name LIKE "sharphound*" OR process.name LIKE "SharpHound*"
       OR process.name LIKE "azurehound*" OR process.name LIKE "AzureHound*"
       OR process.name LIKE "snaffler*" OR process.name LIKE "Snaffler*"
       OR process.name LIKE "rubeus*" OR process.name LIKE "Rubeus*"
       OR process.name LIKE "certify*" OR process.name LIKE "Certify*"
       OR process.name LIKE "seatbelt*" OR process.name LIKE "Seatbelt*")
  // a host and the tool it runs by design, never the whole host (placeholders)
  AND NOT ((host.id == "<network_team_aid>" AND process.name IN ("nmap", "nmap.exe", "masscan", "rustscan"))
           OR host.id == "<pentest_jumpbox_aid>")
| KEEP @timestamp, host.id, host.name, user.name, process.name, process.executable, process.command_line,
       process.parent.name, data.TargetProcessId, _id, _index, _version
```

**CrowdStrike (Falcon LogScale)**, run every 5 minutes over the last 10 (names matched any case, wildcards for versioned builds):
```logscale
#event_simpleName=/^(ProcessRollup2|SyntheticProcessRollup2)$/
| in(field="FileName", ignoreCase=true, values=[
    "certipy", "certipy.exe",
    "adexplorer.exe", "adexplorer64.exe", "adfind.exe", "sharphound*", "azurehound*", "snaffler*",
    "smbclient", "smbclient.exe", "smbmap", "smbmap.exe",
    "crackmapexec*", "cme.exe", "nxc.exe", "netexec.exe", "kerbrute*", "evil-winrm.exe",
    "nmap", "nmap.exe", "masscan", "masscan.exe", "rustscan", "enum4linux", "nbtscan",
    "mimikatz.exe", "rubeus*", "certify*", "seatbelt*", "lazagne.exe", "pypykatz", "pypykatz.exe"])
// a host and the tool it runs by design, never the whole host (placeholders)
| NOT (aid="<network_team_aid>" AND FileName=/^(nmap(\.exe)?|masscan|rustscan)$/i)
| NOT (aid="<pentest_jumpbox_aid>")
| select([@timestamp, aid, ComputerName, UserName, FileName, ImageFileName, ParentBaseFileName, CommandLine, TargetProcessId])
```
Suppress by host and process name for 24h: a tool run many times on one host is one alert a day; a different tool is a new alert.

## What it catches and what it doesn't
- **Caught:** any of these run as their own binary - a frozen `certipy.exe`, `ADExplorer.exe`, Samba `smbclient`, `nxc.exe`, `nmap`.
- **Not caught here - runs under an interpreter, so the name is the interpreter, not the tool:** `python psexec.py`/`wmiexec.py` (FileName `python`), `certipy` installed with pip on Linux (FileName `python3`), `ruby evil-winrm` (FileName `ruby`), PowerView/`Invoke-Kerberoast` (FileName `powershell`). The behaviour rules above cover these - 14/15 for Impacket, 08 for BloodHound, 01-05 for the Certipy chain. If you want the tool *name* on those too, it only lives in the command line (the previous command-line version of this rule), which you've chosen not to run for noise.
- **Not caught here:** a renamed or recompiled binary, or in-memory execution (execute-assembly, BOFs). Behaviour rules only.

## ContextBaseFileName option
`FileName` is on the process start (`ProcessRollup2`) - one event per run, the quietest signal. If a sensor sometimes misses the start but you still see the tool making connections, match the same names on `ContextBaseFileName` on `NetworkConnectIP4/IP6` instead - but that fires once per connection, so suppress hard by host and name:
```logscale
#event_simpleName=/^NetworkConnectIP[46]$/
| in(field="ContextBaseFileName", ignoreCase=true, values=["certipy", "certipy.exe", "smbclient", "smbclient.exe", "nxc.exe", "netexec.exe", "crackmapexec*", "nmap", "nmap.exe"])
| groupBy([aid, ContextBaseFileName], function=[collect([ComputerName, RemoteAddressIP4, RemotePort], limit=20), min(@timestamp, as=first_seen), max(@timestamp, as=last_seen)], limit=max)
| select([aid, ComputerName, ContextBaseFileName, RemoteAddressIP4, RemotePort, first_seen, last_seen])
```

## Before turning it on
Run the gate without the exclusions over 30 days to see which of these your own IT/network/AppSec teams already run, and build the host + tool exclusions from it (`smbclient` and the scanners are the dual-use, noisy ones). Agree red-team / pentest windows and hosts in advance and close those alerts against them.

## When it fires
`process.name` is the tool, `process.executable` where it ran from (a `Downloads`, `Temp`, `/tmp`, `/dev/shm` path is a bad sign), `process.parent.name` what launched it, the command line its targets and options. Check the matching behaviour rule on the same host - behaviour on the same process means it ran, not just started - and pivot on `data.TargetProcessId` for everything it did afterwards.
