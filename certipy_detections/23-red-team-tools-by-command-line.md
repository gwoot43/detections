---
id: TOOLS-01
name: Common red/purple-team tool on the command line (interpreter-run and named tools - fallback to the behaviour rules)
language: cql
index: logs-yourorg-crowdstrike-data-default*
mitre: [T1059, T1046, T1003, T1021, T1087.002, T1558.003, T1550, T1572, T1069.002]
data_source: CrowdStrike FDR ProcessRollup2
suppression:
  fields: [host.id, Match]
  duration: 24h
  missing_fields: do_not_suppress
---
**Catches:** a well-known offensive tool by the name it's invoked with on the command line. This is a **fallback**, not the main line - the name is the whole evidence, so a renamed copy slips past it. The behaviour rules catch those: 14/15 (Impacket exec), 16/B04 (lateral sweep), 17 (SMB from a user process), 18 (smbclient), 20 (pivot relay), 08/10 (BloodHound/share sweep), CS16/CS17 (pivoting, key testing).

It fills the gap the library's **CS18** (process *name*) leaves: tools run under an interpreter - Certipy, Impacket, NetExec, PowerView, bloodhound-python - start as `python`, `ruby`, `powershell` or `bash`, so their own name is never the process name. Their *command line* carries it. This rule reads the command line (which also carries the full image path, so named binaries like `nmap` and `ADExplorer.exe` match here too). W09 matches the .NET AD tools; CS18 the compiled binaries by name.

The matched token is pulled into `Match`, so the alert names the tool. Families, as they're invoked:

| Family | Tokens matched |
|---|---|
| AD CS | `certipy` |
| Impacket | `psexec.py`, `wmiexec.py`, `smbexec.py`, `atexec.py`, `dcomexec.py`, `secretsdump.py`, `getuserspns.py`, `getnpusers.py`, `ntlmrelayx.py`, `smbclient.py`, `smbmap`, `mssqlclient.py`, `samrdump.py`, `lookupsid.py` |
| Lateral / spray | `netexec`, `nxc`, `crackmapexec`, `evil-winrm`, `kerbrute` |
| Directory / BloodHound | `bloodhound-python`, `bloodhound.py`, `sharphound`, `invoke-bloodhound`, `adexplorer`/`adexplorer64`, `adfind`, `snaffler`, `manspider` |
| Credential / Kerberos | `rubeus`, `certify`, `seatbelt`, `whisker`, `mimikatz`, `sekurlsa`, `lsadump`, `invoke-kerberoast`, `invoke-dcsync` |
| Recon cmdlets | `get-domainuser`, `get-netcomputer`, `find-domainshare`, `invoke-sharefinder` |
| Relay / MITM | `responder`, `mitm6` |
| PrivEsc / scan | `linpeas`, `winpeas`, `pspy`, `nmap`, `masscan`, `rustscan`, `smbclient` |

Run every 5 minutes over the last 10. Non-aggregating: one alert per process start, deduplicated on `_id`.
```logscale
#event_simpleName=/^(ProcessRollup2|SyntheticProcessRollup2)$/
// the tool name as invoked, at a token boundary (start, space, slash, quote or =), so it doesn't match inside another word
| CommandLine=/(^|[\s\\\/"'=])(?<Match>certipy|(?:psexec|wmiexec|smbexec|atexec|dcomexec|secretsdump|getuserspns|getnpusers|ntlmrelayx|mssqlclient|samrdump|lookupsid|getadusers|smbclient|smbmap)\.py|netexec|crackmapexec|nxc|evil-winrm|bloodhound-python|bloodhound\.py|sharphound|invoke-bloodhound|adexplorer(?:64)?|adfind|snaffler|manspider|kerbrute|rubeus|certify|seatbelt|whisker|mimikatz|sekurlsa|lsadump|invoke-kerberoast|invoke-dcsync|get-domainuser|get-netcomputer|find-domainshare|invoke-sharefinder|responder|mitm6|linpeas|winpeas|pspy|smbclient|nmap|masscan|rustscan)\b/iF
// a host and the tool it runs by design, never the whole host (placeholders)
| NOT (aid="<network_team_aid>" AND Match=/^(nmap|masscan|rustscan)$/i)
| NOT (aid="<pentest_jumpbox_aid>")
| select([@timestamp, aid, ComputerName, UserName, ImageFileName, ParentBaseFileName, Match, CommandLine])
```
```esql
FROM logs-yourorg-crowdstrike-data-default* METADATA _id, _index, _version
| WHERE event.action IN ("processrollup2", "syntheticprocessrollup2")
// the tool name as invoked (RLIKE can't do case-insensitive whole-value with capture, so GROK runs the regex)
| GROK process.command_line """(?i)(^|[\s\\/"'=])(?<matched>certipy|(psexec|wmiexec|smbexec|atexec|dcomexec|secretsdump|getuserspns|getnpusers|ntlmrelayx|mssqlclient|samrdump|lookupsid|getadusers|smbclient|smbmap)\.py|netexec|crackmapexec|nxc|evil-winrm|bloodhound-python|bloodhound\.py|sharphound|invoke-bloodhound|adexplorer(64)?|adfind|snaffler|manspider|kerbrute|rubeus|certify|seatbelt|whisker|mimikatz|sekurlsa|lsadump|invoke-kerberoast|invoke-dcsync|get-domainuser|get-netcomputer|find-domainshare|invoke-sharefinder|responder|mitm6|linpeas|winpeas|pspy|smbclient|nmap|masscan|rustscan)\b)"""
| WHERE matched IS NOT NULL
| EVAL matched = TO_LOWER(matched)
// a host and the tool it runs by design, never the whole host (placeholders)
| WHERE NOT ((host.id == "<network_team_aid>" AND matched IN ("nmap", "masscan", "rustscan"))
            OR host.id == "<pentest_jumpbox_aid>")
| KEEP @timestamp, host.id, host.name, user.name, process.name, process.executable, process.command_line,
       process.parent.name, data.TargetProcessId, matched, _id, _index, _version
```
Suppress by host and matched tool for 24h: a tool run many times on one host is one alert a day, but a different tool is a new alert (a scanner then a credential tool is the start of an intrusion).

## What it catches and what it doesn't
- **Caught:** the tools above however they start - under an interpreter (the command line carries `certipy`, `*.py`, `netexec`), as a named binary (the image path carries `nmap`, `ADExplorer.exe`), or as a PowerShell function (`Invoke-Kerberoast`).
- **Not caught here:** a renamed or recompiled tool - the name is gone. That's what the behaviour rules are for (listed above); this is the fallback for when the behaviour isn't visible.
- **Not caught here:** in-memory execution (execute-assembly, beacon object files, reflective loading) - no command line of its own.
- **Dual-use overlap:** `smbclient`, `nmap`, `reg`, `net` are also run by admins; `smbclient` and the scanners are the noisy ones - exclude the hosts that run them by design, don't drop the token.

## Before turning it on
Run the gate without the exclusions over 30 days to see which tools already run where, and from that build the host + tool exclusions (IT scanners, the pentest jump box, backup smbclient):
```logscale
#event_simpleName=/^(ProcessRollup2|SyntheticProcessRollup2)$/
| CommandLine=/(^|[\s\\\/"'=])(?<Match>certipy|netexec|nxc|crackmapexec|smbclient|nmap|masscan|adexplorer(?:64)?|bloodhound-python|kerbrute|evil-winrm)\b/iF
| tool := lower(Match)
| groupBy([tool], function=[count(as=starts), count(aid, distinct=true, as=hosts), max(@timestamp, as=last_seen)], limit=max)
| sort(field=hosts, order=desc, limit=200)
```
Agree red-team / pentest windows and hosts in advance and close those alerts against them rather than excluding the tools.

## When it fires
`Match` is the tool, `process.executable` where it ran from (a `Downloads`, `Temp`, `/tmp` or `/dev/shm` path is a bad sign), `process.parent.name` what launched it (a shell under a web server or Office is worse), and the command line its targets and options. Check the matching behaviour rule on the same host - behaviour on the same process means it ran, not just started - and pivot on `data.TargetProcessId` for everything it did afterwards (the pivot query in CS18).
