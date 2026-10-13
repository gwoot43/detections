---
id: W08
name: Shell started by a remote execution service (WMI, WinRM, DCOM, PsExec, service) with a command few hosts see
category: endpoint-windows
status: todo
severity: high
language: esql
index: logs-crowdstrike.fdr-*
mitre: [T1021.002, T1047, T1021.006, T1021.003, T1569.002]
data_source: CrowdStrike FDR ProcessRollup2
suppression:
  fields: [host.id, parent]
  duration: 1h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
Every remote execution method lands on the target the same way: a remote execution service starts a shell. The parent names the method:
- `wmiprvse.exe` is WMI (`wmiexec`, `wmic /node`).
- `wsmprovhost.exe` and `winrshost.exe` are WinRM.
- `mmc.exe` is DCOM (MMC20.Application).
- `services.exe` is a new service whose binary is a shell (`smbexec`, PsExec-style tools).
- `psexesvc.exe` is Sysinternals PsExec.

Management tools do this too, but they run the same commands on many hosts. An attacker's commands are new. So the rule counts how many hosts ran the same command from the same parent in the last day, and alerts only when it is 3 or fewer. That replaces the per-tool exclusions: monitoring and configuration management drop out on their own.

A sweep of remote execution across many hosts is B04 and B05.

## Query
Run hourly with a 24-hour lookback.
```esql
FROM logs-crowdstrike.fdr-*
| WHERE event.action == "ProcessRollup2" AND host.os.type == "windows"
| EVAL parent = TO_LOWER(process.parent.name), child = TO_LOWER(process.name)
| WHERE parent IN ("wmiprvse.exe", "wsmprovhost.exe", "winrshost.exe", "mmc.exe", "services.exe", "psexesvc.exe")
  AND child IN ("cmd.exe", "powershell.exe", "pwsh.exe")
| STATS runs = COUNT(*),
        first_seen = MIN(@timestamp),
        last_seen = MAX(@timestamp),
        host.name = VALUES(host.name),
        users = VALUES(user.name)
    BY host.id, parent, child, process.command_line
| INLINE STATS hosts = COUNT_DISTINCT(host.id) BY parent, process.command_line
| WHERE hosts <= 3
| KEEP host.id, host.name, parent, child, process.command_line, hosts, runs, first_seen, last_seen, users
```

**Not covered:** the source side (`wmic /node`, `schtasks /s`, `sc \\host`) on the machine that launches the move. The destination side above sees the same move wherever Falcon runs.

## Suppression
Suppress by `host.id`, `parent` for 1h. Alerts missing a key field are not suppressed. Tools like `wmiexec` run each command with a unique output file name, so one session produces many rare commands; they fold into one alert per host and method, and the suppressed count shows how many.

## Known false positives / exclusions
- An admin running a one-off command over WinRM or WMI. Expected occasionally; check the user against the admin team.
- Management tools that put a unique ID in every command line. They never repeat, so they never look common. Exclude that tool's command pattern once, by exact prefix.

## Triage
- Find the source: the 4624 logon type 3 on this host just before, or the source host's fan-out in B04. Check the source host for W01 and the account for I05.

## Test
Run Sysinternals PsExec and Impacket `wmiexec.py` against a lab host from a lab admin host.
