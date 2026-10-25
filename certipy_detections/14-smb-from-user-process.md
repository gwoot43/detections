---
id: LATMOV-01
name: Impacket exec output artifact - cmd.exe redirecting output to a __ admin-share file
language: cql
index: logs-yourorg-crowdstrike-data-default*
mitre: [T1021.002, T1569.002]
data_source: CrowdStrike FDR ProcessRollup2 (on the target)
suppression:
  fields: [host.id]
  duration: 6h
  missing_fields: do_not_suppress
---
**Catches:** Impacket's `wmiexec`, `dcomexec` and `smbexec` running a command on a remote host. Not by name - by the one thing all three do the same way.

When these modules run a command on a target, they can't read the output back over the same channel, so they redirect it to a file on an admin share and then read that file. The file name always starts with `__`, on `ADMIN$` or `C$`. So the `cmd.exe` they spawn on the target carries a command line like:

- `cmd.exe /Q /c <command> 1> \\127.0.0.1\ADMIN$\__1729812345.12 2>&1` (wmiexec, dcomexec)
- `... ^> \\<host>\C$\__output_AbCdEfGh 2^>^&1` (smbexec, written into a batch file first)

The sequence `$\__` in a command line is that behaviour. It is how the tool reads its output, not what the tool is called, so a renamed or recompiled Impacket catches the same. The `cmd.exe` runs on the **target**, so this fires on the victim's own Falcon sensor.

This is a single precise match - no counting, no baseline. It's strong enough to alert on its own.

Run every 5 minutes over the last 10.
```logscale
//cmd.exe writing its output to a __-prefixed file on an admin share: the Impacket wmiexec/dcomexec/smbexec signature
#event_simpleName=ProcessRollup2 event_platform=Win CommandLine=/(?<Match>\$\\__\S*)/F
| select([@timestamp, ComputerName, ParentBaseFileName, UserName, Match, CommandLine])
```
```esql
FROM logs-yourorg-crowdstrike-data-default* METADATA _id, _index, _version
// cmd.exe writing its output to a __-prefixed admin-share file (wmiexec, dcomexec, smbexec).
// Leading-wildcard LIKE on purpose: $\__ is a substring inside the command line, not the whole value.
| WHERE event.action == "processrollup2" AND process.command_line LIKE "*$\\__*"
| KEEP @timestamp, host.name, host.id, data.ParentBaseFileName, user.name, process.command_line, _id, _index, _version
```
Suppress by host for 6h.

## What it catches and what it doesn't
- **Caught:** wmiexec, dcomexec, smbexec - all leave the `$\__` output redirect on the target.
- **Not caught here:** `psexec` (runs a service binary with named pipes, no output file) and `atexec` (writes to `\Windows\Temp\<random>.tmp`, not an admin share). Both land as remote-exec signals in the **target-side Windows logs** - see 15. Run 14 and 15 together and the exec family is covered from two angles.
- **Not caught here:** a module told to write its output somewhere other than a `__` admin-share file (uncommon; it's the default and most operators leave it).

## Before turning it on
Confirm the `$\__` artifact in a lab: run one Impacket exec module against a test host and read the child `cmd.exe` command line in Falcon - it carries `\\<ip>\ADMIN$\__<digits>` or `\\<host>\C$\__output_<letters>`.

## When it fires
`CommandLine` shows the command that ran (between `/c` and the `1>`/`^>`). `ParentBaseFileName` on the target shows how it got there: `WmiPrvSE.exe` is wmiexec, `mmc.exe`/`svchost.exe` hosting DCOM is dcomexec, a short-lived service (`services.exe` parent) is smbexec. This is remote code execution on the host from somewhere else - treat the account and the source as compromised, and check 15 (service installs, remote-exec pipes) and 16 (where the source reached next) around the same time.
