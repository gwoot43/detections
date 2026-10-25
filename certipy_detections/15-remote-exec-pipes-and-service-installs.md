---
id: LATMOV-02
name: Remote-exec named pipe on IPC$ (5145) or a command-shell service install (4697) on the target
language: esql
index: logs-yourorg-microsoft-windows*
mitre: [T1021.002, T1569.002, T1047]
data_source: Windows Security 5145 and 4697 on the target
suppression:
  fields: [host.name]
  duration: 6h
  missing_fields: do_not_suppress
---
**Catches:** remote command execution landing on a host - `psexec`, `smbexec`, `atexec`, `wmiexec` and the NetExec/CrackMapExec equivalents - seen from the **target's** own Windows event log, not from the source. This covers `psexec` and `atexec`, which 14 (the `$\__` output artifact) doesn't see.

Two behaviours, both on the Security channel that detection 10 already collects. No counting, no baseline - each is a single precise match.

**A remote client opening a remote-exec named pipe on IPC$ (5145).** Driving a host remotely means talking to one of a few services over SMB:
- `svcctl` - the service-control manager (install/start a service): `psexec`, `smbexec`.
- `atsvc` - the task scheduler: `atexec`.
- `winreg` - the remote registry: many modules read config and secrets this way.
- `remcom_*` - PsExec's own command pipes (`RemCom_communicaton`, `RemCom_stdin/stdout/stderr`).

A remote client opening these is remote control of the host.
```esql
FROM logs-yourorg-microsoft-windows* METADATA _id, _index, _version
// 5145: a remote-exec pipe opened on IPC$ - service control, task scheduler, remote registry, or PsExec's own pipes
| WHERE event.code == "5145"
| EVAL share = TO_LOWER(winevt.event_data.share_name), pipe = TO_LOWER(winevt.event_data.relative_target_name)
| WHERE share LIKE "\\\\*\\ipc$" AND (pipe IN ("svcctl", "atsvc", "winreg") OR pipe LIKE "remcom_*")
| KEEP @timestamp, host.name, pipe, winevt.event_data.subject_user_name, winevt.event_data.ip_address, _id, _index, _version
```
Needs "Audit Detailed File Share" (5145) on the targets, as detection 10 does. `svcctl` is the noisiest (some remote management uses it); `atsvc` and `remcom_*` are the high-fidelity ones - baseline `svcctl` first.

**A service installed to run a command (4697).** `psexec` and `smbexec` install a short-lived service whose image is a `cmd`/`%COMSPEC%` one-liner, a PowerShell command, or a binary dropped in a temp path, then delete it. That image shape is the behaviour, whatever the service is named.
```esql
FROM logs-yourorg-microsoft-windows* METADATA _id, _index, _version
// 4697: a service whose image is a command interpreter, an inline redirect, or a temp-path binary
| WHERE event.code == "4697"
| EVAL img = TO_LOWER(winevt.event_data.service_file_name)
| WHERE img LIKE "*cmd.exe *" OR img LIKE "*cmd /c*" OR img LIKE "*%comspec%*"
     OR img LIKE "*powershell*" OR img LIKE "*pwsh*"
     OR img LIKE "*\\windows\\temp\\*" OR img LIKE "*\\perflogs\\*"
     OR img LIKE "*2>&1*" OR img LIKE "*^>*"
| KEEP @timestamp, host.name, winevt.event_data.service_name, winevt.event_data.service_file_name,
       winevt.event_data.subject_user_name, _id, _index, _version
```
If you collect the System channel, event **7045** is the same service install with `ServiceFileName` - match it the same way. 4697 (Security) is listed here because it's the channel you already have for detection 10.

No LogScale version: these target logs are in Elastic. Run both every 5 minutes over the last 10. Suppress by host for 6h.

## What it catches and what it doesn't
- **Caught:** psexec (svcctl + remcom_ pipes, service install), smbexec (svcctl pipe, service install), atexec (atsvc pipe), and registry-reading modules (winreg pipe).
- **Not caught here:** wmiexec and dcomexec, which run through WMI/DCOM, not a pipe or a service - 14 catches those by their `$\__` output file.
- **Not caught here:** a module that uses an existing service or an unusual pipe name. The pipe list is the common set; widen it from what your estate shows.

## Before turning it on
- Field names (`relative_target_name`, `share_name`, `service_file_name`, `ip_address`, `subject_user_name`) are guesses at your pipeline's snake_case; confirm against a 5145 and a 4697 in Discover.
- Baseline `svcctl` (5145) and the 4697 service-image match over a week - legitimate remote management and software installs use both. Exclude the management hosts and service accounts that do this by design, as host + account pairs.

## When it fires
`ip_address` (5145) or the service's installer (4697) is the source. Pivot to the source host and check 16 (did it reach many hosts?) and 14 (did a `$\__` cmd.exe run here?). A service install plus a remote-exec pipe from the same source within seconds is hands-on remote execution - treat the account and the source as compromised.
