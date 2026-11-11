---
id: W17
name: Startup folder entry written or executed - user-scope persistence with no registry key
category: endpoint-windows
status: todo
language: esql
index: logs-yourorg-crowdstrike-data-default*
mitre: [T1547.001, T1037.001, T1204.002]
data_source: CrowdStrike FDR ProcessRollup2
suppression:
  fields: [host.id, user.name]
  duration: 24h
  missing_fields: do_not_suppress
---

## Why this is high fidelity

A `.lnk`, `.url`, `.exe` or script dropped in
`%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` runs at every logon - no registry key, no scheduled task,
and no administrator rights needed. A rule set built on `Run` keys (`CS02`) and task creation (`CS07`) sees nothing,
which is exactly why it is still used.

Two stages, and either one is worth an alert: the **write** into the folder, and the **execution** from it at the
next logon. The write is the earlier signal; the execution is the one that proves it works.

## Query

Run every 15 minutes with a 1-hour lookback.

```esql
FROM logs-yourorg-crowdstrike-data-default*
| WHERE @timestamp >= NOW() - 1 hour
  AND event.action IN ("processrollup2", "syntheticprocessrollup2")
| EVAL cmd = TO_LOWER(COALESCE(process.command_line, "")),
       path = TO_LOWER(COALESCE(process.executable, "")),
       proc = TO_LOWER(COALESCE(process.name, ""))
// the write: any command line naming a Startup folder (the path has spaces, so the test is on the whole string),
// or the payload running from one at the next logon
| WHERE cmd LIKE "*start menu*programs*startup*"
     OR path LIKE "*start menu*programs*startup*"
| STATS events = COUNT(*), first_seen = MIN(@timestamp),
        commands = MV_SLICE(VALUES(process.command_line), 0, 3),
        parents = MV_SLICE(VALUES(process.parent.name), 0, 3),
        users = MV_SLICE(VALUES(user.name), 0, 3)
    BY host.id, host.name, proc
// Baseline: installers write here - a short list of vendor names (Zoom, Teams, OneDrive) - and the folder is
// otherwise static. A writer that is a shell or a downloader, on a host that has never had one, is the case; the
// parent process is the field that tells them apart.
| WHERE events >= 1
| SORT first_seen DESC
| LIMIT 50
```

## Reading the alert

- **`parents`** is the whole triage. `explorer.exe` is a user dragging a shortcut in; `cmd.exe`, `powershell.exe`,
  `mshta.exe` or `wscript.exe` writing into Startup is hands-on-keyboard persistence.
- **A `.lnk` written by PowerShell** (`WScript.Shell` `CreateShortcut`) is the classic shape: no executable ever
  lands, only a shortcut that points at a remote or living-off-the-land payload.
- **The same host writing again after a reboot** - the entry was re-dropped, which means someone noticed it was
  removed.

## Nearest benign twins

- **Installers.** Zoom, Teams and OneDrive have all written startup shortcuts; they are the same handful of signed
  binaries and the same parent.
- **Logon scripts** that place a shortcut for the user - the parent is the script host and it happens fleet-wide at
  the same time.
- **A user pinning something themselves** - `explorer.exe` as the parent, and one host.

## What it misses

- **A write through a library** with no command line (a loader that creates the `.lnk` from memory). Only a file-write
  event would catch it - if Falcon's file events are enabled on Windows, this rule should switch to them.
- **The All Users Startup folder** when written by an installer running as SYSTEM - same path shape, so it is
  covered, but the parent is a service and will look benign.
- **A `.lnk` in a Startup folder that is never executed** because the user never logs on again - the write fires, the
  execution does not.

## Test

```esql
FROM logs-yourorg-crowdstrike-data-default*
| WHERE @timestamp >= NOW() - 30 days
  AND event.action == "processrollup2"
  AND process.command_line IS NOT NULL
| EVAL cmd = TO_LOWER(process.command_line)
| WHERE cmd LIKE "*start menu*programs*startup*"
| STATS events = COUNT(*) BY host.name, process.name, process.parent.name
| SORT events DESC
| LIMIT 30
```

The parents in this list are your allowlist. Anything in it that is a shell or a script host is worth reading before
the rule is enabled.
