---
id: AD13
name: RDP session hijacked with tscon
category: ad-attack
status: todo
severity: medium
rank: 13
language: esql
index: logs-crowdstrike.fdr-*
mitre: [T1563.002]
data_source: CrowdStrike FDR ProcessRollup2
suppression:
  fields: [host.name]
  duration: 1h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
`tscon.exe` connects a terminal session to another session. Run as SYSTEM, it can attach to any other logged-on user's session, including a disconnected administrator's, without their password, which takes over everything that session is logged into. Administrators almost never run `tscon`, and almost never as SYSTEM.

## Query
```esql
FROM logs-crowdstrike.fdr-* METADATA _id, _index, _version
| WHERE event.action == "ProcessRollup2" AND host.os.type == "windows"
| EVAL pname = TO_LOWER(COALESCE(process.name, "")),
       sid = TO_STRING(user.id)
| WHERE pname == "tscon.exe" AND sid == "S-1-5-18"
| KEEP @timestamp, host.name, user.name, sid, process.command_line, process.parent.name, process.parent.command_line, _id, _version, _index
```

**CrowdStrike (Falcon LogScale / Advanced Event Search)**
```logscale
#event_simpleName=/^(ProcessRollup2|SyntheticProcessRollup2)$/ event_platform=Win FileName=/^tscon\.exe$/i UserSid="S-1-5-18"
| table([@timestamp, aid, ComputerName, UserName, UserSid, CommandLine, ParentBaseFileName])
```
`S-1-5-18` is the SYSTEM account. A `tscon` started by `services.exe` or `cmd.exe` running as SYSTEM is the typical hijack shape. `tscon` run as an ordinary user (for example `tscon 1 /dest:console`, which test-automation hosts use to keep a desktop alive) needs that user's own session or password, so it is left out.

## Suppression
Suppress by `host.name` for 1h. Alerts missing a key field are not suppressed. A different host still alerts.

## Known false positives / exclusions
- Rare remote-support tooling that reconnects sessions. Exclude by exact parent and command line if it appears.

## Triage
- Identify whose session was taken over (the session number in the command line maps to a logged-on user) and log that session off. Check how SYSTEM was obtained on the host, typically a service created just before (WE08).

## Test
On a lab host, run `tscon` as SYSTEM to attach to another session.
