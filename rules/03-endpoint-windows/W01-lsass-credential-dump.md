---
id: W01
name: LSASS memory dump via known tooling or LOLBIN
category: endpoint-windows
status: todo
severity: critical
language: esql
index: logs-crowdstrike.fdr-*
mitre: [T1003.001]
data_source: CrowdStrike FDR ProcessRollup2
---
## Why this is high fidelity
Falcon blocks most LSASS reads, but the attempt still shows up as a process launch. `comsvcs.dll MiniDump`, `procdump -ma lsass` and `rundll32` naming the LSASS process have no admin use case outside a debugging session you would know about.

## Query
```esql
FROM logs-crowdstrike.fdr-* METADATA _id, _index, _version
| WHERE event.action == "ProcessRollup2" AND host.os.type == "windows"
| EVAL cmd = TO_LOWER(process.command_line), pname = TO_LOWER(process.name)
| WHERE (cmd LIKE "*comsvcs*" AND cmd LIKE "*minidump*")
   OR (cmd LIKE "*lsass*" AND (pname IN ("procdump.exe", "procdump64.exe", "rundll32.exe", "createdump.exe", "sqldumper.exe", "adplus.exe", "rdrleakdiag.exe")
                               OR cmd LIKE "* -ma *" OR cmd LIKE "*.dmp*"))
   OR cmd LIKE "*sekurlsa*" OR cmd LIKE "*lsadump*"
| KEEP @timestamp, host.name, user.name, process.parent.name, process.name, process.command_line, process.hash.sha256
```

## Known false positives / exclusions
- Microsoft support engineers running `procdump` on LSASS during a case. Ticket-gated, not excluded.
- `createdump.exe` from the .NET runtime on crashing services. Exclude when parent is `dotnet.exe` and the command line does not name lsass.

## Triage
- Isolate the host in Falcon. Assume every credential logged on to that host is compromised; check 4624 for who that is (I06).

## Test
Use Atomic Red Team T1003.001 on a lab host. Falcon will block it; the rule should still fire on the process launch.
