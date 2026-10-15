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
suppression:
  fields: [host.id, process.name]
  duration: 1h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
Falcon blocks most LSASS reads, but the attempt still shows up as a process launch. `comsvcs.dll MiniDump` (by name or ordinal `#24`), `procdump -ma lsass` and `rundll32` naming the LSASS process have no admin use case outside a debugging session you would know about.

Dump tools that take a PID instead of a name (`sqldumper`, `createdump`, `rdrleakdiag`) only match when the command line names LSASS. Falcon's own LSASS-access detections arrive through CS04.

## Query
```esql
FROM logs-crowdstrike.fdr-* METADATA _id, _index, _version
| WHERE event.action == "ProcessRollup2" AND host.os.type == "windows"
| EVAL cmd = TO_LOWER(process.command_line), pname = TO_LOWER(process.name)
// comsvcs.dll MiniDump, by name or by its ordinal (#24)
| WHERE (cmd LIKE "*comsvcs*" AND (cmd LIKE "*minidump*" OR cmd LIKE "*#24*"))
   OR (cmd LIKE "*lsass*" AND (pname IN ("procdump.exe", "procdump64.exe", "rundll32.exe", "createdump.exe", "sqldumper.exe", "adplus.exe", "rdrleakdiag.exe")
                               OR cmd LIKE "* -ma *" OR cmd LIKE "*.dmp*"))
   OR cmd LIKE "*sekurlsa*" OR cmd LIKE "*lsadump*"
| KEEP @timestamp, host.id, host.name, user.name, process.parent.name, process.name, process.command_line, process.hash.sha256, _id, _version, _index
```

**CrowdStrike (Falcon LogScale / Advanced Event Search)**
```logscale
#event_simpleName=/^(ProcessRollup2|SyntheticProcessRollup2)$/ event_platform=Win
| case {
    // comsvcs.dll MiniDump, by name or by its ordinal (#24)
    CommandLine=/comsvcs/i CommandLine=/minidump|#24/i;
    CommandLine=/lsass/i
      | in(field="FileName", ignoreCase=true, values=["procdump.exe", "procdump64.exe", "rundll32.exe", "createdump.exe", "sqldumper.exe",
                                                     "adplus.exe", "rdrleakdiag.exe"]);
    CommandLine=/lsass/i CommandLine=/ -ma |\.dmp/i;
    CommandLine=/sekurlsa|lsadump/i;
  }
| table([@timestamp, aid, ComputerName, UserName, ParentBaseFileName, FileName, CommandLine, SHA256HashData])
```

## Suppression
Suppress by `host.id`, `process.name` for 1h. Alerts missing a key field are not suppressed. Attackers retry dumping after Falcon blocks them. Each different tool still alerts. `host.id` is the Falcon agent ID and is always present; `host.name` is filled only when the integration's host metadata enrichment is on.

## Known false positives / exclusions
- Microsoft support engineers running `procdump` on LSASS during a case. Ticket-gated, not excluded.
- `createdump.exe` from the .NET runtime on crashing services. It only matches when the command line names LSASS, so it needs no exclusion.

## Triage
- Isolate the host in Falcon. Assume every credential logged on to that host is compromised; check 4624 for who that is (I06).

## Test
Run the Atomic Red Team T1003.001 test on a lab host. Falcon will block it; the rule should still fire on the process launch.
