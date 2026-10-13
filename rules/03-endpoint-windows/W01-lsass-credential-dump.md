---
id: W01
name: LSASS memory dumped or Mimikatz credential module run
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
Reading LSASS memory is how credentials are stolen from a Windows host. Whatever tool does it, the command line gives it away: it names LSASS together with a dump, calls the `MiniDump` export of `comsvcs.dll` (by name or by its ordinal `#24`), or runs Mimikatz's `sekurlsa` or `lsadump` modules. The rule matches on those words, not on a list of tools, so a renamed `procdump` still fires.

Falcon blocks most LSASS reads, but the attempt is still a process launch. Falcon's own LSASS-access detections arrive through CS04.

## Query
```esql
FROM logs-crowdstrike.fdr-* METADATA _id, _index, _version
| WHERE event.action == "ProcessRollup2" AND host.os.type == "windows"
| EVAL cmd = TO_LOWER(process.command_line)
| WHERE (cmd LIKE "*lsass*" AND (cmd LIKE "*dump*" OR cmd LIKE "*dmp*" OR cmd LIKE "* -ma *"))
     OR cmd LIKE "*comsvcs*minidump*" OR cmd LIKE "*comsvcs*#24*"
     OR cmd LIKE "*sekurlsa*" OR cmd LIKE "*lsadump*"
| KEEP @timestamp, host.id, host.name, user.name, process.parent.name, process.name, process.command_line,
       process.hash.sha256, _id, _version, _index
```

## Suppression
Suppress by `host.id`, `process.name` for 1h. Alerts missing a key field are not suppressed. Attackers retry after Falcon blocks them; a different tool still alerts. `host.id` is the Falcon agent ID and is always present.

## Known false positives / exclusions
- Microsoft support running `procdump` on LSASS during a case. Ticket-gated, not excluded.
- Dump tools that take a process ID instead of a name (`sqldumper`, `rdrleakdiag`) only match when the command line also names LSASS.

## Triage
- Isolate the host in Falcon. Assume every credential logged on to it is compromised, and check 4624 for who that is (I06).

## Test
Run the Atomic Red Team T1003.001 test on a lab host. Falcon blocks it; the rule still fires on the process launch.
