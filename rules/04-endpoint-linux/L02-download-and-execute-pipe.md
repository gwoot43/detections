---
id: L02
name: Remote script piped straight into a shell or interpreter
category: endpoint-linux
status: todo
severity: high
language: esql
index: logs-crowdstrike.fdr-*
mitre: [T1105, T1059.004, T1140]
data_source: CrowdStrike FDR ProcessRollup2 (Linux)
suppression:
  fields: [host.name, user.name]
  duration: 1h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
`curl … | sh` is the Linux download cradle used by cryptominers, botnets and post-exploitation kits. Developers run it too, so the rule filters on paths and decoders that installers do not use, and on servers rather than developer laptops.

## Query
```esql
FROM logs-crowdstrike.fdr-* METADATA _id, _index, _version
| WHERE event.action == "ProcessRollup2" AND host.os.type == "linux"
| EVAL cmd = TO_LOWER(process.command_line), pname = TO_LOWER(process.name)
| WHERE ((cmd LIKE "*curl *" OR cmd LIKE "*wget *") AND (cmd LIKE "*| sh*" OR cmd LIKE "*| bash*" OR cmd LIKE "*|sh*" OR cmd LIKE "*|bash*" OR cmd LIKE "*-o /tmp/*" OR cmd LIKE "*-o /dev/shm/*" OR cmd LIKE "*-o /var/tmp/*"))
   OR (cmd LIKE "*base64 -d*" AND (cmd LIKE "*| sh*" OR cmd LIKE "*| bash*" OR cmd LIKE "*|sh*" OR cmd LIKE "*|bash*"))
   OR (pname LIKE "python*" AND cmd LIKE "*urllib*" AND (cmd LIKE "*exec(*" OR cmd LIKE "*os.system*"))
   OR (cmd LIKE "*http*" AND (cmd LIKE "*/dev/shm/*" OR cmd LIKE "*/tmp/.*") AND (cmd LIKE "*chmod +x*" OR cmd LIKE "*chmod 777*"))
   OR (cmd LIKE "*&& chmod +x*" AND cmd LIKE "*&& ./*" AND (cmd LIKE "*/tmp/*" OR cmd LIKE "*/dev/shm/*"))
| WHERE NOT (host.name LIKE "dev-*" OR host.name LIKE "*-laptop*")
| KEEP @timestamp, host.name, user.name, process.parent.name, pname, process.command_line
```

## Suppression
Suppress by `host.name`, `user.name` for 1h. Alerts missing a key field are not suppressed. Install scripts and loaders retry.

## Known false positives / exclusions
- CI runners and package bootstrap (Docker, rustup, Homebrew). Exclude by the URL, and note that an allowlisted URL is still a supply-chain risk.

## Triage
- Fetch the URL in a sandbox, check whether the payload ran (ElfFileWritten then ProcessRollup2), check outbound connections.

## Test
`curl -s http://127.0.0.1/x.sh | sh` on a lab host.
