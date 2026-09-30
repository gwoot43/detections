---
id: CS01
name: Vulnerable or unsigned driver loaded (BYOVD)
category: crowdstrike-fdr
status: todo
severity: critical
language: esql
index: logs-crowdstrike.fdr-*
mitre: [T1068, T1211, T1562.001]
data_source: CrowdStrike FDR DriverLoad / KernelModuleLoad events
suppression:
  fields: [host.name, img]
  duration: 24h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
BYOVD is the dominant EDR-killer delivery method in 2026 (Reynolds, RansomHub, Akira, Scattered Spider). The kernel-side signal is a known-vulnerable signed driver, or any driver, loading from a user-writable path. FDR's driver-load telemetry sees this even when the process side was obfuscated. Maintain the vulnerable-driver hash list from loldrivers.io and your intel feed.

## Query
```esql
FROM logs-crowdstrike.fdr-* METADATA _id, _index, _version
| WHERE event.action IN ("DriverLoad", "KernelModuleLoad") AND host.os.type == "windows"
| EVAL img = TO_LOWER(TO_STRING(COALESCE(file.path, process.executable))),
       h = TO_LOWER(TO_STRING(COALESCE(file.hash.sha256, process.hash.sha256)))
| WHERE
     // driver from a user-writable path is almost always BYOVD
     (img LIKE "*\\temp\\*" OR img LIKE "*\\users\\*" OR img LIKE "*\\programdata\\*" OR img LIKE "*\\appdata\\*" OR img LIKE "*\\downloads\\*" OR img LIKE "*\\perflogs\\*" OR img LIKE "*\\windows\\temp\\*")
     // known vulnerable driver names (extend from loldrivers.io)
  OR img LIKE "*\\iqvw64.sys" OR img LIKE "*\\rtcore64.sys" OR img LIKE "*\\dbutil_2_3.sys" OR img LIKE "*\\gdrv.sys"
  OR img LIKE "*\\aswarpot.sys" OR img LIKE "*\\procexp*.sys" OR img LIKE "*\\truesight.sys" OR img LIKE "*\\viragt64.sys"
  OR img LIKE "*\\wnbios*.sys" OR img LIKE "*\\mhyprot*.sys" OR img LIKE "*\\zam*.sys" OR img LIKE "*\\kprocesshacker.sys"
  OR img LIKE "*\\nscm.sys" OR img LIKE "*\\nsecsoft*.sys"
     // or a hash on your vulnerable-driver value list
  OR h IN ("PUT_LOLDRIVERS_HASHES_HERE")
| KEEP @timestamp, host.name, user.name, img, h, process.name, process.command_line
```
Populate the hash branch from a scheduled import of the loldrivers.io hash list into an Elastic value list, and reference it. Names alone miss renamed drivers; hashes catch them.

## Suppression
Suppress by `host.name`, `img` for 24h. Alerts missing a key field are not suppressed. Drivers reload at every boot.

## Known false positives / exclusions
- Legitimate driver installs from `\Windows\System32\drivers\` under `TrustedInstaller` or a signed installer. The path filter already excludes system paths. Hardware vendor drivers installed at imaging time: exclude by hash of the known-good version.

## Triage
- Isolate immediately and pair with W05 (EDR tamper) and W06 (shadow deletion) on the same host: a vulnerable driver load followed by either is a ransomware detonation in progress.

## Test
Load a known loldrivers test driver from `%TEMP%` on a lab host (isolated, non-production).
